package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

func hasSuffix(b, suffix []byte) bool {
	h := sha1.Sum(b)
	//log.Printf("%s =~ %s?\n", paddedHex(h[:]), paddedHex(suffix))
	return bytes.HasSuffix(h[:], suffix)
}

func progress(perc float64, size int) string {
	var (
		s = "["
		i int
		d = 100.0 / float64(size)
	)
	for ; i < int(perc/d); i++ {
		s += "#"
	}
	for ; i < size; i++ {
		s += "-"
	}
	s += "]"
	return fmt.Sprintf("%s %5s%%", s, fmt.Sprintf("%.1f", perc))
}

func readUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func humanScale(f float64) string {
	switch {
	case f > 1e15:
		return fmt.Sprintf("%.3fP", f/1e15+.0005)
	case f > 1e12:
		return fmt.Sprintf("%.3fT", f/1e12+.0005)
	case f > 1e9:
		return fmt.Sprintf("%.3fG", f/1e9+.0005)
	case f > 1e6:
		return fmt.Sprintf("%.3fM", f/1e6+.0005)
	case f > 1e3:
		return fmt.Sprintf("%.3fk", f/1e3+.0005)
	default:
		return fmt.Sprintf("%.f", f)
	}
}

func findSuffixWorker(suffix, b []byte, ts, min, step uint32, found chan []byte, wg *sync.WaitGroup, round *uint64) {
	//log.Printf("worker: scan %d down to %d, step %d\n", ts, min, step)
	for ; ts > min; ts = ts - step {
		*round++

		b[4] = byte(ts >> 24)
		b[5] = byte(ts >> 16)
		b[6] = byte(ts >> 8)
		b[7] = byte(ts)

		if hasSuffix(b, suffix) {
			found <- b
			return
		}
	}

	wg.Done()
}

func findSuffix(suffix, b []byte, min uint32, workers int) (bool, []byte) {
	ts := readUint32(b[4:])
	wg := new(sync.WaitGroup)

	var (
		round = make([]uint64, workers)
		found = make(chan []byte, 1)
		total = ts - min
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)

		// Make a copy of the slice, since all workers will manipulate
		wb := make([]byte, len(b))
		copy(wb, b)

		go findSuffixWorker(suffix, wb, ts-uint32(i), min, uint32(workers), found, wg, &round[i])
	}

	abort := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		abort <- struct{}{}
	}()

	timer := time.NewTicker(time.Second)
	start := time.Now()
	state := func() string {
		delta := time.Since(start)
		var rounds uint64
		for _, r := range round {
			rounds += r
		}
		return fmt.Sprintf("%s %s, %sk/s [r=%d,t=%s]\r",
			time.Now().Format("2006/01/02 15:04:05"),
			progress((float64(rounds)/float64(total))*100+.05, 20),
			humanScale(float64(rounds)/(float64(delta)/float64(time.Second))),
			rounds, delta/time.Second*time.Second)
	}

	defer func() {
		timer.Stop()
		fmt.Println(state())
	}()

	for {
		select {
		case key := <-found:
			return true, key
		case <-abort:
			return false, nil
		case <-timer.C:
			os.Stdout.Write([]byte(state()))
		}
	}
}

func readFull(r io.Reader, buf []byte) (n int, err error) {
	n, err = io.ReadFull(r, buf)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

func paddedHex(buf []byte) string {
	var (
		tmp = buf
		pad string
	)
	for i := 0; i < len(tmp); i += 2 {
		pad += strings.ToUpper(hex.EncodeToString(tmp[i:i+2])) + " "
	}
	return pad[:len(pad)-1]
}

func readableFingerprint(packet []byte) string {
	hash := sha1.Sum(packet)
	return paddedHex(hash[:])
}

func readPublicKeyPacket(packet []byte, offset int) (err error) {
	//log.Printf("offset: %d\n", offset)
	//log.Printf("packet:\n%s\n", hex.Dump(packet[:16]))
	if version := packet[offset]; version != 4 {
		return fmt.Errorf("unsupported public key version %d", version)
	}

	switch keyType := packet[offset+5]; keyType {
	case 1:
		log.Println("public key type RSA")
	case 2:
		log.Println("public key type RSA (encrypt only)")
	case 3:
		log.Println("public key type RSA (sign only)")
	case 16:
		err = errors.New("unsupported ElGamal public key")
		return
	case 17:
		err = errors.New("unsupported DSA public key (you suck!)")
		return
	case 18:
		err = errors.New("unsupported ECDH public key")
		return
	case 19:
		err = errors.New("unsupported ECDSA public key")
		return
	default:
		err = fmt.Errorf("unknown public key %#02x", keyType)
		return
	}

	log.Printf("public key %s\n", readableFingerprint(packet))
	return
}

func readPacket(r io.Reader) (packet []byte, tag byte, offset int, err error) {
	packet = make([]byte, 1, 4096)
	if _, err = readFull(r, packet); err != nil {
		return
	}

	if packet[0]&0x80 == 0 {
		err = errors.New("tag byte does not have MSB set")
		return
	}

	if packet[0]&0x40 == 0 {
		tag = (packet[0] & 0x3f) >> 2
		lengthType := packet[0] & 3
		if lengthType == 3 {
			err = errors.New("packet contains no data")
			return
		}
		lengthBytes := 1 << lengthType
		//log.Printf("got %d length bytes\n", lengthBytes)
		packet = append(packet, make([]byte, lengthBytes)...)
		_, err = readFull(r, packet[1:])
		if err != nil {
			return
		}
		//log.Printf("packet: %q (%d)\n", packet, len(packet))
		var length int
		for i := 0; i < lengthBytes; i++ {
			length <<= 8
			length |= int(packet[1+i])
		}
		offset = lengthBytes + 1
		packet = append(packet, make([]byte, length)...)
		_, err = readFull(r, packet[lengthBytes+1:])
		return
	}

	err = errors.New("new packet not supported")
	return
}

var (
	keyRingTemplate, _ = template.New("keyring").Parse(`Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 1024
Name-Real: {{.Name}}
Name-Email: {{.Email}}
Expire-Date: 0
%pubring {{.PubRing}}
%secring {{.SecRing}}
%commit
%echo done`)
)

func populateStdin(str string) func(io.WriteCloser) {
	return func(stdin io.WriteCloser) {
		defer stdin.Close()
		io.Copy(stdin, bytes.NewBufferString(str))
	}
}

func generateKeyRing(bits int, name, email string) (secRing, pubRing []byte, err error) {
	var secFile, pubFile *os.File
	if secFile, err = ioutil.TempFile("", "secring"); err != nil {
		return
	}
	secFile.Close()
	if pubFile, err = ioutil.TempFile("", "pubring"); err != nil {
		return
	}
	pubFile.Close()

	defer func() {
		os.Remove(secFile.Name())
		os.Remove(pubFile.Name())
	}()

	log.Printf("generating %d bits RSA key for %s <%s>\n", bits, name, email)
	cmd := exec.Command("gpg", "--batch", "--gen-key")

	var stdin io.WriteCloser
	if stdin, err = cmd.StdinPipe(); err != nil {
		return
	}

	if err = cmd.Start(); err != nil {
		return
	}

	if err = keyRingTemplate.Execute(stdin, map[string]interface{}{
		"Bits":    bits,
		"Name":    name,
		"Email":   email,
		"PubRing": pubFile.Name(),
		"SecRing": secFile.Name(),
	}); err != nil {
		return
	}

	if err = stdin.Close(); err != nil {
		return
	}

	if err = cmd.Wait(); err != nil {
		log.Panic(err)
	}

	if secRing, err = ioutil.ReadFile(secFile.Name()); err != nil {
		return
	}

	if pubRing, err = ioutil.ReadFile(pubFile.Name()); err != nil {
		return
	}

	return
}

func saveRing(name string, pubRing, secRing []byte, ts uint32, offset, length int, uidString string) (err error) {
	log.Printf("saving dir %s/\n", name)
	if err = os.MkdirAll(name, 0700); err != nil {
		return
	}

	log.Printf("found match on %s\n", time.Unix(int64(ts), 0))
	log.Printf("replace timestamp at +%d\n", offset)
	pubRing[4] = byte(ts >> 24)
	pubRing[5] = byte(ts >> 16)
	pubRing[6] = byte(ts >> 8)
	pubRing[7] = byte(ts)
	pubName := filepath.Join(name, "pubring.gpg")
	log.Printf("saving pubring to %s\n", pubName)
	if err = ioutil.WriteFile(pubName, pubRing, 0644); err != nil {
		return
	}

	secRing[4] = byte(ts >> 24)
	secRing[5] = byte(ts >> 16)
	secRing[6] = byte(ts >> 8)
	secRing[7] = byte(ts)
	secName := filepath.Join(name, "secring.gpg")
	log.Printf("saving secring to %s\n", secName)
	if err = ioutil.WriteFile(secName, secRing, 0600); err != nil {
		return
	}
	return
}

func find(workers, bits int, name, email string, suffix []byte, min time.Duration) (found bool, err error) {
	var secRing, pubRing []byte
	if secRing, pubRing, err = generateKeyRing(bits, name, email); err != nil {
		return
	}

	ringFile := bytes.NewBuffer(pubRing)

	var (
		packet []byte
		tag    byte
		offset int
	)
	if packet, tag, offset, err = readPacket(ringFile); err != nil {
		log.Fatalln(err)
	}

	log.Printf("read %d bytes %#02x (%#02x) packet, offset %d\n", len(packet), tag, packet[0], offset)
	if !(tag == 0x05 || tag == 0x06) {
		log.Fatalf("packet not a private key or public key, got %#02x\n", tag)
	}

	if err = readPublicKeyPacket(packet, offset); err != nil {
		log.Fatalln(err)
	}

	tsMin := time.Now().Add(-min)
	log.Printf("scanning for suffix %s up until %s\n", paddedHex(suffix), tsMin)

	var (
		key   []byte
		start = time.Now()
	)
	if found, key = findSuffix(suffix, packet, uint32(tsMin.Unix()), workers); found {
		delta := time.Since(start)
		fingerprint := readableFingerprint(key)
		log.Printf("public key %s found in %s\n", fingerprint, delta)
		uid := fmt.Sprintf("%s <%s>", name, email)
		err = saveRing(strings.Replace(fingerprint, " ", "", -1), pubRing, secRing, readUint32(key[4:]), offset, len(packet), uid)
	}

	return
}

func main() {
	suffixString := flag.String("suffix", "", "suffix to find")
	scanMin := flag.String("min", "43800h", "minimal valid timestamp")
	bits := flag.Int("bits", 4096, "RSA key size")
	name := flag.String("name", "John Doe", "name in uid")
	email := flag.String("email", "john.doe@example.org", "email in uid")
	workers := flag.Int("workers", (runtime.NumCPU()*3)/2, "number of workers")
	flag.Parse()

	if *suffixString == "" {
		log.Fatalln("supply a -suffix")
	}

	suffix, err := hex.DecodeString(*suffixString)
	if err != nil {
		log.Fatalf("invalid suffix %q: %v\n", *suffixString, err)
	}

	min, err := time.ParseDuration(*scanMin)
	if err != nil {
		log.Fatalf("invalid duration %q: %v\n", *scanMin, err)
	}

	for {
		var found bool
		if found, err = find(*workers, *bits, *name, *email, suffix, min); err != nil {
			log.Fatalln(err)
		}
		if found {
			break
		}
		log.Println("... not found, next round!")
	}
}
