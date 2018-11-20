# pgp-suffix-finder

Brute force PGP key ID suffixes of arbitrary length.

this project started on the `unix.chat` irc when someone said we all needed 
k-rad hexspeak gpg keys. before we were done discussing it maze had already 
coded a tool in go for us. he's recently been mia and i wanted to mirror this 
_cool tool_ in case he ghosts.

## :rotating_light: Warning! :rotating_light:

This tool can brute force any (short) PGP key suffix, use it for good; e.g. 
creating vanity key IDs. Don't use it to generate collisions and annoy other 
PGP users. Thanks

## Requirements

A recent Go version will give you the SIMD variant of the SHA1 algorithm. ~~You 
need GnuPG available as `gpg`.~~ Versions 1.4.20 & 2.0.30 are tested and work 
properly, **2.1.x and above do not work!**

the code has been updated to use a binary called `gpg1` 
(use [this aur package](https://aur.archlinux.org/packages/gnupg1/) {,as your guide}) 
to allow version 1.4.x and the newest to co-exist on your system.

if you do install an appropriate binary named `gpg` 
update lines [267](https://github.com/xero/pgp-suffix-finder/blob/master/main.go#L267) 
and [299](https://github.com/xero/pgp-suffix-finder/blob/master/main.go#L299) 
in `main.go` as necessary.

## Building

Prepare a Go environment if you haven't done so already, for more
information refer to https://golang.org/doc/install

Install using `go get`:

	$ go get github.com/xero/pgp-suffix-finder
	$ go build github.com/xero/pgp-suffix-finder

Otherwise, clone into `$GOPATH`:

	$ mkdir -p $GOPATH/github.com/xero
	$ git clone https://github.com/xero/pgp-suffix-finder \
		$GOPATH/github.com/xero/pgp-suffix-finder
	$ go build github.com/xero/pgp-suffix-finder

## References

### OpenPGP specification

https://tools.ietf.org/html/rfc4880

### Short key IDs are bad news

http://www.asheesh.org/note/debian/short-key-ids-are-bad-news.html

### Stop it with those short PGP key IDs!

http://gwolf.org/node/4070
