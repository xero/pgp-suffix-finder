# pgp-suffix-finder

Brute force PGP key ID suffixes of arbitrary length.

## Warning!

This tool can brute force any (short) PGP key suffix, use it for good; e.g.
creating vanity key IDs. Don't use it to generate collisions and annoy other
PGP users. Thanks

## Building

Prepare a Go environment if you haven't done so already, for more
information refer to https://golang.org/doc/install

Install using `go get`:

	$ go get git.maze.io/maze/pgp-suffix-finder
	$ go build git.maze.io/maze/pgp-suffix-finder

Otherwise, clone into `$GOPATH`:

	$ mkdir -p $GOPATH/git.maze.io/maze
	$ git clone https://git.maze.io/maze/pgp-suffix-finder \
		$GOPATH/git.maze.io/maze/pgp-suffix-finder
	$ go build git.maze.io/maze/pgp-suffix-finder

## References

### OpenPGP specification

https://tools.ietf.org/html/rfc4880

### Short key IDs are bad news

http://www.asheesh.org/note/debian/short-key-ids-are-bad-news.html

### Stop it with those short PGP key IDs!

http://gwolf.org/node/4070
