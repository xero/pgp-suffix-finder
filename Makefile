BINARY := pgp-suffix-finder

all: $(BINARY)

$(BINARY):
	go build -o $(BINARY)

clean:
	$(RM) $(BINARY)
