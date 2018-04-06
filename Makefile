SHELL = /bin/sh

BINDIR ?= bin
VUSER ?= "averagejoe"
VHOST ?= "192.168.56.101"

all: mooshy moosh backdoor

deps:
	@command -v dep > /dev/null || go get -u -v github.com/golang/dep/cmd/dep
	@echo "Syncing deps..."
	@dep ensure -v

vendor: deps

fmt:
	@echo "Formatting Go code..."
	@go fmt ./...

$(BINDIR)/cow: dirtycow/dirtycow.c
	@echo "Compiling exploit on $(VHOST) as $(VUSER)..."
	@scp dirtycow/dirtycow.c $(VUSER)@$(VHOST):
	@ssh $(VUSER)@$(VHOST) gcc -pthread dirtycow.c -o cow
	@scp $(VUSER)@$(VHOST):cow $(BINDIR)/cow
	@ssh $(VUSER)@$(VHOST) rm -f dirtycow.c cow

cmd/moosh/cow.go: $(BINDIR)/cow
	@echo "Generating shellcode..."
	@printf "package main\n\nvar DirtyCow = []byte{$(shell cat $(BINDIR)/cow | xxd -i)}" > cmd/moosh/cow.go
	@gofmt -w -s ./cmd/moosh/cow.go

$(BINDIR)/moosh: cmd/moosh/cow.go cmd/moosh/moosh.go vendor
	@echo "Compiling moosh..."
	@CGO_ENABLED=0 GOARCH=amd64 go build -o $(BINDIR)/moosh ./cmd/moosh

$(BINDIR)/mooshy: cmd/mooshy/mooshy.go vendor
	@echo "Compiling mooshy..."
	@CGO_ENABLED=0 GOARCH=amd64 go build -o $(BINDIR)/mooshy ./cmd/mooshy

$(BINDIR)/backdoor: cmd/backdoor/backdoor.go vendor
	@echo "Compiling backdoor..."
	@CGO_ENABLED=0 GOARCH=amd64 go build -o $(BINDIR)/backdoor ./cmd/backdoor

moosh: $(BINDIR)/moosh
mooshy: $(BINDIR)/mooshy
backdoor: $(BINDIR)/backdoor
cow: cmd/moosh/cow.go

clean:
	rm -rf $(BINDIR)/{backdoor,moosh,mooshy,cow} cmd/moosh/cow.go vendor

.SECONDARY: $(BINDIR)/cow
.PHONY: all deps mooshy moosh fmt cow clean backdoor
