SHELL = /usr/bin/env bash

BINDIR ?= bin
VUSER ?= "averagejoe"
VHOST ?= "192.168.56.101"

all: mooshy moosh hhttpd backdoor

deps:
	$(info Checking development deps...)
	@command -v dep > /dev/null || go get -u -v github.com/golang/dep/cmd/dep
	@command -v xxd > /dev/null || { printf 'Please install xxd\n'; exit 1; }
	$(info Syncing go deps...)
	@dep ensure -v

report-deps:
	$(info Checking the report deps...)
	@command -v pandoc > /dev/null || { printf 'Please install pandoc\n'; exit 1; }

vendor: deps

fmt:
	$(info Formatting Go code...)
	@go fmt ./...

$(BINDIR)/cow: dirtycow/dirtycow.c
	$(info Compiling exploit on $(VHOST) as $(VUSER)...)
	@scp $< $(VUSER)@$(VHOST):
	@ssh $(VUSER)@$(VHOST) gcc -pthread $(shell basename $?) -o not-an-exploit
	@scp $(VUSER)@$(VHOST):not-an-exploit $@
	@ssh $(VUSER)@$(VHOST) rm -f $(shell basename $?) not-an-exploit

cmd/moosh/cow.go: $(BINDIR)/cow
	$(info Generating shellcode of $@...)
	@xxd -i $< $@
	@sed -i 's/unsigned char bin_cow\[\] = {/package main\nvar DirtyCow = []byte{/' $@
	@sed -i 's/\([0-9]$$\)/\1}/' $@
	@sed -i '$$d' $@
	@sed -i '$$d' $@
	@gofmt -w -s $@

cmd/moosh/backdoor.go: $(BINDIR)/backdoor
	$(info Generating shellcode of $@...)
	@xxd -i $< $@
	@sed -i 's/unsigned char bin_backdoor\[\] = {/package main\nvar Backdoor = []byte{/' $@
	@sed -i 's/\([0-9]$$\)/\1}/' $@
	@sed -i '$$d' $@
	@sed -i '$$d' $@
	@gofmt -w -s $@

$(BINDIR)/moosh: cmd/moosh/cow.go cmd/moosh/backdoor.go cmd/moosh/moosh.go vendor
	$(info Compiling $@...)
	@CGO_ENABLED=0 GOARCH=amd64 go build -o $@ ./cmd/moosh

$(BINDIR)/mooshy: cmd/mooshy/mooshy.go vendor
	$(info Compiling $@...)
	@CGO_ENABLED=0 GOARCH=amd64 go build -o $@ ./cmd/mooshy

$(BINDIR)/backdoor: cmd/backdoor/backdoor.go vendor
	$(info Compiling backdoor...)
	@CGO_ENABLED=0 GOARCH=amd64 go build -o $@ ./cmd/backdoor

$(BINDIR)/hhttpd: ./target/hhttpd.c
	$(info Compiling $@...)
	gcc -o $@ $<

report.pdf: README.md report-deps eisvogel.tex
	@sed '1d' README.md | pandoc -o $@\
		-V colorlinks\
		--listings\
		--template eisvogel.tex

moosh: $(BINDIR)/moosh
mooshy: $(BINDIR)/mooshy
backdoor: $(BINDIR)/backdoor
hhttpd: $(BINDIR)/hhttpd
cow: cmd/moosh/cow.go
report: report.pdf

clean:
	rm -rf $(BINDIR)/{backdoor,moosh,mooshy,cow,hhttpd} cmd/moosh/cow.go cmd/moosh/backdoor.go vendor

.INTERMEDIATE: $(BINDIR)/cow
.IGNORE: $(BINDIR)/cow
.PHONY: all deps mooshy moosh fmt cow clean backdoor hhttpd report report-deps
