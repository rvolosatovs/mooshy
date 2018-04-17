SHELL = /usr/bin/env bash

BINDIR ?= bin

VUSER ?= $(USER)

GOBUILD ?= CGO_ENABLED=0 GOARCH=amd64 go build -ldflags="-w -s"
UPX ?= upx -q -9

all: mooshy moosh hhttpd backdoor

deps:
	$(info Checking development deps...)
	@command -v dep > /dev/null || go get -u -v github.com/golang/dep/cmd/dep
	@command -v xxd > /dev/null || { printf 'Please install xxd\n'; exit 1; }
	@command -v upx > /dev/null || { printf 'Please install upx\n'; exit 1; }
	$(info Syncing go deps...)
	@dep ensure -v

doc-deps:
	$(info Checking the documentation deps...)
	@command -v pandoc > /dev/null || { printf 'Please install pandoc\n'; exit 1; }

docs/slides/reveal.js:
	$(info Fetching reveal.js/master...)
	@wget https://github.com/hakimel/reveal.js/archive/master.tar.gz
	@tar -xzvf master.tar.gz
	@rm master.tar.gz
	@mv reveal.js-master docs/slides/reveal.js

vendor: deps

fmt:
	$(info Formatting Go code...)
	@go fmt ./...

$(BINDIR)/cow-linux-amd64: dirtycow/dirtycow.c
ifdef VHOST
	$(info Compiling exploit on $(VHOST) as $(VUSER)...)
	@scp $< $(VUSER)@$(VHOST):
	@ssh $(VUSER)@$(VHOST) gcc -std=gnu99 -pthread $(shell basename $<) -o not-an-exploit
	@scp $(VUSER)@$(VHOST):not-an-exploit $@
	@ssh $(VUSER)@$(VHOST) rm -f $(shell basename $<) not-an-exploit
else
	$(info Compiling exploit locally...)
	@gcc -std=gnu99 -pthread $< -o $@
endif

cmd/moosh/cow.go: $(BINDIR)/cow-linux-amd64
	$(info Generating shellcode of $@...)
	@xxd -i $< $@
	@sed -i 's/unsigned char $(subst -,_,$(subst /,_,$<))\[\] = {/package main\nvar DirtyCow = []byte{/' $@
	@sed -i 's/\([0-9]$$\)/\1}/' $@
	@sed -i '$$d' $@
	@sed -i '$$d' $@
	@gofmt -w -s $@

cmd/moosh/backdoor.go: $(BINDIR)/backdoor-linux-amd64
	$(info Generating shellcode of $@...)
	@xxd -i $< $@
	@sed -i 's/unsigned char $(subst -,_,$(subst /,_,$<))\[\] = {/package main\nvar Backdoor = []byte{/' $@
	@sed -i 's/\([0-9]$$\)/\1}/' $@
	@sed -i '$$d' $@
	@sed -i '$$d' $@
	@gofmt -w -s $@

$(BINDIR)/moosh-linux-amd64: cmd/moosh/cow.go cmd/moosh/backdoor.go cmd/moosh/moosh.go vendor
	$(info Compiling $@...)
	@$(GOBUILD) -o $@ ./cmd/moosh
	@$(UPX) $@

$(BINDIR)/mooshy-linux-amd64: cmd/mooshy/mooshy.go vendor
	$(info Compiling $@...)
	@$(GOBUILD) -o $@ ./cmd/mooshy
	@$(UPX) $@

$(BINDIR)/backdoor-linux-amd64: cmd/backdoor/backdoor.go vendor
	$(info Compiling backdoor...)
	@$(GOBUILD) -o $@ ./cmd/backdoor
	@$(UPX) $@

$(BINDIR)/hhttpd-linux-i386: ./target/hhttpd.c
ifdef VHOST
	$(info Compiling hhttpd on $(VHOST) as $(VUSER)...)
	@scp $< $(VUSER)@$(VHOST):
	@ssh $(VUSER)@$(VHOST) gcc -std=gnu99 -fno-stack-protector -z execstack -m32 $(shell basename $<) -o hhttpd
	@scp $(VUSER)@$(VHOST):hhttpd $@
	@ssh $(VUSER)@$(VHOST) rm -f $(shell basename $<) hhttpd
else
	$(info Compiling hhttpd locally...)
	@gcc -std=gnu99 -fno-stack-protector -z execstack -m32 $< -o $@
endif

docs/report/report.pdf: README.md doc-deps docs/report/eisvogel.tex
	@sed '1d' README.md | pandoc -o $@\
		-V colorlinks\
		--listings\
		--template docs/report/eisvogel.tex

docs/slides/slides.html: docs/slides/slides.md docs/slides/bloody.css doc-deps docs/slides/reveal.js
	@cp docs/slides/{bloody.css,reveal.js/css/theme/}
	@pandoc -t revealjs -s -o $@ $< -V revealjs-url=./reveal.js -V theme=bloody

moosh: $(BINDIR)/moosh-linux-amd64
mooshy: $(BINDIR)/mooshy-linux-amd64
backdoor: $(BINDIR)/backdoor-linux-amd64
hhttpd: $(BINDIR)/hhttpd-linux-i386

report: docs/report/report.pdf

slides: docs/slides/slides.html

clean:
	rm -rf $(BINDIR)/{backdoor,moosh,mooshy,cow,hhttpd}-linux-amd64* cmd/moosh/cow.go cmd/moosh/backdoor.go vendor docs/report/report.pdf docs/slides/slides.html docs/slides/reveal.js

.PHONY: all mooshy moosh backdoor hhttpd deps fmt clean report slides doc-deps
