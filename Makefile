BINDIR ?= bin

deps:
	@command -v dep > /dev/null || go get -u github.com/golang/dep/cmd/dep
	@dep ensure

$(BINDIR)/mooshy:
	CGO_ENABLED=0 GOARCH=amd64 go build -o $(BINDIR)/mooshy ./cmd/mooshy

mooshy: $(BINDIR)/mooshy

all: mooshy

.PHONY: all $(BINDIR)/mooshy mooshy deps
