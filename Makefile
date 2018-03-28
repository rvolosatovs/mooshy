BINDIR ?= bin

all: mooshy

deps:
	@command -v dep > /dev/null || go get -u github.com/golang/dep/cmd/dep
	@dep ensure

$(BINDIR)/mooshy:
	CGO_ENABLED=0 GOARCH=amd64 go build -o $(BINDIR)/mooshy ./cmd/mooshy

mooshy: $(BINDIR)/mooshy

.PHONY: all deps mooshy $(BINDIR)/mooshy
