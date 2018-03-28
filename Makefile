BINDIR ?= bin

$(BINDIR)/mooshy:
	CGO_ENABLED=0 GOARCH=amd64 go build -o bin/mooshy ./cmd/mooshy
mooshy: $(BINDIR)/mooshy

all: mooshy

.PHONY: all $(BINDIR)/mooshy mooshy
