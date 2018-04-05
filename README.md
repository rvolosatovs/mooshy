[![Build Status](https://travis-ci.com/rvolosatovs/mooshy.svg?token=Rr1zHeZEE84zs4P7sgSv&branch=master)](https://travis-ci.com/rvolosatovs/mooshy)

# Mooshy

[![asciicast](https://asciinema.org/a/zK5uZERZHIAw1TsNng2o8eDqX.png)](https://asciinema.org/a/zK5uZERZHIAw1TsNng2o8eDqX)

## Installation:
```sh
    go get -u -v github.com/rvolosatovs/mooshy/cmd/mooshy
```

## Development:
```sh
    make
```

### To regenerate shellcode:
```sh
    make
```

## Usage:
```sh
    $ ./bin/mooshy -help                                                       
    Usage of ./bin/mooshy:
      -addr string
        	The lucky guy
      -moosh string
        	Path to moosh (default "./bin/moosh")
      -ssh
        	Use SSH for the infection
      -sshAgent string
        	Path to SSH agent socket (default "/run/user/1000/gnupg/S.gpg-agent.ssh")
      -sshKey string
        	Path to (passwordless) SSH private key (default "/home/rvolosatovs/.ssh/id_rsa")
      -sshKnown string
        	Path to SSH known_hosts file (default "/home/rvolosatovs/.ssh/known_hosts")
      -sshUser string
        	Username to connect as(e.g. for SSH) (default "averagejoe")
      -useSSHAgent
        	Whether or not use SSH agent
      -useSSHKey
        	Whether or not use (passwordless) SSH private key
      -useSSHKnown
        	Whether or not to try to infect all hosts in SSH known_hosts file
```

# Mechanism of action
The tool operates in 2 modes - infection and execution.

## Infection mode
- Connects to the victim machine(s):
    - Connect using SSH to the `addr` specified and/or all hosts in `known_hosts` file, using either a running SSH agent(with `SSH_AUTH_SOCK` set in environment) or using password-less key, which has access to the machine(s).
- Performs a privilege escalation attack using a [Linux kernel vuln](dirtycow.ninja) (PoC uses vanilla Ubuntu 16.04 LTS) to overwrite SUID binary(`mooshy` uses `/usr/bin/passwd`) by shellcode, which sets `/proc/sys/vm/dirty_writeback_centisecs` to `0` to prevent kernel panic due to invalid state, which would otheriwse occur shortly after the execution of exploit and `exec`s `/bin/bash` with SUID bit prepended.
- Using the "suid root shell" installs the backdoor on the system.
- Restores the contents of the original binary.
in "execute" mode:
- Connects to the infected victim and returns a reverse `root` shell.
