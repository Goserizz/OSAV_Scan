package main

import (
	"testing"
	"net"
	"log"
	"time"
	"strings"
)

func TestDNS(t *testing.T) {
	srcMac, err := net.ParseMAC("00:16:09:e8:15:68")
	if err != nil { log.Fatal(err) }
	dstMac, err := net.ParseMAC("0c:81:26:30:b8:78")
	if err != nil { log.Fatal(err) }
	pool := NewDNSPool(10, 100, "107.189.29.130", "eth0", srcMac, dstMac, 20)
	go func() { for{log.Println(pool.GetIcmp())} }()
	go func() { for{log.Println(pool.GetDns())} }()
	pool.Add("8.8.8.8")
	time.Sleep(5 * time.Second)
	pool.Finish()
	
	time.Sleep(time.Hour)
}

func TestAliveDNS(t *testing.T) {
	srcMac, err := net.ParseMAC("00:16:09:e8:15:68")
	if err != nil { log.Fatal(err) }
	dstMac, err := net.ParseMAC("0c:81:26:30:b8:78")
	if err != nil { log.Fatal(err) }
	pool := NewDNSPool(10, 100, "107.189.29.130", "eth0", srcMac, dstMac, 20)
	go func() { 
		for {
			targetIp, realIp := pool.GetDns()
			if targetIp == realIp { Append1Addr6ToFS("20240116-alive.txt", targetIp) }
		}
	}()
	
	inputFile := "20240116-dns.txt"
	for _, line := range ReadLineAddr6FromFS(inputFile) {
		pool.Add(strings.Split(line, ",")[1])
	}
	time.Sleep(10 * time.Second)
}