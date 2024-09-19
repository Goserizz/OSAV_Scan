package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

func TestDns(t *testing.T) {
	var err error
	if *iface == "" {
		*iface, err = GetDefaultRouteInterface()
		if err != nil {
			panic("Please Specify the Interface for DNSRoute.")
		}
	}
	iface := "eno8303"
	srcIpv4Arr, _, srcMac, err := GetIface(iface)
	if err != nil {
		panic(err)
	}
	srcIpStr := srcIpv4Arr[0]
	dstMac, err := net.ParseMAC("38:22:d6:30:a1:ff")
	if err != nil {
		panic(err)
	}

	p := NewDNSPoolNormal(srcIpStr, iface, srcMac, dstMac, "test")

	go func() {
		for {
			targetIp, res, ttl := p.GetDns()
			if targetIp != "" {
				fmt.Println("DNS", targetIp, res, ttl)
			}
		}
	}()

	go func() {
		for {
			targetIp, res, ttl := p.GetIcmp()
			if targetIp != "" {
				fmt.Println("ICMP", targetIp, res, ttl)
			}
		}
	}()

	for i := uint8(5); i < 20; i++ {
		p.Add(net.ParseIP("8.8.8.8").To4(), i)
		time.Sleep(1 * time.Second)
	}
	time.Sleep(10 * time.Second)
}

func TestCache(t *testing.T) {
	crPath := "data/20240723/closed_resolver.txt"
	timePath := "data/20240723/cache_time.txt"
	os.Remove(timePath)
	var err error
	if *iface == "" {
		*iface, err = GetDefaultRouteInterface()
		if err != nil {
			panic("Please Specify the Interface for DNSRoute.")
		}
	}
	iface := "eno8303"
	srcIpv4Arr, _, srcMac, err := GetIface(iface)
	if err != nil {
		panic(err)
	}
	srcIpStr := srcIpv4Arr[0]
	dstMac, err := net.ParseMAC("38:22:d6:30:a1:ff")
	if err != nil {
		panic(err)
	}

	p := NewDNSPoolCache(srcIpStr, iface, srcMac, dstMac)
	time.Sleep(20 * time.Second)

	dstIpStrArr := ReadLineAddr6FromFS(crPath)
	limiter := rate.NewLimiter(rate.Limit(5000), 100)

	turn := 5
	batch := 300000
	bar := progressbar.Default(int64(len(dstIpStrArr)*turn), "Scanning Normal...")
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		fmt.Println("Error loading location:", err)
		return
	}

	for k := 0; k < len(dstIpStrArr); k += batch {
		for j := 0; j < turn; j++ {
			for i := k; i < min(k+batch, len(dstIpStrArr)); i++ {
				if (i+1)%100 == 0 {
					bar.Add(100)
				}
				dstIpStr := dstIpStrArr[i]
				dstIp := net.ParseIP(dstIpStr).To4()
				p.Add(dstIp)
				limiter.Wait(context.TODO())
				Append1Addr6ToFS(timePath, time.Now().In(location).Format("2006-01-02 15:04:05")+","+dstIpStr)
			}
		}
	}
}

func TestFirstHopScan(t *testing.T) {
	iface := "eno8303"
	srcIpStr := "202.112.237.201"
	srcMac, _ := net.ParseMAC("08:92:04:a3:fd:f8")
	dstMac, _ := net.ParseMAC("38:22:d6:30:a1:ff")
	startTtl := uint8(5)
	endTtl := uint8(40)

	dstIpStrArr := ReadLineAddr6FromFS("data/20240901/closed_resolvers.txt")
	limiter := rate.NewLimiter(10000, 100)

	randPfx := GetDomainRandPfx(RAND_LEN)
	fmt.Println("Random Prefix:", randPfx)
	fmt.Println("Press Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	pSpoofSame := NewDNSPoolSpoofSame(srcIpStr, iface, srcMac, dstMac, randPfx)
	bar := progressbar.Default(int64(len(dstIpStrArr)*(int(endTtl)-int(startTtl))), "Scanning SpoofSame...")
	for ttl := startTtl; ttl < endTtl; ttl++ {
		for i, dstIpStr := range dstIpStrArr {
			if (i+1)%100 == 0 {
				bar.Add(100)
				bar.Describe(fmt.Sprintf("Scanning SpoofSame TTL=%d", ttl))
			}
			dstIp := net.ParseIP(dstIpStr).To4()
			pSpoofSame.Add(dstIp, ttl)
			limiter.Wait(context.Background())
		}
	}
}

func TestSAVRange(t *testing.T) {
	iface := "eno8303"
	srcMac, _ := net.ParseMAC("08:92:04:a3:fd:f8")
	dstMac, _ := net.ParseMAC("38:22:d6:30:a1:ff")
	fmt.Println(iface, srcMac, dstMac)

	file, err := os.Open("range_test/test_ip.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var ips []string

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		ips = append(ips, parts[0])
	}

	randPfx := GetDomainRandPfx(RAND_LEN)
	// Press Enter to Continue
	fmt.Println("Random Prefix:", randPfx)
	fmt.Println("Press Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	spoofSender := NewDNSPoolSpoofAny(iface, srcMac, dstMac, randPfx)
	for _, ip := range ips {
		dstIp := net.ParseIP(ip).To4()
		dstIpUint32 := binary.BigEndian.Uint32(dstIp)
		srcIpUint32 := dstIpUint32 ^ 1
		srcIp := make([]byte, 4)
		binary.BigEndian.PutUint32(srcIp, srcIpUint32)
		spoofSender.Add(srcIp, dstIp)
		time.Sleep(1 * time.Second)
		//break
	}
	time.Sleep(10 * time.Second)
}
