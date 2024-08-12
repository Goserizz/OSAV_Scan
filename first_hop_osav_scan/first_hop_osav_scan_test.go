package main

import (
	"os"
	"net"
	"testing"
	"time"
	"fmt"
	"context"

	"golang.org/x/time/rate"
	"github.com/schollz/progressbar/v3"
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

	p := NewDNSPoolNormal(srcIpStr, iface, srcMac, dstMac)

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

	for i := uint8(5); i < 20; i ++ {
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
	bar := progressbar.Default(int64(len(dstIpStrArr) * turn), "Scanning Normal...")
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		fmt.Println("Error loading location:", err)
		return
	}

	for k := 0; k < len(dstIpStrArr); k += batch {
		for j := 0; j < turn; j ++ {
			for i := k; i < min(k + batch, len(dstIpStrArr)); i ++ {
				if (i + 1) % 100 == 0 { bar.Add(100) }
				dstIpStr := dstIpStrArr[i]
				dstIp := net.ParseIP(dstIpStr).To4()
				p.Add(dstIp)
				limiter.Wait(context.TODO())
				Append1Addr6ToFS(timePath, time.Now().In(location).Format("2006-01-02 15:04:05") + "," + dstIpStr)
			}
		}
	}
}