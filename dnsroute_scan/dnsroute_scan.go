package main

import (
	"os"
	"fmt"
	"net"
	"time"
	"sync"
	"context"
	"encoding/binary"

	"golang.org/x/time/rate"
	"github.com/schollz/progressbar/v3"
)

const (
	REMOTE_PORT uint16 = 53
	LOG_INTV = 100000
	BURST = 10000
	PRIME uint64 = 4294967311
	IPNUM uint64 = 4294967296
	BUF_SIZE = 10000
)

func DNSRouteScan(srcIpStr, ifaceName, inFile, outFile, natFile, dnsFile string, startTtl, endTtl uint8, nSender, pps int, srcMac, dstMac []byte) {
	os.Remove(outFile)
	os.Remove(natFile)
	os.Remove(dnsFile)
	dstIpStrArray := ReadLineAddr6FromFS(inFile)
	bar := progressbar.Default(int64(len(dstIpStrArray) * int(endTtl - startTtl + 1)), "Scanning...")
	var doneIps sync.Map
	var testIps sync.Map
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)

	for _, dstIpStr := range dstIpStrArray {
		testIps.Store(dstIpStr, true)
	}
	counter := 0
	for ttl := startTtl; ttl <= endTtl; ttl ++ {
		p := NewDNSPoolSlow(nSender, BUF_SIZE, srcIpStr, ifaceName, srcMac, dstMac, ttl)
		bar.Describe(fmt.Sprintf("Scanning TTL=%d...", ttl))
		finish := false

		// send
		go func() {
			for _, dstIpStr := range dstIpStrArray {
				counter += 1
				if counter % LOG_INTV == 0 { bar.Add(LOG_INTV) }
				_, ok := doneIps.Load(dstIpStr); if ok { continue }
				limiter.Wait(context.TODO())
				p.Add(net.ParseIP(dstIpStr).To4())
			}
			finish = true
		}()

		// recieve icmp
		go func() {
			for {
				targetIp, realIp, resIp := p.GetIcmp()
				if targetIp == "" {
					if finish { break }
				} else {
					if _, ok := testIps.Load(targetIp); !ok { continue }
					if targetIp != realIp { Append1Addr6ToFS(outFile, targetIp + "," + realIp + "," + resIp) }
				}
			}
		}()

		// recieve dns
		go func() {
			for {
				targetIp, realIp := p.GetDns()
				if targetIp == "" {
					if finish { break }
				} else {
					if _, ok := testIps.Load(targetIp); !ok { continue }
					if targetIp != realIp {
						Append1Addr6ToFS(dnsFile, targetIp + "," + realIp)
						doneIps.Store(targetIp, true)
					}
				}
			}
		}()

		for !finish { time.Sleep(time.Second) }
		time.Sleep(10 * time.Second)
		p.Finish()
	}
}

func DNSRouteScanWhole(srcMac, dstMac []byte, srcIpStr, ifaceName, outFile string, startTtl, endTtl uint8, pps, nSender int, nTot uint64) {
	os.Remove(outFile)
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)
	for ttl := startTtl; ttl <= endTtl; ttl ++ {
		finish := false
		p := NewDNSPool(nSender, BUF_SIZE, srcIpStr, ifaceName, srcMac, dstMac, ttl)
		go func() {
			ipDec := uint64(1)
			counter := uint64(0)
			bar := progressbar.Default(int64(nTot), fmt.Sprintf("Scanning TTL=%d, %d waiting", ttl, p.LenInChan()))
			for i := uint64(0); i < PRIME; i ++ {
				ipDec = (ipDec * 3) % PRIME
				if ipDec >= IPNUM || IsBogon(ipDec) { continue }
				if (i + 1) % LOG_INTV == 0 { bar.Add(LOG_INTV); bar.Describe(fmt.Sprintf("Scanning TTL=%d, %d waiting", ttl, p.LenInChan())) }
				dstIp := make([]byte, 4)
				binary.BigEndian.PutUint32(dstIp, uint32(ipDec))
				limiter.Wait(context.TODO())
				p.Add(dstIp)
				counter ++
				if counter == nTot { break }
			}
			time.Sleep(10 * time.Second)
			finish = true
		}()

		go func() {
			for {
				targetIp, realIp, resIp := p.GetIcmp()
				if targetIp == "" {
					if finish { break }
				} else if targetIp != realIp { Append1Addr6ToFS(outFile, targetIp + "," + realIp + "," + resIp) }
			}
		}()

		for !finish { time.Sleep(time.Second) }
		p.Finish()
	}
}