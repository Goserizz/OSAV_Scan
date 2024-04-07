package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

const (
	REMOTE_PORT uint16 = 53
	LOG_INTV           = 100000
	BURST              = 10000
	PRIME       uint64 = 4294967311
	IPNUM       uint64 = 4294967296
	BUF_SIZE           = 1000
)

func DNSRouteScan(srcIpStr, ifaceName, inFile, outFile, natFile, dnsFile string, startTtl, endTtl uint8, nSender, pps int, srcMac, dstMac []byte) {
	os.Remove(outFile)
	os.Remove(natFile)
	os.Remove(dnsFile)
	dstIpStrArray := ReadLineAddr6FromFS(inFile)
	bar := progressbar.Default(int64(len(dstIpStrArray)*int(endTtl-startTtl+1)), "Scanning...")
	var doneIps sync.Map
	var testIps sync.Map
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)

	for _, dstIpStr := range dstIpStrArray {
		testIps.Store(dstIpStr, true)
	}
	counter := 0
	for ttl := startTtl; ttl <= endTtl; ttl++ {
		p := NewDNSPoolSlow(nSender, BUF_SIZE, srcIpStr, ifaceName, srcMac, dstMac, ttl)
		bar.Describe(fmt.Sprintf("Scanning TTL=%d...", ttl))
		finish := false

		// send
		go func() {
			for _, dstIpStr := range dstIpStrArray {
				counter += 1
				if counter%LOG_INTV == 0 {
					bar.Add(LOG_INTV)
				}
				_, ok := doneIps.Load(dstIpStr)
				if ok {
					continue
				}
				limiter.Wait(context.TODO())
				p.Add(net.ParseIP(dstIpStr).To4())
			}
			finish = true
		}()

		// recieve icmp
		go func() {
			for {
				icmpRes := p.GetIcmp()
				if icmpRes == nil {
					if finish {
						break
					}
				} else {
					if _, ok := testIps.Load(icmpRes.Target); !ok {
						continue
					}
					if icmpRes.Target != icmpRes.Real || icmpRes.Target == icmpRes.Res {
						Append1Addr6ToFS(outFile, icmpRes.Target+","+icmpRes.Real+","+icmpRes.Real+","+fmt.Sprintf("%d", ttl))
					}
				}
			}
		}()

		// recieve dns
		go func() {
			for {
				targetIp, realIp := p.GetDns()
				if targetIp == "" {
					if finish {
						break
					}
				} else {
					if _, ok := testIps.Load(targetIp); !ok {
						continue
					}
					if targetIp != realIp {
						Append1Addr6ToFS(dnsFile, targetIp+","+realIp+","+fmt.Sprintf("%d", ttl))
						doneIps.Store(targetIp, true)
					}
				}
			}
		}()

		for !finish {
			time.Sleep(time.Second)
		}
		time.Sleep(1 * time.Second)
		p.Finish()
	}
}

func DNSRouteScanWhole(srcMac, dstMac []byte, srcIpStr, ifaceName, outFile string, startTtl, endTtl uint8, pps, nSender int, nTot uint64) {
	os.Remove(outFile)
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)
	for ttl := startTtl; ttl <= endTtl; ttl++ {
		finish := false
		p := NewDNSPool(nSender, BUF_SIZE, srcIpStr, ifaceName, srcMac, dstMac, ttl)
		go func() {
			ipDec := uint64(1)
			counter := uint64(0)
			bar := progressbar.Default(int64(nTot), fmt.Sprintf("Scanning TTL=%d, %d waiting", ttl, p.LenInChan()))
			for i := uint64(0); i < PRIME; i++ {
				ipDec = (ipDec * 3) % PRIME
				if ipDec >= IPNUM || IsBogon(ipDec) {
					continue
				}
				if (i+1)%LOG_INTV == 0 {
					bar.Add(LOG_INTV)
					bar.Describe(fmt.Sprintf("Scanning TTL=%d, %d waiting", ttl, p.LenInChan()))
				}
				dstIp := make([]byte, 4)
				binary.BigEndian.PutUint32(dstIp, uint32(ipDec))
				limiter.Wait(context.TODO())
				p.Add(dstIp)
				counter++
				if counter == nTot {
					break
				}
			}
			time.Sleep(10 * time.Second)
			finish = true
		}()

		go func() {
			for {
				targetIp, realIp, resIp := p.GetIcmp()
				if targetIp == "" {
					if finish {
						break
					}
				} else if targetIp != realIp {
					Append1Addr6ToFS(outFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
				}
			}
		}()

		for !finish {
			time.Sleep(time.Second)
		}
		p.Finish()
	}
}

func DNSRouteScanWithForwarder(srcMac, dstMac []byte, srcIpStr, ifaceName, outDir string, startTtl, endTtl uint8, pps, nSender int, startFileNo, nSeg, nTot uint64, shards, shard uint64) {
	if startFileNo == 0 {
		if _, err := os.Stat(outDir); !os.IsNotExist(err) {
			fmt.Printf("Your are about to delete %s, are you sure?[y/n]", outDir)
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				response := scanner.Text()
				if strings.ToLower(response) == "y" {
					os.RemoveAll(outDir)
				} else {
					os.Exit(0)
				}
			}
		}
		os.Mkdir(outDir, 0755)
	}

	shards_mask := uint64((1 << shards) - 1)
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)
	ipDec := uint64(1)
	fileNo := startFileNo
	for i := uint64(0); i < fileNo * nSeg; i ++ { ipDec = (ipDec * 3) % PRIME }
	ipDecStart := ipDec

	bar := progressbar.Default(int64(nTot) * int64(endTtl - startTtl + 1) - int64(fileNo * nSeg) * int64(endTtl - startTtl + 1), "Scanning TTL=50, 0 waiting")
	for seg := uint64(startFileNo * nSeg); seg < nTot; seg += nSeg {
		icmpFile := filepath.Join(outDir, fmt.Sprintf("icmp-%d.txt", fileNo))
		dnsFile := filepath.Join(outDir, fmt.Sprintf("dns-%d.txt", fileNo))
		file, err := os.Create(icmpFile)
		if err != nil { panic(err) } else { file.Close() }
		file, err = os.Create(dnsFile)
		if err != nil { panic(err) } else { file.Close() }

		// traceroute
		tfSet := make(map[string]bool)
		p := NewDNSPoolTtl(nSender, BUF_SIZE, srcIpStr, ifaceName, srcMac, dstMac, uint16(shards), uint16(shard))
		finish := false
		go func() {
			for ttl := endTtl; ttl >= startTtl; ttl-- {
				ipDec = ipDecStart
				counter := seg
				for i := uint64(0); i < nSeg; i++ {
					if (i+1)%LOG_INTV == 0 {
						bar.Add(LOG_INTV)
						bar.Describe(fmt.Sprintf("Scanning %d-%d TTL=%d, %d waiting", seg, seg+nSeg, ttl, p.LenInChan()))
					}
					ipDec = (ipDec * 3) % PRIME
					if ipDec >= IPNUM || IsBogon(ipDec) || (ipDec & shards_mask) != shard { continue }
					dstIp := make([]byte, 4)
					binary.BigEndian.PutUint32(dstIp, uint32(ipDec))
					limiter.Wait(context.TODO())
					p.Add(dstIp, ttl)
					counter++
					if counter == nTot { break }
				}
			}
			time.Sleep(2 * time.Second)
			finish = true
		}()

		go func() {
			for {
				targetIp, realIp, resIp, ttl := p.GetIcmp()
				if targetIp == "" {
					if finish { break }
				} else if targetIp != realIp {
					Append1Addr6ToFS(icmpFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
					tfSet[targetIp] = true
				} else if tfSet[targetIp] {
					Append1Addr6ToFS(icmpFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
				}
			}
		}()

		for !finish { time.Sleep(time.Second) }
		p.Finish()
		ipDecStart = ipDec
		fileNo += 1

		// DNS
		finish = false
		ipStrSet := make(map[string]bool)
		icmpF, err := os.Open(icmpFile)
		if err != nil {
			panic(err)
		}
		scanner := bufio.NewScanner(icmpF)
		for scanner.Scan() {
			ipStrSet[strings.Split(scanner.Text(), ",")[0]] = true
			ipStrSet[strings.Split(scanner.Text(), ",")[1]] = true
		}
		icmpF.Close()

		pSlow := NewDNSPoolSlow(nSender, 10000, srcIpStr, ifaceName, srcMac, dstMac, 99)
		go func() {
			for {
				targetIp, realIp := pSlow.GetDns()
				if targetIp == "" {
					if finish {
						break
					}
				} else {
					Append1Addr6ToFS(dnsFile, targetIp+","+realIp+",DNS")
				}
			}
		}()
		go func() {
			for {
				icmpRes := pSlow.GetIcmp()
				if icmpRes == nil {
					if finish {
						break
					}
				} else {
					Append1Addr6ToFS(dnsFile, icmpRes.Target+","+icmpRes.Res+fmt.Sprintf(",ICMP%d-%d", icmpRes.Type, icmpRes.Code))
				}
			}
		}()
		for i := 0; i < 3; i++ {
			for ipStr := range ipStrSet {
				limiter.Wait(context.TODO())
				pSlow.Add(net.ParseIP(ipStr).To4())
			}
			time.Sleep(1 * time.Second)
			dnsF, err := os.Open(dnsFile)
			if err != nil {
				panic(err)
			}
			scanner := bufio.NewScanner(dnsF)
			for scanner.Scan() {
				delete(ipStrSet, strings.Split(scanner.Text(), ",")[0])
			}
			dnsF.Close()
		}
		finish = true
		pSlow.Finish()
	}
}