package main

import (
	"context"
	"bufio"
	"net"
	"strings"
	"fmt"
	"os"
	"sync"
	"time"
	"path/filepath"
	"encoding/binary"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

const (
	LOCAL_PORT         = 37300
	BUF_SIZE           = 100000
	BURST              = 10000
	PRIME       uint64 = 4294967311
	IPNUM       uint64 = 4294967296
	LOG_INTV           = 10000
)

func TCPRouteScan(srcIpStr, iface, inputFile, outputFile string, startTtl, endTtl uint8, pps int, srcMac, dstMac []byte, remotePort uint16) {
	os.Remove(outputFile)
	dstIpStrArray := ReadLineAddr6FromFS(inputFile)
	bar := progressbar.Default(int64(len(dstIpStrArray)*int(endTtl-startTtl+1)), "Scanning...")
	var doneIps sync.Map
	var testIps sync.Map
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)

	for _, dstIpStr := range dstIpStrArray {
		testIps.Store(dstIpStr, true)
	}
	counter := 0
	tfSet := make(map[string]bool)
	for ttl := endTtl; ttl >= startTtl; ttl-- {
		p := NewTCPoolv4(remotePort, BUF_SIZE, LOCAL_PORT, iface, srcIpStr, srcMac, dstMac, ttl)
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
			time.Sleep(10 * time.Second)
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
					if icmpRes.Type != 11 { continue }
					if _, ok := testIps.Load(icmpRes.Target); !ok {
						continue
					}
					if icmpRes.Target != icmpRes.Real {
						Append1Addr6ToFS(outputFile, icmpRes.Target + "," + icmpRes.Real + "," + icmpRes.Res)
						tfSet[icmpRes.Target] = true
					} else if tfSet[icmpRes.Target] { Append1Addr6ToFS(outputFile, icmpRes.Target + "," + icmpRes.Real + "," + icmpRes.Res) }
				}
			}
		}()

		// recieve tcp
		go func() {
			for {
				target, real, _ := p.GetTcp()
				if target == "" {
					if finish {
						break
					}
				} else {
					if _, ok := testIps.Load(target); !ok {
						continue
					}
					if target != real {
						// Append1Addr6ToFS(outputFile, target + "," + real)
						doneIps.Store(target, true)
					}
				}
			}
		}()

		for !finish {
			time.Sleep(time.Second)
		}
		p.Finish()
	}
}

func TCPRouteScanWithForwarder(srcIpStr, iface, outDir, blockFile string, startTtl, endTtl uint8, pps int, startFileNo, nSeg, nTot uint64, srcMac, dstMac []byte, remotePort uint16) {
	if startFileNo == 0{
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

	limiter := rate.NewLimiter(rate.Limit(pps), BURST)
	ipDec := uint64(1)
	fileNo := startFileNo
	for i := uint64(0); i < fileNo * nSeg; i ++ {
		ipDec = (ipDec * 3) % PRIME
		if ipDec >= IPNUM || IsBogon(ipDec) { continue }
	}
	ipDecStart := ipDec
	for seg := uint64(startFileNo * nSeg); seg < nTot; seg += nSeg {
		icmpFile := filepath.Join(outDir, fmt.Sprintf("icmp-%d.txt", fileNo))
		tcpFile := filepath.Join(outDir, fmt.Sprintf("tcp-%d.txt", fileNo))
		file, err := os.Create(icmpFile)
		if err != nil {
			panic(err)
		} else {
			file.Close()
		}
		file, err = os.Create(tcpFile)
		if err != nil {
			panic(err)
		} else {
			file.Close()
		}
		// traceroute
		tfSet := make(map[string]bool)
		for ttl := endTtl; ttl >= startTtl; ttl-- {
			finish := false
			p := NewTCPoolv4Fast(remotePort, BUF_SIZE, LOCAL_PORT, iface, srcIpStr, srcMac, dstMac, ttl, blockFile)
			go func() {
				ipDec = ipDecStart
				counter := seg
				bar := progressbar.Default(int64(nSeg), fmt.Sprintf("Scanning TTL=%d, %d waiting", ttl, p.LenInChan()))
				for i := uint64(0); i < nSeg; i++ {
					if (i+1)%LOG_INTV == 0 {
						bar.Add(LOG_INTV)
						bar.Describe(fmt.Sprintf("Scanning %d-%d TTL=%d, %d waiting", seg, seg+nSeg, ttl, p.LenInChan()))
					}
					ipDec = (ipDec * 3) % PRIME
					if ipDec >= IPNUM || IsBogon(ipDec) {
						continue
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
				time.Sleep(5 * time.Second)
				finish = true
			}()

			go func() {
				for {
					targetIp, realIp, resIp, _ := p.GetIcmp()
					if targetIp == "" {
						if finish {
							break
						}
					} else if targetIp != realIp {
						Append1Addr6ToFS(icmpFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
						tfSet[targetIp] = true
					} else if tfSet[targetIp] {
						Append1Addr6ToFS(icmpFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
					}
				}
			}()

			for !finish {
				time.Sleep(time.Second)
			}
			p.Finish()
		}
		ipDecStart = ipDec
		fileNo += 1

		// TCP
		finish := false
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

		p := NewTCPoolv4(remotePort, BUF_SIZE, LOCAL_PORT, iface, srcIpStr, srcMac, dstMac, 99)
		go func() {
			for {
				targetIp, realIp, _ := p.GetTcp()
				if targetIp == "" {
					if finish {
						break
					}
				} else {
					Append1Addr6ToFS(tcpFile, targetIp+","+realIp+",TCP")
				}
			}
		}()
		go func() {
			for {
				icmpRes := p.GetIcmp()
				if icmpRes == nil {
					if finish {
						break
					}
				} else {
					Append1Addr6ToFS(tcpFile, icmpRes.Target+","+icmpRes.Res+fmt.Sprintf(",ICMP%d-%d", icmpRes.Type, icmpRes.Code))
				}
			}
		}()
		for i := 0; i < 3; i++ {
			for ipStr := range ipStrSet {
				limiter.Wait(context.TODO())
				p.Add(net.ParseIP(ipStr).To4())
			}
			time.Sleep(5 * time.Second)
			tcpF, err := os.Open(tcpFile)
			if err != nil {
				panic(err)
			}
			scanner := bufio.NewScanner(tcpF)
			for scanner.Scan() {
				delete(ipStrSet, strings.Split(scanner.Text(), ",")[0])
			}
			tcpF.Close()
		}
		finish = true
		p.Finish()
	}
}
