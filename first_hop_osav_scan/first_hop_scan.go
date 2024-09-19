package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

func FirstHopScan(srcIpStr, ifaceName, inputFile, outputFile, dnsFile string, startTtl, endTtl uint8, pps int, srcMac, dstMac []byte) {
	os.Remove(outputFile)
	os.Remove(dnsFile)
	dstIpStrArr := ReadLineAddr6FromFS(inputFile)
	limiter := rate.NewLimiter(rate.Limit(pps), pps)

	finish := false
	randPfx := GetDomainRandPfx(RAND_LEN)
	fmt.Println("Random Prefix:", randPfx)
	fmt.Println("Press Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	pNormal := NewDNSPoolNormal(srcIpStr, ifaceName, srcMac, dstMac, randPfx)
	pSpoof := NewDNSPoolSpoof(srcIpStr, ifaceName, srcMac, dstMac, randPfx)
	pSpoofSame := NewDNSPoolSpoofSame(srcIpStr, ifaceName, srcMac, dstMac, randPfx)
	go func() {
		for {
			targetIp, res, ttl := pNormal.GetIcmp()
			if targetIp != "" {
				Append1Addr6ToFS(outputFile, fmt.Sprintf("%s,%s,%d", targetIp, res, ttl))
			} else if finish {
				break
			}
		}
	}()
	go func() {
		for {
			targetIp, res, ttl := pNormal.GetDns()
			if targetIp != "" {
				Append1Addr6ToFS(dnsFile, fmt.Sprintf("%s,%s,%d", targetIp, res, ttl))
			} else if finish {
				break
			}
		}
	}()

	bar := progressbar.Default(int64(len(dstIpStrArr))*int64(endTtl-startTtl+1)*3, "Scanning Normal...")
	for ttl := startTtl; ttl <= endTtl; ttl++ {
		for i, dstIpStr := range dstIpStrArr {
			if (i+1)%LOG_INTV == 0 {
				bar.Add(LOG_INTV)
				bar.Describe(fmt.Sprintf("Scanning Normal TTL=%d", ttl))
			}
			dstIp := net.ParseIP(dstIpStr).To4()
			pNormal.Add(dstIp, ttl)
			limiter.Wait(context.TODO())
		}
	}
	time.Sleep(10 * time.Second)
	finish = true

	for ttl := startTtl; ttl <= endTtl; ttl++ {
		for i, dstIpStr := range dstIpStrArr {
			if (i+1)%LOG_INTV == 0 {
				bar.Add(LOG_INTV)
				bar.Describe(fmt.Sprintf("Scanning Spoof TTL=%d", ttl))
			}
			dstIp := net.ParseIP(dstIpStr).To4()
			pSpoof.Add(dstIp, ttl)
			limiter.Wait(context.TODO())
		}
	}

	for ttl := startTtl; ttl <= endTtl; ttl++ {
		for i, dstIpStr := range dstIpStrArr {
			if (i+1)%LOG_INTV == 0 {
				bar.Add(LOG_INTV)
				bar.Describe(fmt.Sprintf("Scanning Spoof TTL=%d", ttl))
			}
			dstIp := net.ParseIP(dstIpStr).To4()
			pSpoofSame.Add(dstIp, ttl)
		}
	}
	bar.Finish()
	time.Sleep(10 * time.Second)
}

func SpoofRangeScan(ifaceName, inputFile string, pps int, srcMac, dstMac []byte) {
	file, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var ips []string

	for scanner.Scan() {
		line := scanner.Text()
		ips = append(ips, strings.Split(line, ",")[0])
	}

	randPfx := GetDomainRandPfx(RAND_LEN)
	fmt.Println("Random Prefix:", randPfx)
	fmt.Println("Press Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	spoofSender := NewDNSPoolSpoofAny(ifaceName, srcMac, dstMac, randPfx)
	limiter := rate.NewLimiter(rate.Limit(pps), pps)
	bar := progressbar.Default(int64(len(ips)*25), "Scanning Spoof Range...")
	for _range := uint8(31); _range > 7; _range-- {
		for i, ip := range ips {
			if (i+1)%100 == 0 {
				bar.Add(100)
			}
			limiter.Wait(context.Background())
			dstIp := net.ParseIP(ip).To4()
			dstIpUint32 := binary.BigEndian.Uint32(dstIp)
			srcIpUint32 := dstIpUint32 ^ (1 << (31 - _range))
			srcIp := make([]byte, 4)
			binary.BigEndian.PutUint32(srcIp, srcIpUint32)
			spoofSender.Add(srcIp, dstIp, _range)
		}
	}
	time.Sleep(10 * time.Second)
}

func CacheTest(srcIpStr, ifaceName, inputFile, outputFile string, srcMac, dstMac []byte) {
	os.Remove(outputFile)
	p := NewDNSPoolCache(srcIpStr, ifaceName, srcMac, dstMac)
	time.Sleep(20 * time.Second)

	dstIpStrArr := ReadLineAddr6FromFS(inputFile)
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
				Append1Addr6ToFS(outputFile, time.Now().In(location).Format("2006-01-02 15:04:05")+","+dstIpStr)
			}
		}
	}
}