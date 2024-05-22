package main

import (
	"os"
	"fmt"
	"net"
	"time"
	"context"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

func FirstHopScan(srcIpStr, ifaceName, inputFile, outputFile string, startTtl, endTtl uint8, pps int, srcMac, dstMac []byte) {
	os.Remove(outputFile)
	dstIpStrArr := ReadLineAddr6FromFS(inputFile)
	bar := progressbar.Default(int64(len(dstIpStrArr)) * int64(endTtl-startTtl+1) * 2, "Scanning Normal...")
	limiter := rate.NewLimiter(rate.Limit(pps), pps)

	finish := false
	pNormal := NewDNSPoolNormal(srcIpStr, ifaceName, srcMac, dstMac)
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
	for ttl := startTtl; ttl <= endTtl; ttl++ {
		for i, dstIpStr := range dstIpStrArr {
			if (i + 1) % LOG_INTV == 0 {
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

	pSpoof := NewDNSPoolSpoof(srcIpStr, ifaceName, srcMac, dstMac)
	for ttl := startTtl; ttl <= endTtl; ttl++ {
		for i, dstIpStr := range dstIpStrArr {
			if (i + 1) % LOG_INTV == 0 {
				bar.Add(LOG_INTV)
				bar.Describe(fmt.Sprintf("Scanning Spoof TTL=%d", ttl))
			}
			dstIp := net.ParseIP(dstIpStr).To4()
			pSpoof.Add(dstIp, ttl)
			limiter.Wait(context.TODO())
		}
	}
	bar.Finish()
}