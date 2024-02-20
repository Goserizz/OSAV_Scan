package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

const (
	LOCAL_PORT = 37300
	BUF_SIZE   = 10000
	BURST      = 100
	LOG_INTV   = 10000
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
				p.Add(dstIpStr)
			}
			time.Sleep(10 * time.Second)
			finish = true
		}()

		// recieve icmp
		go func() {
			for {
				target, real, res, _ := p.GetIcmp()
				if target == "" {
					if finish {
						break
					}
				} else {
					if _, ok := testIps.Load(target); !ok {
						continue
					}
					if target != real {
						Append1Addr6ToFS(outputFile, target + "," + real + "," + res)
						tfSet[target] = true
					} else if tfSet[target] { Append1Addr6ToFS(outputFile, target + "," + real + "," + res) }
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
