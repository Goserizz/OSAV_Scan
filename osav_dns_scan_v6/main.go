package main

import (
	"os"
	"fmt"
	"net"
	"time"
	"flag"
	"context"
	"math/rand"

	"osav_dns_scan_v6/utils"

	"golang.org/x/time/rate"
	"github.com/schollz/progressbar/v3"
)

const (
	BURST = 1000
	UPDATE_INTV = 100000
)

var (
	ifaceName 	= flag.String("iface", "eth0", "The interface used for scanning.")
	dstMacStr 	= flag.String("dmac", "", "The mac address of router.")
	pps	   		= flag.Uint64("r", 200000, "PPS used for scanning.")
	localPort   = flag.Uint("p", 37300, "Local port used for scanning.")
	inputFile   = flag.String("i", "", "Input file for scanning.")
	diffFile    = flag.String("d", "", "Output file for diff.")
	sameFile    = flag.String("s", "", "Output file for same.")
	scanPfxLen  = flag.Int("l", 48, "Scan to which length of prefixes.")
)

func V6OsavScan(ifaceName, srcIpStr, inputFile, diffFile, sameFile string, srcMac, dstMac []byte) {
	sendFinish := false
	dnsPool := NewDNSPool(100000, srcIpStr, ifaceName, srcMac, dstMac, uint16(*localPort))
	var pfxBitsArr []utils.BitsArray
	pfxBitsInd := make(map[int]int)
	// var pfxBitsInd []int
	limiter := rate.NewLimiter(rate.Limit(*pps), BURST)

	lines := utils.ReadLineAddr6FromFS(inputFile)
	for i := len(lines) - 1; i > 0; i -- {
		j := rand.Intn(i + 1)
		lines[i], lines[j] = lines[j], lines[i]
	}
	totProbes := int64(0)
	nTotal := 0
	for _, pfxStr := range(lines) {
		_, pfx, _ := net.ParseCIDR(pfxStr)
		for _, pfxBits := range utils.Pfx2Bits(pfx) {
			if pfxBits.PrefixLen() >= uint8(*scanPfxLen) { totProbes += 1 } else { totProbes += 1 << (uint8(*scanPfxLen) - pfxBits.PrefixLen()) }
			pfxBitsArr = append(pfxBitsArr, pfxBits)
			// pfxBitsInd = append(pfxBitsInd, 0)
			pfxBitsInd[nTotal] = 0
			nTotal += 1
		}
	}
	bar := progressbar.Default(totProbes, "Scanning...")

	go func() {
		finished := false
		// nRemain := len(pfxBitsArr)
		counter := 0
		nowPfxLen := uint8(0)
		for !finished {
			finished = true
			var delArr []int
			// for i := range(pfxBitsArr) {
			for i, ind := range pfxBitsInd {
				pfxBits := pfxBitsArr[i]
				// ind := pfxBitsInd[i]
				maxInd := 1
				if pfxBits.PrefixLen() < uint8(*scanPfxLen) { maxInd = 1 << (uint8(*scanPfxLen) - pfxBits.PrefixLen()) }
				if ind == maxInd { 
					delArr = append(delArr, i)
					nowPfxLen = pfxBits.PrefixLen() - 1
					continue 
				} else { finished = false }
				if maxInd == 1 {
					nowIpBits := pfxBits.Copy()
					nowIpBits.RandFill()
					limiter.Wait(context.TODO())
					dnsPool.Add(nowIpBits.ToIPv6())
				} else {
					genLen := uint8(*scanPfxLen) - pfxBits.PrefixLen()
					nowIpBits := pfxBits.Copy()
					for jnd := uint8(0); jnd < genLen / 4; jnd ++ {
						nowBits := (ind >> (4 * jnd)) & 0xf
						nowIpBits.Append(byte(nowBits))
					}
					nowIpBits.RandFill()
					limiter.Wait(context.TODO())
					dnsPool.Add(nowIpBits.ToIPv6())
				}
				pfxBitsInd[i] = ind + 1
				counter ++
				if counter % UPDATE_INTV == 0 {
					bar.Describe(fmt.Sprintf("Inchan: %d..., %d/%d (/%d) scanning", dnsPool.LenInChan(), len(pfxBitsInd), nTotal, nowPfxLen))
					bar.Add(UPDATE_INTV)
				}
			}
			for _, i := range delArr { delete(pfxBitsInd, i) }
			newPfxBitsInd := make(map[int]int)
			for k, v := range pfxBitsInd { newPfxBitsInd[k] = v}
			pfxBitsInd = newPfxBitsInd
		}
		sendFinish = true
	}()

	os.Remove(diffFile)
	os.Remove(sameFile)
	go func() {
		for {
			orgIp, realIp := dnsPool.Get()
			if orgIp != realIp { utils.Append1Addr6ToFS(diffFile, orgIp + "," + realIp) } else { utils.Append1Addr6ToFS(sameFile, orgIp) }
		}
	}()

	dnsPool.Add("2001:4860:4860:0000:0000:0000:0000:8888")

	for !sendFinish {
		time.Sleep(time.Second)
	}
	time.Sleep(5 * time.Second)
}

func main() {
	flag.Parse()

	var err error
	if *ifaceName == "" {
		*ifaceName, err = utils.GetDefaultRouteInterface()
		if err != nil { panic("Please Specify the Interface for DNSRoute.") }
	}
	_, srcIpv6Arr, srcMac, err := utils.GetIface(*ifaceName)
	if err != nil { panic(err) }
	dstMac, err := net.ParseMAC(*dstMacStr)
	if err != nil { panic(fmt.Sprintf("%s, %s\n", *dstMacStr, err)) }

	V6OsavScan(*ifaceName, srcIpv6Arr[0], *inputFile, *diffFile, *sameFile, srcMac, dstMac)
}