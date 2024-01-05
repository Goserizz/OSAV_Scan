package main

import (
	"os"
	"fmt"
	"net"
	"log"
	"time"
	"flag"
	"context"
	"strings"
	"strconv"
	"math/rand"

	"osav_dns_scan_v6/utils"

	"golang.org/x/time/rate"
	"github.com/schollz/progressbar/v3"
)

const (
	BURST = 1000
	UPDATE_INTV = 10000
	SCAN_PFX_LEN = 60
)

var (
	ifaceName 	= flag.String("iface", "eth0", "The interface used for scanning.")
	dstMacStr 	= flag.String("dmac", "", "The mac address of router.")
	pps	   		= flag.Uint64("r", 200000, "PPS used for scanning.")
	localPort   = flag.Uint("p", 37300, "Local port used for scanning.")
	inputFile   = flag.String("i", "", "Input file for scanning.")
	diffFile    = flag.String("d", "", "Output file for diff.")
	sameFile    = flag.String("s", "", "Output file for same.")
)

func V6OsavScan(ifaceName, srcIpStr, inputFile, diffFile, sameFile string, srcMac, dstMac []byte) {
	sendFinish := false
	dnsPool := NewDNSPool(100000, srcIpStr, ifaceName, srcMac, dstMac, uint16(*localPort))
	var pfxBitsArr []utils.BitsArray
	var pfxBitsInd []int
	limiter := rate.NewLimiter(rate.Limit(*pps), BURST)

	lines := utils.ReadLineAddr6FromFS(inputFile)
	for i := len(lines) - 1; i > 0; i -- {
		j := rand.Intn(i + 1)
		lines[i], lines[j] = lines[j], lines[i]
	}
	totProbes := int64(0)
	for _, pfxStr := range(lines) {
		pfxLen, err := strconv.Atoi(strings.Split(pfxStr, "/")[1])
		if err != nil {log.Fatalln(err)}
		if pfxLen >= SCAN_PFX_LEN { totProbes += 1 } else { totProbes += 1 << (SCAN_PFX_LEN - pfxLen) }
		_, pfx, _ := net.ParseCIDR(pfxStr)
		for _, pfxBits := range utils.Pfx2Bits(pfx) {
			pfxBitsArr = append(pfxBitsArr, pfxBits)
			pfxBitsInd = append(pfxBitsInd, 0)
		}
	}
	bar := progressbar.Default(totProbes, "Scanning...")

	go func() {
		finished := false
		counter := 0
		for !finished {
			finished = true
			for i := range(pfxBitsArr) {
				pfxBits := pfxBitsArr[i]
				ind := pfxBitsInd[i]
				maxInd := 1
				if pfxBits.PrefixLen() < SCAN_PFX_LEN { maxInd = 1 << (SCAN_PFX_LEN - pfxBits.PrefixLen()) }
				if ind == maxInd { continue } else { finished = false }
				if maxInd == 1 {
					nowIpBits := pfxBits.Copy()
					nowIpBits.RandFill()
					limiter.Wait(context.TODO())
					dnsPool.Add(nowIpBits.ToIPv6())
				} else {
					genLen := SCAN_PFX_LEN - pfxBits.PrefixLen()
					nowIpBits := pfxBits.Copy()
					for jnd := uint8(0); jnd < genLen / 4; jnd ++ {
						nowBits := (ind >> (4 * jnd)) & 0xf
						nowIpBits.Append(byte(nowBits))
					}
					// nowIpBits = nowIpBits.FillZero64()
					nowIpBits.RandFill()
					limiter.Wait(context.TODO())
					dnsPool.Add(nowIpBits.ToIPv6())
				}
				pfxBitsInd[i] = ind + 1
				counter ++
				if counter % UPDATE_INTV == 0 {
					bar.Describe(fmt.Sprintf("Inchan: %d...", dnsPool.LenInChan()))
					bar.Add(UPDATE_INTV)
				}
			}

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