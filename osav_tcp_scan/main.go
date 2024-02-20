package main

import (
	"os"
	"fmt"
	"net"
	"flag"
	"time"
	"context"
	"encoding/binary"

	"osav_tcp_scan/utils"
	"golang.org/x/time/rate"
	"github.com/schollz/progressbar/v3"
)

var (
	ifaceName 	= flag.String("i", "eth0", "The interface used for scanning.")
	dstMacStr 	= flag.String("d", "", "The mac address of router.")
	pps	   		= flag.Uint64("pps", 250000, "PPS used for scanning.")
	localPort   = flag.Uint("l", 37301, "Local port used for scanning.")
	remotePort  = flag.Uint("r", 80, "Remote port used for scanning.")
)

const (
	PRIME uint64 = 4294967311
	IPNUM uint64 = 4294967296
	N_TOT uint64 = 3970694159
)

func TCPScan(remotePort uint16) {
	sameFile := fmt.Sprintf("data/same%d.txt", remotePort)
	diffFile := fmt.Sprintf("data/diff%d.txt", remotePort)
	os.Remove(sameFile)
	os.Remove(diffFile)
	
	// Get interface and source ip
	srcIpArr, srcMac, err := utils.GetIface(*ifaceName)
	if err != nil { panic(err) }
	srcIpStr := srcIpArr[0]
	dstMac, err := net.ParseMAC(*dstMacStr)
	if err != nil { panic(fmt.Sprintf("%s, %s\n", *dstMacStr, err)) }

	p := NewTCPoolv4(remotePort, 100000, uint16(*localPort), *ifaceName, srcIpStr, srcMac, dstMac)
	limiter := rate.NewLimiter(rate.Limit(*pps), 1000)
	ipDec := uint64(1)
	n_diff := 0
	n_same := 0
	n_sent := 0
	finish := false
	go func() {
		bar := progressbar.Default(int64(N_TOT), "0 same, 0 diff")
		for i := uint64(0); i < PRIME; i ++ {
			ipDec = (ipDec * 3) % PRIME
			if ipDec >= IPNUM ||  utils.IsBogon(ipDec) { continue }
			if (i + 1) % *pps == 0 { 
				bar.Add(int(*pps))
				bar.Describe(fmt.Sprintf("%d waiting, %d(%.2f%%) same, %d(%d approx) diff", p.LenInChan(), n_same, float64(n_same) / float64(n_sent) * 100, n_diff, int(float64(n_diff) / float64(i) * float64(PRIME))))
			}
			n_sent ++
			dstIpBin := make([]byte, 4)
			binary.BigEndian.PutUint32(dstIpBin, uint32(ipDec))
			limiter.Wait(context.TODO())
			p.Add(net.IP(dstIpBin).String())
		}
		finish = true
	}()

	go func() {
		for {
			orgIp, realIp := p.Get()
			if orgIp == realIp { 
				// utils.Append1Addr6ToFS(sameFile, orgIp)
				n_same += 1
			} else { 
				orgIpInt := binary.BigEndian.Uint32(net.ParseIP(orgIp).To4())
				if utils.IsBogon(uint64(orgIpInt)) { continue }
				utils.Append1Addr6ToFS(diffFile, orgIp + "," + realIp)
				n_diff += 1
			}
		}
	}()
	for !finish { time.Sleep(time.Second) }
	time.Sleep(10 * time.Second)
}

func main() {
	flag.Parse()
	TCPScan(uint16(*remotePort))
}
