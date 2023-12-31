package main

import (
	"os"
	"fmt"
	"net"
	"time"
	"context"
	"encoding/binary"

	"osav_tcp_scan/utils"
	"golang.org/x/time/rate"
	"github.com/schollz/progressbar/v3"
)

const (
	PRIME uint64 = 4294967311
	IPNUM uint64 = 4294967296
)

func TCPScan(remotePort uint16) {
	sameFile := fmt.Sprintf("data/same%d.txt", remotePort)
	diffFile := fmt.Sprintf("data/diff%d.txt", remotePort)
	os.Remove(sameFile)
	os.Remove(diffFile)
	p := NewTCPoolv4(remotePort, 1000000, "137.184.232.249")
	limiter := rate.NewLimiter(100000, 100)
	ipDec := uint64(1)
	bar := progressbar.Default(int64(PRIME), "0 same, 0 diff")
	n_diff := 0
	n_same := 0
	finish := false
	go func() {
		for i := uint64(0); i < PRIME; i ++ {
			bar.Add(1)
			bar.Describe(fmt.Sprintf("%d(%d approx) same, %d(%d approx) diff", n_same, int(float64(n_same) / float64(i) * float64(PRIME)), n_diff, int(float64(n_diff) / float64(i) * float64(PRIME))))
			ipDec = (ipDec * 3) % PRIME
			if ipDec >= IPNUM ||  utils.IsBogon(ipDec) { continue }
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
				utils.Append1Addr6ToFS(sameFile, orgIp)
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
	scanPorts := []uint16{21, 25, 8080, 4567, 53}
	for _, scanPort := range scanPorts {
		TCPScan(scanPort)
	}
}