package main

import (
	"fmt"
	"time"
)

func TCPRoute(srcIpStr string, localPort uint16, dstIpStr string, remotePort uint16, startTtl, endTtl int, srcMac, dstMac []byte, iface string) {
	sendTimeArray := make([]int64, endTtl + 1)
	tcpRecv := false
	for ttl := startTtl; ttl <= endTtl; ttl ++ {
		sendTimeArray[ttl] = time.Now().UnixMilli()
		if ttl != startTtl { fmt.Println() }
		fmt.Printf("%s TTL = %d", time.Now().Format("2006/01/02 15:04:05"), ttl)
		p := NewTCPoolv4(remotePort, 100, localPort, iface, srcIpStr, srcMac, dstMac, uint8(ttl))
		go func() {
			target, real, res, port := p.GetIcmp()
			if target != "" {
				rtt := time.Now().UnixMilli() - sendTimeArray[ttl]
				fmt.Printf(", RTT = %d ms: Recieve ICMP (icmp-ip-dst = %s#%d) from %s", rtt, real, port, res)
			}
		}()
		go func() {
			target, real, port := p.GetTcp()
			if target != "" && target == dstIpStr {
				rtt := time.Now().UnixMilli() - sendTimeArray[ttl]
				fmt.Printf(", RTT = %d ms: Recieve TCP SYN-ACK from %s#%d", rtt, real, port)
				tcpRecv = true
			}
		}()
		p.Add(dstIpStr)
		time.Sleep(time.Second)
		p.Finish()
		if tcpRecv { break }
	}
}