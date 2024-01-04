package main

import (
	"os"
	"fmt"
	"net"
	"time"
	"bytes"
	"strconv"
	"strings"
	"encoding/binary"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	TRANSACTION_ID uint16 = 666
	FORMAT_IPV4_LEN = 15
	FORMAT_IPV6_LEN = 39
)

var (
	IPV4_TTL_DOMAIN_LEN = len(QryDomain) + RAND_LEN + FORMAT_IPV4_LEN + 6
	IPV6_TTL_DOMAIN_LEN = len(QryDomain) + RAND_LEN + FORMAT_IPV6_LEN + 6
)

func getDnsPkt(dstIpStr string, ttl int) []byte {
	// Construct DNS Header
	dnsHdrBuf := new(bytes.Buffer)
	var flags uint16 = 0x0100  // recursive
	var qdcount uint16 = 1   // # Queries
	var ancount, nscount, arcount uint16 = 0, 0, 0  //  Answer, Authoritive, Addition
	binary.Write(dnsHdrBuf, binary.BigEndian, TRANSACTION_ID)
	binary.Write(dnsHdrBuf, binary.BigEndian, flags)
	binary.Write(dnsHdrBuf, binary.BigEndian, qdcount)
	binary.Write(dnsHdrBuf, binary.BigEndian, ancount)
	binary.Write(dnsHdrBuf, binary.BigEndian, nscount)
	binary.Write(dnsHdrBuf, binary.BigEndian, arcount)
	dnsHdr := dnsHdrBuf.Bytes()

	// DNS Query
	qryDomain := fmt.Sprintf("%02d.", ttl)
	if strings.Contains(dstIpStr, ":") {
		qryDomain += RandFillDomain(dstIpStr)
	} else {
		qryDomain += RandFillDomain(FormatIpv4(dstIpStr))
	}
	dnsQryBuf := new(bytes.Buffer)
	sections := strings.Split(qryDomain, ".")
	for i := uint16(0); i < qdcount; i ++ {
		for _, s := range sections {
			binary.Write(dnsQryBuf, binary.BigEndian, byte(len(s)))  // length
			for _, b := range []byte(s) {
				binary.Write(dnsQryBuf, binary.BigEndian, b)
			}
		}
		binary.Write(dnsQryBuf, binary.BigEndian, byte(0)) // 末尾0长度octet
		binary.Write(dnsQryBuf, binary.BigEndian, uint16(1)) // 类型，AAAA为28
		binary.Write(dnsQryBuf, binary.BigEndian, uint16(1)) // 类，Internet为1
	}
	dnsQry := dnsQryBuf.Bytes()
	
	return append(dnsHdr, dnsQry...)
}

func DNSRouteTestUser(srcIpStr string, localPort uint16, dstIpStr string, startTTL, maxTTL int) {
	sendTimeArray := make([]int64, maxTTL + 1)
	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", srcIpStr, localPort))
    if err != nil { panic(err) }
	dialer := net.Dialer{ LocalAddr: localAddr, }
	ttl := startTTL
	dnsRecv := false

	// Listen ICMP
	go func() {
		icmpConn, err := icmp.ListenPacket("ip4:icmp", srcIpStr)
		if err != nil { panic(err) }
		defer icmpConn.Close()

		for {
			buf := make([]byte, 1024)
			_, addr, err := icmpConn.ReadFrom(buf)
			// log.Println(buf[:n])
			if err != nil { continue }

			icmpDstIpStr := net.IP(buf[24:28]).String()
			icmpSrcPort  := binary.BigEndian.Uint16(buf[28:30])
			// icmpDstPort  := binary.BigEndian.Uint16(buf[30:32])
			if icmpSrcPort != localPort { continue }
			rtt := time.Now().UnixMilli() - sendTimeArray[ttl]
			fmt.Printf(", RTT = %d ms: Recieve ICMP (icmp-ip-dst = %s) from %s", rtt, icmpDstIpStr, addr)
		}
	}()

	for ; ttl <= maxTTL; ttl ++ {
		sendTimeArray[ttl] = time.Now().UnixMilli()
		if ttl != startTTL { fmt.Println() }
		fmt.Printf("%s TTL = %d", time.Now().Format("2006/01/02 15:04:05"), ttl)

		udpSendConn, err := dialer.Dial("udp", fmt.Sprintf("%s:53", dstIpStr))
		if err != nil { panic(err) }

		// Set TTL
		if pconn, ok := udpSendConn.(*net.UDPConn); ok { if err = ipv4.NewConn(pconn).SetTTL(ttl); err != nil { panic(err) } }

		// Send DNS Packet
		if _, err = udpSendConn.Write(getDnsPkt(dstIpStr, ttl)); err != nil { panic(err) }

		udpSendConn.Close()
		
		// Try to Receive DNS Response
		udpRecvConn, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", srcIpStr, localPort))
		if err != nil { panic(err) }

		for {
			if err = udpRecvConn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil { panic(err) }
			buf := make([]byte, 1024)
			_, addr, err := udpRecvConn.ReadFrom(buf)
			if err != nil {
				if os.IsTimeout(err) { break }
				panic(err)
			}

			question, _ := ParseDNSQuestion(buf, 12)
			if len(question.Name) == 0 { continue }
			qryDomain := strings.Replace(question.Name, "\\", "", -1)
			if len(qryDomain) != IPV4_TTL_DOMAIN_LEN { continue }
			realIp := DeformatIpv4(qryDomain[3:][:FORMAT_IPV4_LEN])
			if realIp == dstIpStr {
				dnsTtl, err := strconv.Atoi(qryDomain[:2])
				if err != nil { dnsTtl = ttl }
				rtt := time.Now().UnixMilli() - sendTimeArray[dnsTtl]
				fmt.Printf("\r%s", time.Now().Format("2006/01/02 15:04:05"))
				fmt.Printf(" TTL = %d, RTT = %d ms: Receive DNS response from %s\n", dnsTtl, rtt, addr)
				dnsRecv = true
				break
			}
		}
		udpRecvConn.Close()
		
		if dnsRecv { break }
	}
}

func DNSRouteTestUserv6(srcIpStr string, localPort uint16, dstIpStr string, startTTL, maxTTL int) {
	sendTimeArray := make([]int64, maxTTL + 1)
	localAddr, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[%s]:%d", srcIpStr, localPort))
    if err != nil { panic(err) }
	dialer := net.Dialer{ LocalAddr: localAddr, }
	ttl := startTTL
	dnsRecv := false

	// Listen ICMPv6
	go func() {
		icmpConn, err := icmp.ListenPacket("ip6:ipv6-icmp", srcIpStr)
		if err != nil { panic(err) }
		defer icmpConn.Close()

		for {
			buf := make([]byte, 1024)
			_, addr, err := icmpConn.ReadFrom(buf)
			// log.Println(buf[:n])
			if err != nil { continue }

			icmpDstIpStr := net.IP(buf[32:48]).String()
			icmpSrcPort  := binary.BigEndian.Uint16(buf[48:50])
			if icmpSrcPort != localPort { continue }
			rtt := time.Now().UnixMilli() - sendTimeArray[ttl]
			fmt.Printf(", RTT = %d ms: Recieve ICMP (icmp-ip-dst = %s) from %s", rtt, icmpDstIpStr, addr)
		}
	}()

	for ; ttl <= maxTTL; ttl ++ {
		sendTimeArray[ttl] = time.Now().UnixMilli()
		if ttl != startTTL { fmt.Println() }
		fmt.Printf("%s TTL = %d", time.Now().Format("2006/01/02 15:04:05"), ttl)

		udpSendConn, err := dialer.Dial("udp6", fmt.Sprintf("[%s]:53", dstIpStr))
		if err != nil { panic(err) }

		// Set TTL
		if pconn, ok := udpSendConn.(*net.UDPConn); ok { if err = ipv6.NewConn(pconn).SetHopLimit(ttl); err != nil { panic(err) } }

		// Send DNS Packet
		if _, err = udpSendConn.Write(getDnsPkt(dstIpStr, ttl)); err != nil { panic(err) }

		udpSendConn.Close()
		
		// Try to Receive DNS Response
		udpRecvConn, err := net.ListenPacket("udp6", fmt.Sprintf("[%s]:%d", srcIpStr, localPort))
		if err != nil { panic(err) }

		for {
			if err = udpRecvConn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil { panic(err) }
			buf := make([]byte, 1024)
			_, addr, err := udpRecvConn.ReadFrom(buf)
			if err != nil {
				if os.IsTimeout(err) { break }
				panic(err)
			}

			question, _ := ParseDNSQuestion(buf, 12)
			if len(question.Name) == 0 { continue }
			qryDomain := strings.Replace(question.Name, "\\", "", -1)
			if len(qryDomain) != IPV6_TTL_DOMAIN_LEN { continue }
			realIp := qryDomain[3:][:FORMAT_IPV6_LEN]
			if realIp == dstIpStr {
				dnsTtl, err := strconv.Atoi(qryDomain[:2])
				if err != nil { dnsTtl = ttl }
				rtt := time.Now().UnixMilli() - sendTimeArray[dnsTtl]
				fmt.Printf("\r%s", time.Now().Format("2006/01/02 15:04:05"))
				fmt.Printf(" TTL = %d, RTT = %d ms: Receive DNS response from %s\n", dnsTtl, rtt, addr)
				dnsRecv = true
				break
			}
		}
		udpRecvConn.Close()
		
		if dnsRecv { break }
	}
}