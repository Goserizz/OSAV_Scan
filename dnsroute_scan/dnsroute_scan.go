package main

import (
	"os"
	"fmt"
	"log"
	"net"
	"time"
	"sync"
	"bytes"
	"strings"
	"syscall"
	"context"
	"math/rand"
	"encoding/binary"

	"golang.org/x/time/rate"
	"github.com/schollz/progressbar/v3"
)

const (
	TRANSACTION_ID uint16 = 666
	IPV4_TTL_DOMAIN_LEN = 43
	FORMAT_IPV4_LEN = 15
	REMOTE_PORT uint16 = 53
	RAND_LEN = 5
	QRY_DOMAIN = "v4.ruiruitest.com"
	CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	IPV4_HDR_SIZE = 20
	UDP_HDR_SIZE = 8
	LOG_INTV = 10000
	BURST = 1000
)

func RandFillDomain(ipStr string) string {
	if RAND_LEN == 0 {
		return ipStr + "." + QRY_DOMAIN
	} else {
		randSuffixBytes := make([]byte, RAND_LEN)
		for i := range randSuffixBytes {
			randSuffixBytes[i] = CHARS[rand.Intn(len(CHARS))]
		}
		return ipStr + "." + string(randSuffixBytes) + "." + QRY_DOMAIN
	}
}

func sendDNSv4(srcIpStr, dstIpStr string, ttl uint8) {
	srcIp := net.ParseIP(srcIpStr)
	dstIp := net.ParseIP(dstIpStr)
	// create IPv4 raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalln("Error creating socket:", err)
	}
	defer syscall.Close(fd)

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

	// Construct IPv4 Header
	ipv4Hdr := make([]byte, IPV4_HDR_SIZE)
	ipv4Hdr[0] = 0x45  // Vesrion = 4 | header length = 5
	// [1]     TOS
	// [2] [3] Total length
	// [4] [5] Identification
	copy(ipv4Hdr[4:6], dstIp.To4()[0:2])  // High 16 bits encoded in IP-ID
	// [6] [7] Flags | Fragment offset
	ipv4Hdr[8] = ttl
	ipv4Hdr[9] = 17  // Protocol = 17 (UDP)
	// [10 - 11] Header Checksum
 	copy(ipv4Hdr[12:], srcIp.To4())  // Source address
	// [16 - 20] Destination address

	QRY_DOMAIN := fmt.Sprintf("%02d.", ttl) + RandFillDomain(FormatIpv4(dstIp.String()))

	// DNS Query
	dnsQryBuf := new(bytes.Buffer)
	sections := strings.Split(QRY_DOMAIN, ".")
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

	// UDP Header
	udpHdrBuf := new(bytes.Buffer)
	// binary.Write(udpHdrBuf, binary.BigEndian, DNSROUTE_BASE_PORT + uint16(ttl))  // TTL encoded in source port
	binary.Write(udpHdrBuf, binary.BigEndian, binary.BigEndian.Uint16(dstIp.To4()[2:4]))
	binary.Write(udpHdrBuf, binary.BigEndian, REMOTE_PORT)  // remote port
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(UDP_HDR_SIZE + len(dnsHdr) + len(dnsQry)))  // length
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(0))  // Low 16 bits encoded in checksum
	udpHdr := udpHdrBuf.Bytes()

	// IPv4 Header
	totLen := uint16(len(dnsQry) + len(dnsHdr) + UDP_HDR_SIZE + IPV4_HDR_SIZE)
	ipv4Hdr[2] = byte(totLen >> 8)
	ipv4Hdr[3] = byte(totLen & 0xff)
	copy(ipv4Hdr[16:], dstIp.To4())
	ipv4Cksum := CalCksum(ipv4Hdr)
	ipv4Hdr[10] = byte(ipv4Cksum >> 8)
	ipv4Hdr[11] = byte(ipv4Cksum & 0xff)

	var pseudoHdr []byte
	pseudoHdr = append(pseudoHdr, ipv4Hdr[12:20]...)
	pseudoHdr = append(pseudoHdr, udpHdr[4:6]...)
	pseudoHdr = append(pseudoHdr, 0)
	pseudoHdr = append(pseudoHdr, ipv4Hdr[9])
	cksumData := append(pseudoHdr, udpHdr...)
	cksumData = append(cksumData, dnsHdr...)
	cksumData = append(cksumData, dnsQry...)
	cksum := CalCksum(cksumData)
	udpHdr[6] = byte(cksum >> 8)
	udpHdr[7] = byte(cksum & 0xff)

	// Combine IPv6 header, UDP header, DNS header, DNS query
	packet := append(ipv4Hdr, udpHdr...)
	packet = append(packet, dnsHdr...)
	packet = append(packet, dnsQry...)

	// Send packet
	var dstAddr [4]byte
	copy(dstAddr[:], dstIp.To4())
	for {
		err = syscall.Sendto(fd, packet, 0, &syscall.SockaddrInet4{
			Port: 0,
			Addr: dstAddr,
		})
		if err != nil {
			continue
		} else {
			break
		}
	}
}

func FormatIpv4(ipv4 string) string {
	var formatParts []string
	for _, part := range strings.Split(ipv4, ".") {
		for len(part) < 3 {
			part = "0" + part
		}
		formatParts = append(formatParts, part)
	}
	return strings.Join(formatParts, ".")
}

func DeformatIpv4(ipv4 string) string {
	var deformatParts []string
	for _, part := range strings.Split(ipv4, ".") {
		for part[0] == '0' && len(part) > 1 {
			part = part[1:]
		}
		deformatParts = append(deformatParts, part)
	}
	return strings.Join(deformatParts, ".")
}

func DNSRouteScan(srcIpStr, inFile, outFile, natFile, dnsFile string, startTtl, endTtl uint8, localPort uint16, pps int) {
	os.Remove(outFile)
	os.Remove(natFile)
	os.Remove(dnsFile)
	dstIpStrArray := ReadLineAddr6FromFS(inFile)
	bar := progressbar.Default(int64(len(dstIpStrArray) * int(endTtl - startTtl + 1)), "Scanning...")
	var doneIps sync.Map
	var testIps sync.Map
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)
	finished := false

	for _, dstIpStr := range dstIpStrArray {
		testIps.Store(dstIpStr, true)
	}

	go func() {
		// 创建原始套接字
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		if err != nil {
			log.Fatal(err)
		}
		defer syscall.Close(fd)

		// 绑定本地地址
		addr := syscall.SockaddrInet4{
			Port: 0,
			Addr: [4]byte{0, 0, 0, 0},
		}
		err = syscall.Bind(fd, &addr)
		if err != nil {
			log.Fatal(err)
		}

		// 接收ICMP报文
		for {
			buf := make([]byte, 1500)
			_, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				log.Fatal(err)
			}
			// buf = buf[:n]
			// 打印接收到的ICMP报文内容
			// ipAddr := addr.(*syscall.SockaddrInet4).Addr
			// srcIp := net.IPv4(ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
			icmpDstIpStr := net.IP(buf[44:48]).String()
			// icmpDstPort := binary.BigEndian.Uint16(buf[50:52])
			realIp := net.IPv4(buf[32], buf[33], buf[48], buf[49]).String()
			if buf[20] != 11 || buf[21] != 0 { continue }
			if _, ok := testIps.Load(realIp); !ok { continue }

			if icmpDstIpStr != realIp {
				Append1Addr6ToFS(outFile, realIp + "," + icmpDstIpStr)
				doneIps.Store(realIp, true)
			}
		}
	}()

	go func() {
		// Create IPv4 raw socket
		sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
		if err != nil {
			log.Fatalln(err)
		}
		defer syscall.Close(sock)

		laddr := &syscall.SockaddrInet4{ Port: int(localPort), }
		copy(laddr.Addr[:], net.ParseIP(srcIpStr))
		err = syscall.Bind(sock, laddr)
		if err != nil {
			log.Fatalln(err)
		}

		// Read packets
		for {
			buf := make([]byte, 65536)
			_, addr, err := syscall.Recvfrom(sock, buf, 0)
			if err != nil {
				continue
			}

			// Resolve UDP header
			remoteIpStr := net.IP(addr.(*syscall.SockaddrInet4).Addr[:]).String()
			// localPort := binary.BigEndian.Uint16(buf[22:24])
			remotePort := binary.BigEndian.Uint16(buf[20:22])
			txId := binary.BigEndian.Uint16(buf[28:30])
			if txId != TRANSACTION_ID  {
				continue
			}

			dnsPacket := buf[28:]
			question, _ := ParseDNSQuestion(dnsPacket, 12)
			if len(question.Name) == 0 {
				continue
			}
			// log.Println(question.Name, len(question.Name))
			QRY_DOMAIN := strings.Replace(question.Name, "\\", "", -1)
			if len(QRY_DOMAIN) != IPV4_TTL_DOMAIN_LEN {
				continue
			}
			realIp := DeformatIpv4(QRY_DOMAIN[3:][:FORMAT_IPV4_LEN])
			if _, ok := testIps.Load(realIp); !ok { continue }
			if _, ok := doneIps.Load(realIp); !ok { 
				Append1Addr6ToFS(dnsFile, realIp + "," + remoteIpStr) 
				if remotePort != REMOTE_PORT { Append1Addr6ToFS(natFile, realIp + "," + remoteIpStr) }
				doneIps.Store(realIp, true)
			}
		}
	}()

	go func() {
		counter := 0
		for ttl := startTtl; ttl <= endTtl; ttl ++ {
			bar.Describe(fmt.Sprintf("Scanning TTL=%d...", ttl))
			for _, dstIpStr := range dstIpStrArray {
				counter += 1
				if counter % LOG_INTV == 0 { bar.Add(LOG_INTV) }
				_, ok := doneIps.Load(dstIpStr); if ok { continue }
				limiter.Wait(context.TODO())
				sendDNSv4(srcIpStr, dstIpStr, ttl)
			}
		}
		finished = true
	}()

	for !finished { time.Sleep(time.Second) }
	time.Sleep(5 * time.Second)
}