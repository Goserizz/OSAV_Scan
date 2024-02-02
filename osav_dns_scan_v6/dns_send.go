package main

import (
	"log"
	"net"
	"bytes"
	"strings"
	"syscall"
	"math/rand"
	"encoding/binary"

	"osav_dns_scan_v6/utils"
)

const (
	MAC_HDR_SIZE = 14
	IPV6_HDR_SIZE = 40
	UDP_HDR_SIZE = 8
	DNS_HDR_SIZE = 12
	DNS_QRY_SIZE = 48
	QRY_DOMAIN = "v6.ruiruitest.online"
	TRANSACTION_ID uint16 = 6667
	CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	RAND_LEN = 4  // must be even
	// FORMAT_IPV6_LEN = 39
	FORMAT_IPV6_LEN = 16
	// FORMAT_IPV6 = "0000:0000:0000:0000:0000:0000:0000:0000"
	FORMAT_IPV6 = "0000000000000000"
)

var (
	ALL_HDR_SIZE = MAC_HDR_SIZE + IPV6_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE
	DOMAIN_LEN = RAND_LEN + 1 + FORMAT_IPV6_LEN + 1 + len(QRY_DOMAIN) + 1
)

func GetDomainRandPfx() string {
	randSuffixBytes := make([]byte, RAND_LEN)
	for i := range randSuffixBytes { randSuffixBytes[i] = CHARS[rand.Intn(len(CHARS))] }
	return string(randSuffixBytes)
}

func GetRandIid() []byte {
	var randIid []byte
	for i := 0; i < 8; i ++ {
		randIid = append(randIid, byte(rand.Intn(256)))
	}
	return randIid
}

type DNSPool struct {
	inChan 	    chan []byte
	outOrgChan  chan string
	outRealChan chan string
	srcIpStr    string
	ifaceName   string
	srcMac      []byte
	dstMac      []byte
	localPort   uint16
}

func NewDNSPool(bufSize int, srcIpStr string, ifaceName string, srcMac, dstMac []byte, localPort uint16) *DNSPool {
	dnsPool := &DNSPool{
		inChan: make(chan []byte, bufSize),
		outOrgChan: make(chan string, bufSize),
		outRealChan: make(chan string, bufSize),
		srcIpStr: srcIpStr,
		ifaceName: ifaceName,
		srcMac: srcMac,
		dstMac: dstMac,
		localPort: localPort,
	}
	go dnsPool.send()
	go dnsPool.recv()
	return dnsPool
}

func (p *DNSPool) Add(dstPfx []byte) {
	p.inChan <- dstPfx
}

func (p *DNSPool) Get() (string, string) {
	return utils.GetFullIP(<- p.outOrgChan), utils.GetFullIP((<- p.outRealChan))
}

func (p *DNSPool) LenInChan() int {
	return len(p.inChan)
}

func (p *DNSPool) send() {
	srcIp := net.ParseIP(p.srcIpStr)
	// Create IPv6 raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_IPV6)
	if err != nil { log.Fatalln("Error creating socket:", err) }
	defer syscall.Close(fd)

	// Construct MAC Header
	macHdr := make([]byte, MAC_HDR_SIZE)
	copy(macHdr[0:6], p.dstMac)
	copy(macHdr[6:12], p.srcMac)
	binary.BigEndian.PutUint16(macHdr[12:14], syscall.ETH_P_IPV6)

	// Get Interface Info
	iface, err := net.InterfaceByName(p.ifaceName)
	if err != nil {
		log.Fatalf("Interface error: %v\n", err)
	}
	bindAddr := &syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IP,
		Ifindex:  iface.Index,
	}

	// Construct IPv6 Header
	iid := GetRandIid()
	ipv6Hdr := make([]byte, IPV6_HDR_SIZE)
	ipv6Hdr[0] = 6 << 4  // version = 6
	binary.BigEndian.PutUint16(ipv6Hdr[4:6], UDP_HDR_SIZE + DNS_HDR_SIZE + DNS_QRY_SIZE)  // UDP size
	ipv6Hdr[6] = 17  // next header = UDP
	ipv6Hdr[7] = 255  // hop limit = 255
	copy(ipv6Hdr[8:], srcIp.To16())  // src IPv6
	copy(ipv6Hdr[32:], iid)

	// UDP Header
	udpHdrBuf := new(bytes.Buffer)
	binary.Write(udpHdrBuf, binary.BigEndian, p.localPort)  // local port
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(53))  // remote port
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(UDP_HDR_SIZE + DNS_HDR_SIZE + DNS_QRY_SIZE))  // length
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(0))  // checksum
	udpHdr := udpHdrBuf.Bytes()

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

	// construct DNS Query
	randPfx := GetDomainRandPfx()
	preDomain := randPfx + "." + FORMAT_IPV6 + "." + QRY_DOMAIN
	dnsQryBuf := new(bytes.Buffer)
	sections := strings.Split(preDomain, ".")
	for _, s := range sections {
		binary.Write(dnsQryBuf, binary.BigEndian, byte(len(s)))  // length
		for _, b := range []byte(s) {
			binary.Write(dnsQryBuf, binary.BigEndian, b)
		}
	}
	binary.Write(dnsQryBuf, binary.BigEndian, byte(0)) // 末尾0长度octet
	binary.Write(dnsQryBuf, binary.BigEndian, uint16(28)) // 类型，AAAA为28
	binary.Write(dnsQryBuf, binary.BigEndian, uint16(1)) // 类，Internet为1
	dnsQry := dnsQryBuf.Bytes()
	copy(dnsQry[RAND_LEN + 10:], iid)

	// pre calculate checksum
	udpCks := uint32(0)
	for i := 0; i < 16; i += 2 { udpCks += uint32(binary.BigEndian.Uint16(srcIp[i:i+2])) }
	for i := 0; i < 8; i += 2 {udpCks += uint32(binary.BigEndian.Uint16(iid[i:i+2]))}
	udpCks += UDP_HDR_SIZE + DNS_HDR_SIZE + DNS_QRY_SIZE  // UDP Length
	udpCks += syscall.IPPROTO_UDP  // upper layer protocol: UDP
	for i := 0; i < 6; i += 2 { udpCks += uint32(binary.BigEndian.Uint16(udpHdr[i:i+2])) }
	for i := 0; i < DNS_HDR_SIZE; i += 2 { udpCks += uint32(binary.BigEndian.Uint16(dnsHdr[i:i+2])) }
	for i := 0; i < 2 + RAND_LEN; i += 2 { udpCks += uint32(binary.BigEndian.Uint16(dnsQry[i:i+2])) }
	// udpCks += FORMAT_IPV6_LEN << 8 + 50  // ASCII("2") = 50 
	for i := 2 + RAND_LEN + 8; i < DNS_QRY_SIZE; i += 2 { udpCks += uint32(binary.BigEndian.Uint16(dnsQry[i:i+2])) }

	// Combine IPv6 header, UDP header, DNS header, DNS query
	packet := append(macHdr, ipv6Hdr...)
	packet  = append(packet, udpHdr...)
	packet  = append(packet, dnsHdr...)
	packet  = append(packet, dnsQry...)

	for {
		dstPfx := <- p.inChan

		// Complete IPv6 Header
		// copy(ipv6Hdr[24:], dstIp.To16())  // dst IPv6
		copy(packet[38:], dstPfx)

		// Complete DNS Header
		// dstIpStrBytes := []byte(dstIpStr)
		sum := udpCks
		for i := 0; i < 8; i += 2 { sum += (uint32(binary.BigEndian.Uint16(dstPfx[i : i + 2])) << 1) }
		// for i := 1; i < FORMAT_IPV6_LEN; i += 2 { sum += uint32(binary.BigEndian.Uint16(dstIpStrBytes[i : i + 2])) }
		// binary.BigEndian.PutUint16(dnsHdr[6:8], cks)
		binary.BigEndian.PutUint16(packet[60:62], uint16(^(sum + (sum >> 16))))

		// Complete UDP Header
		// copy(dnsQry[2 + RAND_LEN:], dstIpStrBytes)
		copy(packet[ALL_HDR_SIZE + RAND_LEN + 2:], dstPfx)

		// Send packet
		for { if err = syscall.Sendto(fd, packet, 0, bindAddr); err == nil { break } }
	}
}

func (p *DNSPool) recv() {
	// Create IPv6 raw socket
	sock, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		log.Fatalln(err)
	}
	defer syscall.Close(sock)

	laddr := &syscall.SockaddrInet6{
		Port: int(p.localPort),
	}
	copy(laddr.Addr[:], net.ParseIP(p.srcIpStr))
	err = syscall.Bind(sock, laddr)
	if err != nil {
		log.Fatalln(err)
	}

	// Read packets
	for {
		buf := make([]byte, 1024)
		_, addr, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			continue
		}

		// Resolve UDP header
		// remotePort := uint16(buf[0]) << 8 | uint16(buf[1])
		remoteIpStr := net.IP(addr.(*syscall.SockaddrInet6).Addr[:]).String()
		localPort := uint16(buf[2]) << 8 | uint16(buf[3])
		if localPort != p.localPort { continue }

		// dnsPacket := buf[8:]
		// log.Println(buf)
		if buf[20] != RAND_LEN { continue }
		if buf[21 + RAND_LEN] != FORMAT_IPV6_LEN { continue }
		if buf[22 + RAND_LEN + FORMAT_IPV6_LEN] != 2 { continue }
		if buf[23 + RAND_LEN + FORMAT_IPV6_LEN + 2] != 10 { continue }
		if buf[24 + RAND_LEN + FORMAT_IPV6_LEN + 2 + 10] != 6 { continue }
		if buf[25 + RAND_LEN + FORMAT_IPV6_LEN + 2 + 10 + 6] != 0 { continue }

		p.outOrgChan <- net.IP(buf[22 + RAND_LEN:][:FORMAT_IPV6_LEN]).String()
		p.outRealChan <- remoteIpStr
	}
}