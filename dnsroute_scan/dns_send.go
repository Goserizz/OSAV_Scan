package main

import (
	"net"
	"time"
	"bytes"
	"strings"
	"syscall"
	"math/rand"
	"encoding/binary"
)

const (
	MAC_HDR_SIZE = 14
	IPV4_HDR_SIZE = 20
	UDP_HDR_SIZE = 8
	DNS_HDR_SIZE = 12
	DNS_QRY_SIZE = 12
	QRY_DOMAIN = "v4.ruiruitest.online"
	JD_DOMAIN = "jd.com"
	TRANSACTION_ID uint16 = 6666
	CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	RAND_LEN = 5  // must be odd
	FORMAT_IPV4_LEN = 4
	FORMAT_IPV4 = "0000"
	FORMAT_TTL_LEN = 2
	FORMAT_TTL  = "00"
)

var (
	IPV4_TTL_DOMAIN_LEN = RAND_LEN + FORMAT_TTL_LEN + FORMAT_IPV4_LEN + len(QRY_DOMAIN) + 4
	IPV4_LEN = uint16(IPV4_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE + DNS_QRY_SIZE)
)

func GetDomainRandPfx(randLen int) string {
	randSuffixBytes := make([]byte, randLen)
	for i := range randSuffixBytes { randSuffixBytes[i] = CHARS[rand.Intn(len(CHARS))] }
	return string(randSuffixBytes)
}

type DNSPool struct {
	inIpChan          chan []byte
	outIcmpTargetChan chan string
	outIcmpRealChan   chan string
	outIcmpResChan    chan string
	outDnsTargetChan  chan string
	outDnsRealChan    chan string
	srcIpStr          string
	ifaceName         string
	srcMac            []byte
	dstMac            []byte
	localPort         uint16
	ttl               uint8
	finish            bool
	nSender           int
}

func NewDNSPool(nSender, bufSize int, srcIpStr string, ifaceName string, srcMac, dstMac []byte, ttl uint8) *DNSPool {
	dnsPool := &DNSPool{
		inIpChan: make(chan []byte, bufSize),
		outIcmpTargetChan: make(chan string, bufSize),
		outIcmpRealChan: make(chan string, bufSize),
		outIcmpResChan: make(chan string, bufSize),
		outDnsTargetChan: make(chan string, bufSize),
		outDnsRealChan: make(chan string, bufSize),
		srcIpStr: srcIpStr,
		ifaceName: ifaceName,
		srcMac: srcMac,
		dstMac: dstMac,
		ttl: ttl,
		finish: false,
		nSender: nSender,
	}
	for i := 0; i < nSender; i ++ { go dnsPool.send() }
	go dnsPool.recvIcmp()
	return dnsPool
}

func (p *DNSPool) Add(dstIp []byte) {
	p.inIpChan <- dstIp
}

func (p *DNSPool) GetIcmp() (string, string, string) {
	select {
		case targetIp := <- p.outIcmpTargetChan:
			return targetIp, <- p.outIcmpRealChan, <- p.outIcmpResChan
		case <-time.After(time.Second):
			return "", "", ""
	}
}

func (p *DNSPool) LenInChan() int {
	return len(p.inIpChan)
}

func (p *DNSPool) send() {
	// Create IPv6 raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_IP)
	if err != nil { panic(err) }
	defer syscall.Close(fd)

	// Construct MAC Header
	macHdr := make([]byte, MAC_HDR_SIZE)
	copy(macHdr[0:6], p.dstMac)
	copy(macHdr[6:12], p.srcMac)
	binary.BigEndian.PutUint16(macHdr[12:14], syscall.ETH_P_IP)

	// Get Interface Info
	iface, err := net.InterfaceByName(p.ifaceName)
	if err != nil { panic(err) }
	bindAddr := &syscall.SockaddrLinklayer{ Protocol: syscall.ETH_P_IP, Ifindex:  iface.Index, }

	// IP Header
	srcIp := net.ParseIP(p.srcIpStr)
	ipv4Hdr := make([]byte, IPV4_HDR_SIZE)
	ipv4Hdr[0] = 0x45  // Vesrion = 4 | header length = 5
	// [1]	 TOS
	// [2] [3] Total length
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], IPV4_LEN)
	// [4] [5] Identification
	// [6] [7] Flags | Fragment offset
	ipv4Hdr[8] = p.ttl  // TTL
	ipv4Hdr[9] = syscall.IPPROTO_UDP  // Protocol = 6 (TCP)
	// [10 - 11] Header Checksum
 	copy(ipv4Hdr[12:16], srcIp.To4())  // Source address
	// [16 - 20] Destination address

	// UDP Header
	udpHdrBuf := new(bytes.Buffer)
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(0))  // local port
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
	dnsQryBuf := new(bytes.Buffer)
	sections := strings.Split(JD_DOMAIN, ".")
	for _, s := range sections {
		binary.Write(dnsQryBuf, binary.BigEndian, byte(len(s)))  // length
		for _, b := range []byte(s) {
			binary.Write(dnsQryBuf, binary.BigEndian, b)
		}
	}
	binary.Write(dnsQryBuf, binary.BigEndian, byte(0)) // 0
	binary.Write(dnsQryBuf, binary.BigEndian, uint16(1)) // A
	binary.Write(dnsQryBuf, binary.BigEndian, uint16(1)) // Internet
	dnsQry := dnsQryBuf.Bytes()

	// pre calculate IP header checksum
	ipv4Cks := uint32(0)
	for i := 0; i < 20; i += 2 { ipv4Cks += uint32(binary.BigEndian.Uint16(ipv4Hdr[i:i+2])) }

	// Combine IPv6 header, UDP header, DNS header, DNS query
	packet := append(macHdr, ipv4Hdr...)
	packet  = append(packet, udpHdr...)
	packet  = append(packet, dnsHdr...)
	packet  = append(packet, dnsQry...)

	// dstIpStrBytes := make([]byte, FORMAT_IPV4_LEN + 1)
	// dstIpStrBytes[0] = FORMAT_IPV4_LEN

	var dstIp []byte
	// OuterLoop:
	for {
		// select {
		// case dstIp = <- p.inIpChan:
		// case <-time.After(2 * time.Second):
		// 	if p.finish { break OuterLoop } else { continue OuterLoop }
		// }
		dstIp = <- p.inIpChan
		if dstIp == nil { break }
		// dstIp := net.ParseIP(dstIpStr).To4()
		dstIpHigh := uint32(binary.BigEndian.Uint16(dstIp[0:2]))
		dstIpLow  := uint32(binary.BigEndian.Uint16(dstIp[2:4]))

		// Complete IPv4 Header
		copy(packet[18:20], dstIp[:2])  // encode high 16 bits in IP-ID
		copy(packet[30:34], dstIp)
		ipv4NowCks := ipv4Cks + dstIpHigh + dstIpHigh + dstIpLow
		binary.BigEndian.PutUint16(packet[24:26], uint16(^(ipv4NowCks + (ipv4NowCks >> 16))))

		// Complete UDP Header
		copy(packet[34:36], dstIp[2:4])  // encode low 16 bits in source port

		// Send packet
		for { if err = syscall.Sendto(fd, packet, 0, bindAddr); err == nil { break } }
	}
}

func (p *DNSPool) recvIcmp() {
	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil { panic(err) }
	defer syscall.Close(fd)

	// 绑定本地地址
	addr := syscall.SockaddrInet4{ Port: 0, Addr: [4]byte{0, 0, 0, 0}, }
	err = syscall.Bind(fd, &addr)
	if err != nil { panic(err) }

	ipv4LenUint8 := uint8(IPV4_LEN)
	// 接收ICMP报文
	for {
		buf := make([]byte, 1500)
		_, addr, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil { panic(err) }
		if p.finish { break }
		if buf[31] != ipv4LenUint8 || buf[37] != syscall.IPPROTO_UDP || buf[20] != 11 || buf[21] != 0 { continue }
		p.outIcmpTargetChan <- net.IPv4(buf[32], buf[33], buf[48], buf[49]).String()
		p.outIcmpRealChan <- net.IP(buf[44:48]).String()
		p.outIcmpResChan <- net.IP(addr.(*syscall.SockaddrInet4).Addr[:]).String()
	}
}

func (p *DNSPool) Finish() {
	p.Add(nil)
	p.finish = true
}
