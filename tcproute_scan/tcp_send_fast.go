package main

import (
	"os"
	"net"
	"log"
	"time"
	"bufio"
	"syscall"
	"strings"
	"encoding/binary"
)

type TCPoolv4Fast struct {
	inChan	  	chan []byte
	outTcpTgtChan  chan string
	outTcpRealChan chan string
	outTcpPortChan chan uint16
	outIcmpTgtChan chan string
	outIcmpRealChan chan string
	outIcmpResChan chan string
	outIcmpPortChan chan uint16
	srcIpStr	string
	localPort	uint16
	remotePort  uint16
	ipv4Cks	 	uint32
	iface	   	string
	srcMac	  	[]byte
	dstMac	  	[]byte
	ttl         uint8
	finish      bool
	blockSet    map[string]bool
}

func NewTCPoolv4Fast(remotePort uint16, bufSize int, localPort uint16, iface, srcIpStr string, srcMac []byte, dstMac []byte, ttl uint8, blockFile string) *TCPoolv4Fast {
	srcIp := net.ParseIP(srcIpStr)
	ipv4Cks := uint32(0)
	ipv4Cks += 0x45 << 8
	ipv4Cks += IPV4_HDR_SIZE + TCP_HDR_SIZE
	ipv4Cks += (uint32(ttl) << 8) | syscall.IPPROTO_TCP
	ipv4Cks += uint32(binary.BigEndian.Uint16(srcIp.To4()[0:2]))
	ipv4Cks += uint32(binary.BigEndian.Uint16(srcIp.To4()[2:4]))

	blockSet := make(map[string]bool)
	blockF, err := os.Open(blockFile)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(blockF)
	for scanner.Scan() {
		blockSet[strings.TrimSpace(scanner.Text())] = true
	}
	blockF.Close()

	p := &TCPoolv4Fast{
		inChan: 		make(chan []byte, bufSize),
		outTcpTgtChan: 	make(chan string, bufSize),
		outTcpRealChan:	make(chan string, bufSize),
		outTcpPortChan: make(chan uint16, bufSize),
		outIcmpTgtChan: make(chan string, bufSize),
		outIcmpRealChan: make(chan string, bufSize),
		outIcmpResChan: make(chan string, bufSize),
		outIcmpPortChan: make(chan uint16, bufSize),
		srcIpStr: 		srcIpStr,
		localPort: 		localPort,
		remotePort: 	remotePort,
		ipv4Cks: 		ipv4Cks,
		iface: 			iface,
		srcMac: 		srcMac,
		dstMac: 		dstMac,
		ttl:            ttl,
		finish:         false,
		blockSet:       blockSet,
	}
	go p.send()
	go p.recvTcp()
	go p.recvIcmp()
	return p
}

func (p *TCPoolv4Fast) LenInChan() int { return len(p.inChan) }
func (p *TCPoolv4Fast) Add(dstIp []byte) { p.inChan <- dstIp }

func (p *TCPoolv4Fast) GetTcp() (string, string, uint16) { 
	select {
	case target := <- p.outTcpTgtChan:
		return target, <- p.outTcpRealChan, <- p.outTcpPortChan
	case <-time.After(time.Second):
		return "", "", 0
	}
}
func (p *TCPoolv4Fast) GetIcmp() (string, string, string, uint16) { 
	select {
	case target := <- p.outIcmpTgtChan:
		return target, <- p.outIcmpRealChan, <- p.outIcmpResChan, <- p.outIcmpPortChan
	case <- time.After(time.Second):
		return "", "", "", 0
	}
}

func (p *TCPoolv4Fast) calCks(dstIp []byte) uint16 {
	ipv4Cks := p.ipv4Cks
	fstShort := uint32(binary.BigEndian.Uint16(dstIp[0:2]))
	secShort := uint32(binary.BigEndian.Uint16(dstIp[2:4]))
	ipv4Cks += fstShort
	ipv4Cks += secShort
	return ^uint16((ipv4Cks >> 16) + (ipv4Cks & 0xffff))
}

func (p *TCPoolv4Fast) send() {
	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_IP)
	if err != nil {
		log.Fatalf("Socket error: %v\n", err)
	}
	defer syscall.Close(fd)

	// construct MAC header
	macHdr := make([]byte, MAC_HDR_SIZE)
	copy(macHdr[ 0: 6], p.dstMac)
	copy(macHdr[ 6:12], p.srcMac)
	binary.BigEndian.PutUint16(macHdr[12:14], syscall.ETH_P_IP)

	// Get Interface Info
	iface, err := net.InterfaceByName(p.iface)
	if err != nil {
		log.Fatalf("Interface error: %v\n", err)
	}
	bindAddr := &syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IP,
		Ifindex:  iface.Index,
	}

	// IP Header
	srcIp := net.ParseIP(p.srcIpStr)
	ipv4Hdr := make([]byte, IPV4_HDR_SIZE)
	ipv4Hdr[0] = 0x45  // Vesrion = 4 | header length = 5
	// [1]	 TOS
	// [2] [3] Total length
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], IPV4_HDR_SIZE + TCP_HDR_SIZE)
	// [4] [5] Identification
	// [6] [7] Flags | Fragment offset
	ipv4Hdr[8] = p.ttl  // TTL
	ipv4Hdr[9] = syscall.IPPROTO_TCP  // Protocol = 6 (TCP)
	// [10 - 11] Header Checksum
 	copy(ipv4Hdr[12:16], srcIp.To4())  // Source address
	// [16 - 20] Destination address

	// TCP Header
	tcpHdr := make([]byte, TCP_HDR_SIZE)
	binary.BigEndian.PutUint16(tcpHdr[0:2], p.localPort)  // local port
	binary.BigEndian.PutUint16(tcpHdr[2:4], p.remotePort)  // remote port
	// [4 -  8] Seq Num
	// [8 - 12] Ack Num
	tcpHdr[12] = DATA_OFFSET << 4  // [12] DataOffset (4 bits) | RSV (3 bits)
	tcpHdr[13] = SYN_FLAG  // [13] SYN flag
	binary.BigEndian.PutUint16(tcpHdr[14:16], WINDOW_SIZE)  // [14 - 16] Window Size
	// [16 - 18] Checksum
	// [18 - 20] Urgent Point
	// [20 - 24] option: MSS = 1460
	copy(tcpHdr[20:24], TCP_MSS)

	pkt := append(macHdr, ipv4Hdr...)
	pkt  = append(pkt, tcpHdr...)

	for {
		dstIp := <- p.inChan
		if dstIp == nil { break }
		ipv4Cks := p.calCks(dstIp)

		// Complete IP Header
		// copy(ipv4Hdr[16:20], dstIp)
		copy(pkt[30:34], dstIp)
		// binary.BigEndian.PutUint16(ipv4Hdr[10:12], p.calIpv4Cks(dstIp))
		binary.BigEndian.PutUint16(pkt[24:26], ipv4Cks)

		// Complete TCP Header
		// copy(tcpHdr[4:8], dstIp)
		copy(pkt[38:42], dstIp)
		// binary.BigEndian.PutUint16(tcpHdr[16:18], p.calTcpCks(dstIp))

		// Send the Packet
		// pkt := append(macHdr, ipv4Hdr...)
		// pkt  = append(pkt, tcpHdr...)
		for { if err := syscall.Sendto(fd, pkt, 0, bindAddr); err == nil { break } else { log.Println(err) } }
	}
}

func (p *TCPoolv4Fast) recvTcp() {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil { log.Fatal(err) }
	defer syscall.Close(fd)

	buf := make([]byte, 54)
	for {
		_, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil { continue }
		if p.finish { break }

		localPort := binary.BigEndian.Uint16(buf[36:38])
		remotePort := binary.BigEndian.Uint16(buf[34:36])
		flag := buf[47]
		// remotePort := binary.BigEndian.Uint16(buf[20:22])
		if localPort != p.localPort && flag != (SYN_FLAG | ACK_FLAG) { continue }
		realIpStr := net.IP(buf[26:30]).String()
		ackNum := binary.BigEndian.Uint32(buf[42:46])
		orgIpBin := make([]byte, 4)
		binary.BigEndian.PutUint32(orgIpBin[0:4], ackNum - 1)
		orgIpStr := net.IP(orgIpBin).String()
		p.outTcpTgtChan <- orgIpStr
		p.outTcpRealChan <- realIpStr
		p.outTcpPortChan <- remotePort
	}
}

func (p *TCPoolv4Fast) recvIcmp() {
	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil { panic(err) }
	defer syscall.Close(fd)

	// 绑定本地地址
	addr := syscall.SockaddrInet4{ Port: 0, Addr: [4]byte{0, 0, 0, 0}, }
	err = syscall.Bind(fd, &addr)
	if err != nil { panic(err) }

	// 接收ICMP报文
	for {
		buf := make([]byte, 1500)
		_, addr, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil { panic(err) }
		if p.finish { break }

		resIp := net.IP(addr.(*syscall.SockaddrInet4).Addr[:]).String()
		if _, ok := p.blockSet[resIp]; ok { continue }

		if buf[31] != IPV4_HDR_SIZE + TCP_HDR_SIZE || buf[37] != syscall.IPPROTO_TCP || buf[20] != 11 || buf[21] != 0 { continue }
		// if (buf[48] == buf[46] && buf[49] == buf[47]) && (buf[32] != buf[44] || buf[33] != buf[45]) { continue }
		remotePort := binary.BigEndian.Uint16(buf[50:52])
		p.outIcmpTgtChan <- net.IP(buf[52:56]).String()
		p.outIcmpRealChan <- net.IP(buf[44:48]).String()
		p.outIcmpResChan <- net.IP(addr.(*syscall.SockaddrInet4).Addr[:]).String()
		p.outIcmpPortChan <- remotePort
	}
}

func (p *TCPoolv4Fast) Finish() {
	p.Add(nil)
	p.finish = true
}