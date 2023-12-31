package main

import (
	"net"
	"log"
	"syscall"
	"encoding/binary"
)

const (
	IPV4_HDR_SIZE = 20
	TCP_HDR_SIZE = 20
	LOCAL_PORT = 37301
	TTL = 64
	WINDOW_SIZE = 65535
)

func CalChecksum(data []byte) uint16 {
    var (
        sum    uint32
        length = len(data)
        index  int
    )

    //以每16比特（2字节）为单位进行求和
    for length > 1 {
        sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
        index += 2
        length -= 2
    }

    //如果长度为奇数，将最后剩下的8比特（1字节）看作16比特的高8位进行求和
    if length > 0 {
        sum += uint32(data[index]) << 8
    }

    //至此，sum可能超过了16比特可以表示的最大范围，因此需要将高16位与低16位相加
    sum += (sum >> 16)

    //返回求和的补码，这就是UDP校验和
    return uint16(^sum)
}

type TCPoolv4 struct {
	inChan      chan string
	outOrgChan  chan string
	outRealChan chan string
	srcIpStr    string
	remotePort  uint16
	ipv4Cks     uint32
	tcpCks      uint32
}

func NewTCPoolv4(remotePort uint16, bufSize int, srcIpStr string) *TCPoolv4 {
	tcpCks := uint32(0)
	srcIp := net.ParseIP(srcIpStr)
    tcpCks += uint32(binary.BigEndian.Uint16(srcIp.To4()[0:2]))
	tcpCks += uint32(binary.BigEndian.Uint16(srcIp.To4()[2:4]))
    tcpCks += syscall.IPPROTO_TCP  // upper layer protocol: TCP
    tcpCks += 20  // TCP length = 20 bytes
    tcpCks += LOCAL_PORT
    tcpCks += uint32(remotePort)
    tcpCks += (5 << 12) + 2  // DataOffset | RSV | SYN flag
    tcpCks += WINDOW_SIZE  // Window size

	ipv4Cks := uint32(0)
	ipv4Cks += 0x45 << 8
	ipv4Cks += IPV4_HDR_SIZE + TCP_HDR_SIZE
	ipv4Cks += (TTL << 8) | syscall.IPPROTO_TCP
	ipv4Cks += uint32(binary.BigEndian.Uint16(srcIp.To4()[0:2]))
	ipv4Cks += uint32(binary.BigEndian.Uint16(srcIp.To4()[2:4]))

	p := &TCPoolv4{
		inChan: make(chan string, bufSize),
		outOrgChan: make(chan string, bufSize),
		outRealChan: make(chan string, bufSize),
		srcIpStr: srcIpStr,
		remotePort: remotePort,
		tcpCks: tcpCks,
		ipv4Cks: ipv4Cks,
	}
	go p.send()
	go p.recv()
	return p
}

func (p *TCPoolv4) Add(dstIpStr string) {
	p.inChan <- dstIpStr
}

func (p *TCPoolv4) Get() (string, string) {
	return <- p.outOrgChan, <- p.outRealChan
}

func (p *TCPoolv4) calTcpCks(dstIp []byte) uint16 {
	sum := p.tcpCks
	sum += uint32(binary.BigEndian.Uint16(dstIp[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIp[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIp[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIp[2:4]))
	return ^uint16((sum >> 16) + (sum & 0xffff))
}

func (p *TCPoolv4) calIpv4Cks(dstIp []byte) uint16 {
	sum := p.ipv4Cks
	sum += uint32(binary.BigEndian.Uint16(dstIp[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIp[2:4]))
	return ^uint16((sum >> 16) + (sum & 0xffff))
}

func (p *TCPoolv4) send() {
	// 创建原始套接字
    fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_IP)
    if err != nil {
        log.Fatalf("Socket error: %v\n", err)
    }
    defer syscall.Close(fd)

	// construct MAC header
	macHdr := make([]byte, 14)
	dstMac := []byte{0xfe, 0x00, 0x00, 0x00, 0x01, 0x01}
	srcMac := []byte{0x92, 0x6b, 0x02, 0x19, 0x2c, 0x11}
	copy(macHdr[ 0: 6], dstMac)
	copy(macHdr[ 6:12], srcMac)
	binary.BigEndian.PutUint16(macHdr[12:14], syscall.ETH_P_IP)

	// 获取网络接口
    iface, err := net.InterfaceByName("eth0") // 替换为您的接口名
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
	// [1]     TOS
	// [2] [3] Total length
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], IPV4_HDR_SIZE + TCP_HDR_SIZE)
	// [4] [5] Identification
	// [6] [7] Flags | Fragment offset
	ipv4Hdr[8] = TTL  // TTL
	ipv4Hdr[9] = syscall.IPPROTO_TCP  // Protocol = 6 (TCP)
	// [10 - 11] Header Checksum
 	copy(ipv4Hdr[12:16], srcIp.To4())  // Source address
	// [16 - 20] Destination address

	// TCP Header
	tcpHdr := make([]byte, TCP_HDR_SIZE)
	binary.BigEndian.PutUint16(tcpHdr[0:2], LOCAL_PORT)  // local port
	binary.BigEndian.PutUint16(tcpHdr[2:4], p.remotePort)  // remote port
	// [4 -  8] Seq Num
	// [8 - 12] Ack Num
	tcpHdr[12] = 5 << 4  // [12] DataOffset (4 bits) | RSV (3 bits)
	tcpHdr[13] = 0x02  // [13] SYN flag
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)  // [14 - 16] Window Size
	// [16 - 18] Checksum
	// [18 - 20] Urgent Point

	for {
		dstIpStr := <- p.inChan
		dstIp := net.ParseIP(dstIpStr)

		// Complete IP Header
		copy(ipv4Hdr[16:20], dstIp.To4())
		binary.BigEndian.PutUint16(ipv4Hdr[10:12], p.calIpv4Cks(dstIp.To4()))

		// Complete TCP Header
		copy(tcpHdr[4:8], dstIp.To4())
		binary.BigEndian.PutUint16(tcpHdr[16:18], p.calTcpCks(dstIp.To4()))

		// Send the Packet
		pkt := append(macHdr, ipv4Hdr...)
		pkt  = append(pkt, tcpHdr...)
		for { if err := syscall.Sendto(fd, pkt, 0, bindAddr); err == nil { break } }
	}
}

func (p *TCPoolv4) recv() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
    if err != nil {
        panic(err)
    }
    defer syscall.Close(fd)

	laddr := &syscall.SockaddrInet4{
		Port: int(LOCAL_PORT),
	}
	copy(laddr.Addr[:], net.ParseIP(p.srcIpStr))
	err = syscall.Bind(fd, laddr)
	if err != nil {
		log.Fatalln(err)
	}

	for {
		buf := make([]byte, 40)
		_, addr, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil { continue }

		realIpStr := net.IP(addr.(*syscall.SockaddrInet4).Addr[:]).String()
		localPort := binary.BigEndian.Uint16(buf[22:24])
		// remotePort := binary.BigEndian.Uint16(buf[20:22])
		if localPort != LOCAL_PORT { continue }
		ackNum := binary.BigEndian.Uint32(buf[28:32])
		orgIpBin := make([]byte, 4)
		binary.BigEndian.PutUint32(orgIpBin[0:4], ackNum - 1)
		orgIpStr := net.IPv4(orgIpBin[0], orgIpBin[1], orgIpBin[2], orgIpBin[3]).String()
		p.outOrgChan <- orgIpStr
		p.outRealChan <- realIpStr
	}
}
