package main

import (
	"net"
	"flag"
)

var (
	iface = flag.String("iface", "", "The interface used for DNSRoute.")
	startTtl = flag.Int("s", 5, "Start TTL.")
	endTtl = flag.Int("e", 50, "End TTL.")
	inputFile = flag.String("i", "", "Input file for scanning.")
	outputFile = flag.String("o", "", "Output file.")
	pps = flag.Int("pps", 10000, "Sending rate PPS.")
	dstMacStr = flag.String("dmac", "", "The mac address of router.")
	remotePort = flag.Uint("r", 80, "The remote port used for sending TCP SYN.")
	nTot = flag.Uint64("n", 3702258688, "The number of ip addresses will be sent.")
	nSeg = flag.Uint64("nseg", 10000000, "The number of addresses scannned in batch.")
	blockFile = flag.String("b", "blocklist.txt", "Do not receive packets from these IPs.")
	startFileNo = flag.Uint64("no", 0, "The No. of file start from.")
)

func main() {
	var err error
	flag.Parse()
	if *iface == "" {
		*iface, err = GetDefaultRouteInterface()
		if err != nil { panic("Please Specify the Interface for DNSRoute.") }
	}
	srcIpv4Arr, _, srcMac, err := GetIface(*iface)
	if err != nil { panic(err) }
	srcIpStr := srcIpv4Arr[0]
	dstMac, err := net.ParseMAC(*dstMacStr)
	if err != nil { panic(err) }
	
	if *inputFile == "" {
		TCPRouteScanWithForwarder(srcIpStr, *iface, *outputFile, *blockFile, uint8(*startTtl), uint8(*endTtl), *pps, *startFileNo, *nSeg, *nTot, srcMac, dstMac, uint16(*remotePort))
	} else {
		TCPRouteScan(srcIpStr, *iface, *inputFile, *outputFile, uint8(*startTtl), uint8(*endTtl), *pps, srcMac, dstMac, uint16(*remotePort))
	}
}