package main

import (
	"net"
	"flag"
)

var (
	iface = flag.String("iface", "", "The interface used for DNSRoute.")
	startTTL = flag.Int("s", 5, "Start TTL.")
	endTTL = flag.Int("e", 40, "End TTL.")
	inputFile = flag.String("i", "", "Input file for scanning.")
	outputFile = flag.String("o", "", "Output file.")
	natFile = flag.String("nat", "", "Output file for SNAT.")
	dnsFile = flag.String("d", "", "Output file for DNS response without transparent forwarding.")
	pps = flag.Int("pps", 200000, "Sending rate PPS.")
	dstMacStr = flag.String("dmac", "", "The mac address of router.")
	nTot = flag.Uint64("n", 3702258688, "The number of ip addresses will be sent.")
	nSend = flag.Int("nsend", 1, "The number of senders.")
	nSeg = flag.Uint64("nseg", 0, "The number of addresses scannned in batch.")
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
	
	if *inputFile != "" {
		DNSRouteScan(srcIpStr, *iface, *inputFile, *outputFile, *natFile, *dnsFile, uint8(*startTTL), uint8(*endTTL), *nSend, *pps, srcMac, dstMac)
	} else if *nSeg == 0 {
		DNSRouteScanWhole(srcMac, dstMac, srcIpStr, *iface, *outputFile, uint8(*startTTL), uint8(*endTTL), *pps, *nSend, *nTot)
	} else {
		DNSRouteScanWithForwarder(srcMac, dstMac, srcIpStr, *iface, *outputFile, uint8(*startTTL), uint8(*endTTL), *pps, *nSend, *nSeg, *nTot)
	}
	
}