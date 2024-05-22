package main

import (
	"flag"
	"net"
)

var (
	iface       = flag.String("iface", "", "The interface used for DNSRoute.")
	startTTL    = flag.Int("s", 5, "Start TTL.")
	endTTL      = flag.Int("e", 40, "End TTL.")
	inputFile   = flag.String("i", "", "Input file for scanning.")
	outputFile  = flag.String("o", "", "Output file.")
	pps         = flag.Int("pps", 10000, "Sending rate PPS.")
	dstMacStr   = flag.String("dmac", "", "The mac address of router.")
)

func main() {
	var err error
	flag.Parse()
	if *iface == "" {
		*iface, err = GetDefaultRouteInterface()
		if err != nil {
			panic("Please Specify the Interface for DNSRoute.")
		}
	}
	srcIpv4Arr, _, srcMac, err := GetIface(*iface)
	if err != nil {
		panic(err)
	}
	srcIpStr := srcIpv4Arr[0]
	dstMac, err := net.ParseMAC(*dstMacStr)
	if err != nil {
		panic(err)
	}

	FirstHopScan(srcIpStr, *iface, *inputFile, *outputFile, uint8(*startTTL), uint8(*endTTL), *pps, srcMac, dstMac)
}