package main

import (
	"log"
	"flag"
	"net"
	"strings"
)

var (
	iface = flag.String("i", "", "The interface used for TCPRoute.")
	localPort = flag.Uint("l", 16657, "The local port used for sending TCP SYN.")
	remotePort = flag.Uint("r", 80, "The remote port used for sending TCP SYN.")
	dstMacStr = flag.String("dmac", "", "The mac address of router.")
	startTTL = flag.Int("s", 1, "Start TTL.")
	endTTL = flag.Int("e", 40, "End TTL.")
)

func main() {
	var err error
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		panic("Wrong Format: Please Specify One Address for DNSRoute!")
	} else if net.ParseIP(args[0]) == nil { panic("Invalid IP!") }
	
	if *iface == "" {
		*iface, err = GetDefaultRouteInterface()
		if err != nil { panic("Please Specify the Interface for DNSRoute.") }
	}
	srcIpv4Arr, srcIpv6Arr, srcMac, err := GetIface(*iface)
	if err != nil { panic(err) }
	dstIpStr := args[0]
	dstMac, err := net.ParseMAC(*dstMacStr)
	if err != nil { panic(err) }

	if strings.Contains(dstIpStr, ".") {
		log.Printf("Using interface %s: %s#%d to TCPRoute %s#%d with TTL from %d to %d", *iface, srcIpv4Arr[0], *localPort, dstIpStr, *remotePort, *startTTL, *endTTL)
		TCPRoute(srcIpv4Arr[0], uint16(*localPort), dstIpStr, uint16(*remotePort), *startTTL, *endTTL, srcMac, dstMac, *iface)
	} else {
		log.Printf("Using interface %s: %s#%d to DNSRoute %s#%d with TTL from %d to %d", *iface, srcIpv6Arr[0], *localPort, dstIpStr, 53, *startTTL, *endTTL)
		// DNSRouteTestUserv6(srcIpv6Arr[0], uint16(*localPort), FormatIpv6(dstIpStr), *startTTL, *endTTL)
	}
}