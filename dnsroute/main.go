package main

import (
	"log"
	"net"
	"flag"
)

var (
	iface = flag.String("i", "", "The interface used for DNSRoute.")
	localPort = flag.Uint("p", 16657, "The port used for sending DNS request.")
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
	srcIpArr, _, err := GetIface(*iface)
	if err != nil { panic(err) }
	srcIpStr := srcIpArr[0]
	dstIpStr := args[0]

	log.Printf("Using interface %s: %s#%d to DNSRoute %s#%d with TTL from %d to %d", *iface, srcIpStr, *localPort, dstIpStr, 53, *startTTL, *endTTL)
	DNSRouteTestUser(srcIpStr, uint16(*localPort), dstIpStr, *startTTL, *endTTL)
}