package main

import (
	"flag"
)

var (
	iface = flag.String("iface", "", "The interface used for DNSRoute.")
	localPort = flag.Uint("p", 16658, "The port used for sending DNS request.")
	startTTL = flag.Int("s", 1, "Start TTL.")
	endTTL = flag.Int("e", 40, "End TTL.")
	inputFile = flag.String("i", "", "Input file for scanning.")
	outputFile = flag.String("o", "", "Output file.")
	natFile = flag.String("n", "", "Output file for SNAT.")
	dnsFile = flag.String("d", "", "Output file for DNS response without transparent forwarding.")
	pps = flag.Int("pps", 20000, "Sending rate PPS.")
)

func main() {
	var err error
	flag.Parse()
	if *iface == "" {
		*iface, err = GetDefaultRouteInterface()
		if err != nil { panic("Please Specify the Interface for DNSRoute.") }
	}
	srcIpv4Arr, _, _, err := GetIface(*iface)
	if err != nil { panic(err) }
	DNSRouteScan(srcIpv4Arr[0], *inputFile, *outputFile, *natFile, *dnsFile, uint8(*startTTL), uint8(*endTTL), uint16(*localPort), *pps)
}