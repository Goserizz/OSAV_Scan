package main

const (
	MacHdrSize               = 14
	Ipv4HdrSize              = 20
	UdpHdrSize               = 8
	DnsHdrSize               = 12
	QryDomain                = "v4.ruiruitest.online"
	TransactionId     uint16 = 6666
	CHARS                    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	FormatTtlLen             = 2
	BasePort          uint16 = 50000
	DnsQrySizeSlow           = 50
	RandLenSlow              = 4 // must be even
	FormatIpv4LenSlow        = 15
	FormatIpv4Slow           = "000:000:000:000"
)

var (
	Ipv4TtlDomainLenSlow = RandLenSlow + FormatTtlLen + FormatIpv4LenSlow + len(QryDomain) + 4
	Ipv4LenSlow          = uint16(Ipv4HdrSize + UdpHdrSize + DnsHdrSize + DnsQrySizeSlow)
)
