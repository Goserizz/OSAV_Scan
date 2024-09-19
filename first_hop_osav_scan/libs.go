package main

const (
	BASE_PORT       uint16 = 50000
	MAC_HDR_SIZE           = 14
	IPV4_HDR_SIZE          = 20
	UDP_HDR_SIZE           = 8
	DNS_HDR_SIZE           = 12
	TRANSACTION_ID  uint16 = 6666
	BASE_DOMAIN            = "osav.ruiruitest.online"
	CHARS                  = "0123456789"
	RAND_LEN               = 9
	TTL_LEN                = 2
	RANGE_LEN              = 2
	IPV4_ENCODE_LEN        = 8
	IS_NORMAL_LEN          = 1
	BUF_SIZE               = 1024
	LOG_INTV               = 10000

	CACHE_LEN = 5
)

var (
	IPV4_LEN = IPV4_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE + 1 + RAND_LEN + 1 + TTL_LEN + 1 + IPV4_ENCODE_LEN + 1 + IS_NORMAL_LEN + 1 + len(BASE_DOMAIN) + 5

	IPV4_CACHE_LEN = IPV4_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE + RAND_LEN + 1 + IPV4_ENCODE_LEN + 1 + CACHE_LEN + 1 + len(BASE_DOMAIN) + 5
)
