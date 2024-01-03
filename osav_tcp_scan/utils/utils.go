package utils

import (
	"net"
	"strings"
)

const (
	Addr6StrLen = 39
)

func ToHex(x uint8) string {
	if x > 15 {
		panic("Hex can only be between 0-15.")
	}
	switch x {
	case 0:
		return "0"
	case 1:
		return "1"
	case 2:
		return "2"
	case 3:
		return "3"
	case 4:
		return "4"
	case 5:
		return "5"
	case 6:
		return "6"
	case 7:
		return "7"
	case 8:
		return "8"
	case 9:
		return "9"
	case 10:
		return "a"
	case 11:
		return "b"
	case 12:
		return "c"
	case 13:
		return "d"
	case 14:
		return "e"
	case 15:
		return "f"
	}
	return ""
}

func SplitIPStr(ipStr string) []string{
	if ipStr[len(ipStr) - 1] == ':' {
		ipStr = ipStr[:len(ipStr) - 1]
	}
	ipSeg := strings.Split(ipStr, ":")
	var ipFullSeg []string
	for i := 0; i < len(ipSeg); i++ {
		seg := ipSeg[i]
		if seg == "" {
			nIgnore := 9 - len(ipSeg)
			for j := 0; j < nIgnore; j++ {
				ipFullSeg = append(ipFullSeg, "0000")
			}
			continue
		}
		nZero := 4 - len(seg)
		for i := 0; i < nZero; i++ {
			seg = "0" + seg
		}
		ipFullSeg = append(ipFullSeg, seg)
	}
	return ipFullSeg
}

func GetFullIP(ipStr string) string {
	ipFullSeg := SplitIPStr(ipStr)
	return strings.Join(ipFullSeg, ":")
}

func IsBogon(dec_ip uint64) bool {
  if  ((dec_ip & 0xFF000000) == 0x00000000) || // 0.0.0.0/8
      ((dec_ip & 0xFF000000) == 0x0A000000) || // 10.0.0.0/8
      ((dec_ip & 0xFFC00000) == 0x64400000) || // 100.64.0.0/10
      ((dec_ip & 0xFF000000) == 0x7F000000) || // 127.0.0.0/8
      ((dec_ip & 0xFFFF0000) == 0xA9FE0000) || // 169.254.0.0/16
      ((dec_ip & 0xFFF00000) == 0xAC100000) || // 172.16.0.0/12
      ((dec_ip & 0xFFFFFF00) == 0xC0000000) || // 192.0.0.0/24
      ((dec_ip & 0xFFFFFF00) == 0xC0000200) || // 192.0.2.0/24
      ((dec_ip & 0xFFFF0000) == 0xC0A80000) || // 192.168.0.0/16
      ((dec_ip & 0xFFFE0000) == 0xC6120000) || // 198.18.0.0/15
      ((dec_ip & 0xFFFFFF00) == 0xC6336400) || // 198.51.100.0/24
      ((dec_ip & 0xFFFFFF00) == 0xCB007100) || // 203.0.113.0/24
      ((dec_ip & 0xF0000000) == 0xE0000000) || // 224.0.0.0/4
      ((dec_ip & 0xF0000000) == 0xF0000000) { return true } else {return false}   // 240.0.0.0/4
}

func GetIface(interfaceName string) ([]string, []byte, error) {

    iface, err := net.InterfaceByName(interfaceName)
    if err != nil { return nil, nil, err }

	var ipv4Addrs []string

    addrs, err := iface.Addrs()
    if err != nil { return nil, nil, err }

    for _, addr := range addrs {
        ipnet, ok := addr.(*net.IPNet)
        if !ok { continue }
        if ipv4 := ipnet.IP.To4(); ipv4 != nil { ipv4Addrs = append(ipv4Addrs, ipv4.String()) }
    }

    return ipv4Addrs, iface.HardwareAddr, nil
}
