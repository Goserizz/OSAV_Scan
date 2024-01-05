package utils

import (
	"net"
	"errors"
	"strings"

	"github.com/vishvananda/netlink"
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

func Pfx2Range(pfxStr string) (string, string) {
	_, pfx, _ := net.ParseCIDR(pfxStr)
	startIP := make([]byte, 16)
	endIP := make([]byte, 16)
	for i := range pfx.IP {
		startIP[i] = pfx.IP[i] & pfx.Mask[i]
		endIP[i]   = pfx.IP[i] | (^pfx.Mask[i])
	}
	startBits := NewBitsArray(32, startIP)
	endBits := NewBitsArray(32, endIP)
	return startBits.ToIPv6(), endBits.ToIPv6()
}

func GetDefaultRouteInterface() (string, error) {
    // 获取路由表
    routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
    if err != nil {
        return "", err
    }

    for _, route := range routes {
        // 检查是否为默认路由 (0.0.0.0/0 或 ::/0)
        if route.Dst == nil {
            // 获取与默认路由关联的网卡
            link, err := netlink.LinkByIndex(route.LinkIndex)
            if err != nil {
                return "", err
            }
            return link.Attrs().Name, nil
        }
    }

    return "", errors.New("default route not found")
}

func GetIface(interfaceName string) ([]string, []string, []byte, error) {
    iface, err := net.InterfaceByName(interfaceName)
    if err != nil { return nil, nil, nil, err }

	var ipv4Addrs []string
	var ipv6Addrs []string

    addrs, err := iface.Addrs()
    if err != nil { return nil, nil, nil, err }

    for _, addr := range addrs {
        ipnet, ok := addr.(*net.IPNet)
        if !ok { continue }
        if ipv4 := ipnet.IP.To4(); ipv4 != nil { 
			ipv4Addrs = append(ipv4Addrs, ipv4.String()) 
		} else if ipv6 := ipnet.IP.To16(); ipv6 != nil { 
			ipv6Addrs = append(ipv6Addrs, ipv6.String()) 
		}
    }

    return ipv4Addrs, ipv6Addrs, iface.HardwareAddr, nil
}