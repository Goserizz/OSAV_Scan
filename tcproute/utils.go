package main

import (
	"fmt"
	"net"
	"bytes"
	"errors"
	"strings"
	"os/exec"
	"math/rand"
	"encoding/binary"

	"github.com/vishvananda/netlink"
)

const (
	RAND_LEN = 5
	QryDomain = "v4.ruiruitest.online"
	CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
)

func RandFillDomain(ipStr string) string {
	if RAND_LEN == 0 {
		return ipStr + "." + QryDomain
	} else {
		randSuffixBytes := make([]byte, RAND_LEN)
		for i := range randSuffixBytes {
			randSuffixBytes[i] = CHARS[rand.Intn(len(CHARS))]
		}
		return ipStr + "." + string(randSuffixBytes) + "." + QryDomain
	}
}

func FormatIpv4(ipv4 string) string {
	var formatParts []string
	for _, part := range strings.Split(ipv4, ".") {
		for len(part) < 3 {
			part = "0" + part
		}
		formatParts = append(formatParts, part)
	}
	return strings.Join(formatParts, ".")
}

func SplitIPv6Str(ipStr string) []string{
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

func FormatIpv6(ipStr string) string {
	return strings.Join(SplitIPv6Str(ipStr), ":")
}

func DeformatIpv4(ipv4 string) string {
	var deformatParts []string
	for _, part := range strings.Split(ipv4, ".") {
		for part[0] == '0' && len(part) > 1 {
			part = part[1:]
		}
		deformatParts = append(deformatParts, part)
	}
	return strings.Join(deformatParts, ".")
}

type DNSQuestion struct {
	Name   string
	Type   uint16
	Class  uint16
}

func ParseDNSQuestion(buffer []byte, offset int) (DNSQuestion, int) {
	// 读取question的name字段
	name, bytesRead := readName(buffer, offset)
	offset += bytesRead

	// 读取question的type和class字段
	questionType := binary.BigEndian.Uint16(buffer[offset : offset+2])
	questionClass := binary.BigEndian.Uint16(buffer[offset+2 : offset+4])
	offset += 4

	// 创建DNSQuestion对象
	question := DNSQuestion{
		Name:   name,
		Type:   questionType,
		Class:  questionClass,
	}

	return question, offset
}

func readName(buffer []byte, offset int) (string, int) {
	var name string
	var bytesRead int

	// DNS报文中的name字段以长度+字符串的形式表示
	// 0xC0表示name字段中的某一部分是一个偏移量，需要跳转到该位置读取
	// 具体参考DNS报文的编码规范

	// 循环读取name字段的各个部分
	for {
		// 读取长度
		length := int(buffer[offset])
		offset++
		bytesRead++

		if length == 0 {
			// 结束条件是遇到长度为0的部分表示name字段结束
			break
		}

		if length >= 0xC0 {
			// 遇到偏移量，需要跳转到偏移量指向的位置继续读取
			nextOffset := int(binary.BigEndian.Uint16([]byte{buffer[offset-1], buffer[offset]})) & 0x3FFF
			part, _ := readName(buffer, nextOffset)
			name += part
			bytesRead++
			break
		}

		// 读取字符串部分
		name += string(buffer[offset : offset+length])
		offset += length
		bytesRead += length
		name += "."

	}

	return name, bytesRead
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

// 获取默认网关的IP地址
func GetDefaultGateway() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	route := strings.Fields(out.String())
	if len(route) < 3 {
		return "", fmt.Errorf("unexpected output: %s", out.String())
	}
	return route[2], nil
}

// 获取MAC地址
func GetMACAddress(ip string) (string, error) {
	cmd := exec.Command("arp", "-n", ip)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	lines := strings.Split(out.String(), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("unexpected output: %s", out.String())
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 3 {
		return "", fmt.Errorf("unexpected output: %s", lines[1])
	}
	return fields[2], nil
}