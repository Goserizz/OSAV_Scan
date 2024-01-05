package utils

import (
	"encoding/binary"
)

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