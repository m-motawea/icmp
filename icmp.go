package icmp

import (
	"encoding/binary"
	"errors"
)

type Type uint8
type Code uint8
type Checksum uint16

type ICMP struct {
	Type         Type
	Code         Code
	Checksum     Checksum
	RestOfHeader []byte
	Data         []byte
}

func (i *ICMP) MarshalBinary() ([]byte, error) {
	len := 8 + len(i.Data)
	b := make([]byte, len)

	temp := (uint16(i.Type) << 8) | uint16(i.Code)
	binary.BigEndian.PutUint16(b[0:2], temp)
	// Add empty Checksum
	binary.BigEndian.PutUint16(b[2:4], uint16(0))
	// Add Rest of Header
	copy(b[4:8], i.RestOfHeader)
	// get checksum
	csum := checksum(b[:8])
	i.Checksum = Checksum(csum)
	binary.BigEndian.PutUint16(b[2:4], uint16(csum))
	copy(b[8:], i.Data)

	return b, nil
}

func (i *ICMP) UnmarshalBinary(b []byte) error {
	if len(b) < 8 {
		return errors.New("invalid header length")
	}
	temp1 := binary.BigEndian.Uint16(b[0:2])
	i.Type = Type(temp1 >> 8)
	i.Code = Code(temp1 & 0x00FF)
	i.Checksum = Checksum(binary.BigEndian.Uint16(b[2:4]))
	i.RestOfHeader = make([]byte, 4)
	copy(i.RestOfHeader, b[4:8])
	if len(b) > 8 {
		i.Data = make([]byte, len(b)-8)
		copy(i.Data, b[8:])
	}
	return nil
}

func checksum(buf []byte) uint16 {
	sum := uint32(0)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	/*
	 * From RFC 768:
	 * If the computed checksum is zero, it is transmitted as all ones (the
	 * equivalent in one's complement arithmetic). An all zero transmitted
	 * checksum value means that the transmitter generated no checksum (for
	 * debugging or for higher level protocols that don't care).
	 */
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}
