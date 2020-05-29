package icmp

import (
	"encoding/binary"
	"errors"
)

type Identifier uint16
type SequenceNumber uint16

const (
	TYPE_ICMP_ECHO_REPLY    Type = 0
	TYPE_ICMP_ECHO_REPQUEST Type = 8
)

type EchoRestOfHeader struct {
	Identifier     Identifier
	SequenceNumber SequenceNumber
}

func (e *EchoRestOfHeader) MarshalBinary() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], uint16(e.Identifier))
	binary.BigEndian.PutUint16(b[2:4], uint16(e.SequenceNumber))
	return b, nil
}

func (e *EchoRestOfHeader) UnmarshalBinary(b []byte) error {
	if len(b) != 4 {
		return errors.New("invalid rest of header for ICMP")
	}
	e.Identifier = Identifier(binary.BigEndian.Uint16(b[0:2]))
	e.SequenceNumber = SequenceNumber(binary.BigEndian.Uint16(b[2:4]))
	return nil
}
