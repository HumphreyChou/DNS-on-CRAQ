// define DNS query and storage format
// also define some utils for serialization and deserialization
package dns

import (
	"bytes"
	"encoding/gob"
	"log"
)

type TYPE uint16
type CLASS uint16

const (
	// subset of DNS types
	TYPE_PADDING TYPE = iota
	A
	NS
	MD
	MF
	CNAME
	SOA
	//... more to go
)

const (
	// DNS classes
	CLASS_PADDING CLASS = iota
	IN
	CS
	CH
	HS
)

const (
	// DNS query header options except RCODE
	QR uint8 = 1 << 7
	// OPCODE
	OPCODE uint8 = 0xf << 4
	QUERY  uint8 = 0x0 << 3
	IQUERY uint8 = 0x1 << 3
	STATUS uint8 = 0x2 << 3
	AA     uint8 = 1 << 2
	TC     uint8 = 1 << 1
	RD     uint8 = 1
	RA     uint8 = 1 << 7
)

const (
	// DNS query header RCODE
	NO_ERR uint8 = iota
	FMT_ERR
	SERVER_FAILURE
	NAME_ERR
	NOT_IMPL
	REFUSED
)

const TTL uint32 = 10

type RR struct {
	name      string
	type_     uint16
	class     uint16
	ttl       uint32
	rdLength  uint16
	rdata     string
	timestamp int64 // not a part of standard RR
}

func (rr *RR) ToBytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(*rr)
	if err != nil {
		log.Println("Failed to serialize RR, err: ", err)
		return nil
	}
	return buf.Bytes()
}

func makeRR(val []byte) *RR {
	rr := RR{}
	var buf bytes.Buffer
	buf.Write(val)
	dec := gob.NewDecoder(&buf)
	err := dec.Decode(&rr)
	if err != nil {
		log.Println("Failed to deserialize RR, err: ", err)
		return nil
	}
	return &rr
}

type Header struct {
	id      int16
	opt1    uint8 // QR Opcde AA TC RD
	opt2    uint8 // RA Z RCODE
	qdCount uint16
	anCount uint16
	nsCount uint16
	arCount uint16
}

type Question struct {
	qName  string
	qType  uint16
	qClass uint16
}

type Message struct {
	header   Header
	question []Question
	answer   []RR
}

func (msg *Message) ToBytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(*msg)
	if err != nil {
		log.Println("Failed to serialize message, err: ", err)
		return nil
	}
	return buf.Bytes()
}

func parseQuery(query []byte) *Message {
	msg := Message{}
	var buf bytes.Buffer
	buf.Write(query)
	dec := gob.NewDecoder(&buf)
	err := dec.Decode(&msg)
	if err != nil {
		log.Println("Failed to deserialize message, err: ", err)
		return nil
	}
	// sanity check
	log.Printf("[Query] id: %d, qdCount: %d", msg.header.id, msg.header.qdCount)
	return &msg
}

func makeResponse(id int16, rrs []*RR) (*Message, error) {
	header := Header{
		id: id, opt1: 0 | QR, opt2: 0,
		qdCount: 0, anCount: uint16(len(rrs)),
		nsCount: 0, arCount: 0,
	}
	question := make([]Question, 0)
	answer := make([]RR, len(rrs))
	for _, rr := range rrs {
		answer = append(answer, *rr)
	}
	return &Message{
		header, question, answer,
	}, nil
}
