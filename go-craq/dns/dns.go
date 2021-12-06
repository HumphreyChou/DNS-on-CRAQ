// define DNS query and storage format
package dns

import (
	"fmt"
	"log"
	"net"

	"github.com/despreston/go-craq/node"
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

type RR struct {
	name     string
	type_    uint16
	class    uint16
	ttl      uint32
	rdLength uint16
	rdata    string
}

func (rr *RR) ToBytes() []byte {
	return nil
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

type Answer []RR

type Message struct {
	header   Header
	question Question
	answer   Answer
}

func (msg *Message) ToBytes() []byte {
	return nil
}

func parseQuery(query []byte) (*Message, error) {
	return nil, nil
}

func ServeDNS(n *node.Node, port int) error {
	listen, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})
	if err != nil {
		log.Fatal("Failed to listen on port ", port)
	}
	defer listen.Close()
	for {
		var query [1024]byte
		n, addr, err := listen.ReadFromUDP(query[:])
		if err != nil {
			log.Println("Read client query failed, err: ", err)
			continue
		}

		// parse DNS query and reply
		msg, err := parseQuery(query[:])
		if err != nil {
			log.Println("Failed to parse client query")
			continue
		}
		msg.header.id = 1 // nonsense

		_, err = listen.WriteToUDP(query[:n], addr)
		if err != nil {
			fmt.Println("Write to udp failed, err: ", err)
			continue
		}
	}
	return nil
}
