// define DNS query and storage format
package dns

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
