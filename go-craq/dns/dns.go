// define DNS query and storage format
// also define some utils for serialization and deserialization
package dns

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
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
	Name      [16]byte
	Type      uint16
	Class     uint16
	Ttl       uint32
	RdLength  uint16
	RData     [4]byte
	Timestamp int64 // not a part of standard RR
}

const RR_SIZE uint = 38

func (rr *RR) ToBytes() []byte {
	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.BigEndian, *rr)
	if err != nil {
		log.Println("Failed to serialize RR, err: ", err)
		return nil
	}
	return buf.Bytes()
}

func makeRR(val []byte) *RR {
	rr := RR{}
	buf := bytes.NewBuffer(val)
	err := binary.Read(buf, binary.BigEndian, &rr)
	if err != nil {
		log.Println("Failed to deserialize RR, err: ", err)
		return nil
	}
	return &rr
}

type Header struct {
	Id      int16
	Opt1    uint8 // QR Opcde AA TC RD
	Opt2    uint8 // RA Z RCODE
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

const HDR_SIZE uint = 12

type Question struct {
	QName  [16]byte
	QType  uint16
	QClass uint16
}

const QUES_SIZE uint = 20

type Message struct {
	header   Header
	question []Question
	answer   []RR
}

type TabbleItem struct {
	cur uint
	ips [][4]byte
}

func (msg *Message) ToBytes() []byte {
	res := []byte{}
	// serialize header
	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.BigEndian, msg.header)
	if err != nil {
		log.Println("Failed to serialize header, err: ", err)
		return nil
	}
	res = append(res, buf.Bytes()...)
	// deserialize other fields
	for _, ques := range msg.question {
		buf = bytes.Buffer{}
		err = binary.Write(&buf, binary.BigEndian, ques)
		if err != nil {
			log.Println("Failed to serialize message, err: ", err)
			return nil
		}
		res = append(res, buf.Bytes()...)
	}

	for _, ans := range msg.answer {
		buf = bytes.Buffer{}
		err = binary.Write(&buf, binary.BigEndian, ans)
		if err != nil {
			log.Println("Failed to serialize message, err: ", err)
			return nil
		}
		res = append(res, buf.Bytes()[:RR_SIZE-8]...) // RRs in response should not contain timestamp
	}

	return res
}

func parseQuery(query []byte) *Message {
	log.Println("DHCP query: " + hex.EncodeToString(query))
	header := Header{}
	question := make([]Question, (len(query)-int(HDR_SIZE))/int(QUES_SIZE))
	answer := []RR{}
	// deserialize header
	buf := bytes.NewBuffer(query[:HDR_SIZE])
	err := binary.Read(buf, binary.BigEndian, &header)
	if err != nil {
		log.Println("Failed to deserialize header, err: ", err)
		return nil
	}
	// deserialize other fields, in this scenario, only questions
	buf = bytes.NewBuffer(query[HDR_SIZE:])
	err = binary.Read(buf, binary.BigEndian, &question)
	if err != nil {
		log.Println("Failed to deserialize questions, err: ", err)
		return nil
	}

	// sanity check
	log.Printf("[Query] id: %d, qdCount: %d, qName: %s", header.Id, header.QdCount, string(question[0].QName[:]))
	return &Message{header: header, question: question, answer: answer}
}

func makeResponse(id int16, question []Question, rrs []*RR) (*Message, error) {
	header := Header{
		Id: id, Opt1: 0 | QR, Opt2: 0,
		QdCount: uint16(len(question)), AnCount: uint16(len(rrs)),
		NsCount: 0, ArCount: 0,
	}
	answer := []RR{}
	for _, rr := range rrs {
		answer = append(answer, *rr)
	}
	return &Message{
		header: header, question: question, answer: answer,
	}, nil
}

func ReadTable() (map[string]TabbleItem, error) {
	file, err := os.Open("../python-test/dns_table.txt")
	if err != nil {
		log.Println("Can not open table file" + err.Error())
		return nil, err
	}
	defer file.Close()

	table := make(map[string]TabbleItem, 100)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		name := line[0]
		for i := len(name); i < 16; i++ {
			name += string(0)
		}
		// log.Printf("%s: %d", name, len(name))
		ips := [][4]byte{}
		for _, ip_str := range line[1:] {
			ip := [4]byte{}
			fmt.Sscanf(ip_str, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])
			// log.Printf("%x %x %x %x", ip[0], ip[1], ip[2], ip[3])
			ips = append(ips, ip)
		}
		table[name] = TabbleItem{cur: 0, ips: ips}
	}
	return table, nil
}
