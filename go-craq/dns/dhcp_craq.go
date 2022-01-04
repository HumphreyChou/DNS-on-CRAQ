//go:build CRAQ
// +build CRAQ

package dns

import (
	"log"
	"net"
	"time"

	"github.com/despreston/go-craq/coordinator"
)

func ServeDHCP(me *coordinator.Coordinator, port int) error {
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
		_, addr, err := listen.ReadFromUDP(query[:])
		if err != nil {
			log.Println("Read client query failed, err: ", err)
			continue
		}

		// parse DHCP query and allocate or update an IP address
		// DHCP request format is the same as DNS request
		msg := parseQuery(query[:])
		if msg == nil {
			log.Println("Failed to parse client query")
			continue
		}

		if (msg.header.opt1&QR != 0) || (msg.header.opt1&OPCODE != QUERY) {
			log.Println("Not a standard DNS query")
			continue
		}

		// TODO: read from domain-IP table and pick an IP
		key := msg.question[0].qName
		var ip string
		rr := &RR{
			name: key, type_: uint16(A), class: uint16(IN),
			ttl: TTL, rdLength: uint16(len(ip)), rdata: ip,
			timestamp: time.Now().Unix(),
		}
		me.Write(key, rr.ToBytes()) // this call would block until all nodes have commited

		response, err := makeResponse(msg.header.id, []*RR{rr})
		if err != nil {
			log.Println("Failed to make response message")
			continue
		}

		_, err = listen.WriteToUDP(response.ToBytes(), addr)
		if err != nil {
			log.Println("Failed to write to client, err: ", err)
			continue
		}
	}
	return nil
}
