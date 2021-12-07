//go:build TTL
// +build TTL

package dns

import (
	"log"
	"net"

	"github.com/despreston/go-craq/node"
)

func ServeDNS(me *node.Node, port int) error {
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

		// parse DNS query and reply
		msg := parseQuery(query[:])
		if msg == nil {
			log.Println("Failed to parse client query")
			continue
		}

		if (msg.header.opt1&QR != 0) || (msg.header.opt1&OPCODE != QUERY) {
			log.Println("Not a standard DNS query")
			continue
		}

		// read from self database and prepare an answer
		rrs := make([]*RR, msg.header.qdCount)
		for i := 0; i < int(msg.header.qdCount); i++ {
			question := msg.question[i]
			// TODO: read from self and check TTL
			key, bytes, err := me.Read(question.qName)
			if err != nil {
				log.Println("Can not read key " + question.qName)
				continue
			}

			rr := makeRR(bytes)
			if rr == nil {
				log.Println("Failed to make RR")
				continue
			}
			// check if response matches query
			if key != question.qName || rr.type_ != question.qType || rr.class != question.qClass {
				log.Println("RR does not match key " + question.qName)
				continue
			}
			rrs = append(rrs, rr)
		}

		response, err := makeResponse(msg.header.id, rrs)
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
