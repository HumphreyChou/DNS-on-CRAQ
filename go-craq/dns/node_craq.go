//go:build CRAQ
// +build CRAQ

package dns

import (
	"log"
	"net"

	"github.com/despreston/go-craq/node"
)

func ServeDNS(me *node.Node, port int) error {
	log.Printf("[mode CRAQ] Start serving DNS query at %d\n", port)
	listen, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})
	if err != nil {
		log.Fatal("Failed to listen on port ", port)
	}
	defer listen.Close()

	for {
		var buf [1024]byte
		n, addr, err := listen.ReadFromUDP(buf[:])
		if err != nil {
			log.Println("Read client query failed, err: ", err)
			continue
		}
		query := buf[:n]

		// parse DNS query and reply
		msg := parseQuery(query[:])
		if msg == nil {
			log.Println("Failed to parse client query")
			continue
		}

		if (msg.header.Opt1&QR != 0) || (msg.header.Opt1&OPCODE != QUERY) {
			log.Println("Not a standard DNS query")
			continue
		}

		// read from cluster database and prepare an answer
		rrs := []*RR{}
		for i := 0; i < int(msg.header.QdCount); i++ {
			question := msg.question[i]
			name := string(question.QName[:])
			key, bytes, err := me.Read(name)
			if err != nil {
				log.Println("Can not read key " + name)
				continue
			}

			rr := makeRR(bytes)
			if rr == nil {
				log.Println("Failed to make RR")
				continue
			}
			// check if response matches query
			if key != name || rr.Type != question.QType || rr.Class != question.QClass {
				log.Println("RR does not match key " + name)
				continue
			}
			// log.Printf("[Response] name: %s, ip: %x.%x.%x.%x\n", key, rr.RData[0], rr.RData[1], rr.RData[2], rr.RData[3])
			rrs = append(rrs, rr)
		}
		if len(rrs) == 0 {
			log.Printf("No RR to answer for id %d", msg.header.Id)
			continue
		}

		response, err := makeResponse(msg.header.Id, msg.question, rrs)
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
