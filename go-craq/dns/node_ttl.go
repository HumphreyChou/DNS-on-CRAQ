//go:build TTL
// +build TTL

package dns

import (
	"log"
	"net"
	"time"

	"github.com/despreston/go-craq/node"
)

func ServeDNS(me *node.Node, port int) error {
	log.Printf("[mode TTL] Start serving DNS query at %d\n", port)
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

		// read from self database and prepare an answer
		rrs := []*RR{}
		for i := 0; i < int(msg.header.QdCount); i++ {
			question := msg.question[i]
			name := string(question.QName[:])
			// read from self storage
			key, bytes, err := me.ReadRaw(name)
			if err != nil {
				log.Printf("Can not read key %s: %s, ask primary for record\n", name, err.Error())
				bytes, err = me.AskTail(name)
				if err != nil {
					log.Println("Can not ask primary for latest version " + name)
					continue
				}
				me.WriteRaw(name, bytes)
			}

			rr := makeRR(bytes)
			if rr == nil {
				log.Println("Failed to make RR")
				continue
			}
			key = string(rr.Name[:])

			// check TTL for non-tail nodes and see if it expires
			now := time.Now().Unix()
			if !me.IsTail && rr.Timestamp+int64(rr.Ttl) < now {
				log.Printf("name %s TTL expires, ask primary for latest\n", name)
				// ask tail for latest RR
				bytes, err = me.AskTail(name)
				if err != nil {
					log.Println("Can not ask primary for latest version" + name)
					continue
				}
				rr = makeRR(bytes)
				key = string(rr.Name[:])

				// sanity check
				if key != name {
					log.Printf("RR [%s] does not match key [%s]", key, name)
					continue
				}

				// store it in self database
				rr.Timestamp = time.Now().Unix()
				me.WriteRaw(name, rr.ToBytes())
			}

			// check if response matches query
			if key != name || rr.Type != question.QType || rr.Class != question.QClass {
				log.Printf("RR [%s] does not match key [%s]", key, name)
				continue
			}

			// log.Printf("[Response] name: %s, ip: %x.%x.%x.%x\n", key, rr.RData[0], rr.RData[1], rr.RData[2], rr.RData[3])
			rrs = append(rrs, rr)
		}
		if len(rrs) == 0 {
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
