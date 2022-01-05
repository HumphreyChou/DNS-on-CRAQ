package dns

import (
	"log"
	"net"
	"time"

	"github.com/despreston/go-craq/coordinator"
)

func ServeDHCP(me *coordinator.Coordinator, port int) error {
	log.Printf("Start serving DHCP request at %d", port)
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

		// parse DHCP query and allocate or update an IP address
		// DHCP request format is the same as DNS request
		msg := parseQuery(query[:])
		if msg == nil {
			log.Println("Failed to parse client query")
			continue
		}

		if (msg.header.Opt1&QR != 0) || (msg.header.Opt1&OPCODE != QUERY) {
			log.Println("Not a standard DNS query")
			continue
		}

		// TODO: read from domain-IP table and pick an IP
		key := string(msg.question[0].QName[:])
		var name [16]byte
		ip := [4]byte{0, 0, 0, 0}
		copy(name[:], key)
		rr := &RR{
			Name: name, Type: uint16(A), Class: uint16(IN),
			Ttl: TTL, RdLength: uint16(len(ip)), RData: ip,
			Timestamp: time.Now().Unix(),
		}
		me.Write(key, rr.ToBytes()) // this call would block until all nodes have commited

		response, err := makeResponse(msg.header.Id, []*RR{rr})
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
