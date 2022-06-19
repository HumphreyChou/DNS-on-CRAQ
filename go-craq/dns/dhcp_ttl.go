//go:build TTL
// +build TTL

package dns

import (
	"log"
	"net"
	"time"

	"github.com/despreston/go-craq/coordinator"
)

func ServeDHCP(me *coordinator.Coordinator, port int) error {
	// first read name-ip table
	table, err := ReadTable()
	if err != nil {
		log.Fatal("Failed to read IP table")
	}

	log.Printf("[mode TTL] Start serving DHCP request at %d", port)
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

		// read from name-IP table and pick an IP
		key := string(msg.question[0].QName[:])
		var name [16]byte
		copy(name[:], key)
		ip := [4]byte{}
		if alloc, found := table[key]; found {
			ip = alloc.ips[alloc.cur]
			alloc.cur = (alloc.cur + 1) % uint(len(alloc.ips))
			table[key] = alloc
		} else {
			log.Println("Can not allocate IP for " + key)
			continue
		}
		rr := &RR{
			Name: name, Type: uint16(A), Class: uint16(IN),
			Ttl: TTL, RdLength: uint16(len(ip)), RData: ip,
			Timestamp: time.Now().Unix(),
		}
		log.Printf("name %s, ip %x %x %x %x\n", name, ip[0], ip[1], ip[2], ip[3])

		// write this new RR to tail
		if err := me.WriteRaw(key, rr.ToBytes()); err != nil {
			log.Printf("Can not write %s to primary\n", key)
		}

		response, err := makeResponse(msg.header.Id, msg.question, []*RR{rr})
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
