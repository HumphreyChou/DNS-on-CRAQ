package main

import (
	"flag"
	"log"
	"net/http"
	"net/rpc"
	"strconv"

	"github.com/despreston/go-craq/coordinator"
	"github.com/despreston/go-craq/dns"
	"github.com/despreston/go-craq/transport/netrpc"
)

func main() {
	var addr, pub string

	flag.StringVar(&addr, "a", "8000", "Local address to listen on")
	flag.StringVar(&pub, "p", ":8010", "Public address reachable by chain nodes")
	flag.Parse()

	c := coordinator.New(netrpc.NewNodeClient)

	binding := netrpc.CoordinatorBinding{Svc: c}
	if err := rpc.RegisterName("RPC", &binding); err != nil {
		log.Fatal(err)
	}
	rpc.HandleHTTP()

	// Start the Coordinator
	go c.Start()

	// wait for client DNS requests (allocate or update IPs)
	port, err := strconv.Atoi(addr)
	if err != nil {
		log.Fatal("Invalid listen port" + addr + err.Error())
	}
	go dns.ServeDHCP(c, port)

	// wait for RPC in DNS servers cluster
	log.Println("Listening at " + pub)
	log.Fatal(http.ListenAndServe(pub, nil))
}
