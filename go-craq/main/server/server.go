package main

import (
	"flag"
	"log"
	"net/http"
	"net/rpc"
	"strconv"

	"github.com/despreston/go-craq/dns"
	"github.com/despreston/go-craq/node"
	"github.com/despreston/go-craq/store/kv"
	"github.com/despreston/go-craq/transport/netrpc"
)

func main() {
	var addr, pub, cdr, dbFile string

	flag.StringVar(&addr, "a", ":8001", "Local address to listen on")
	flag.StringVar(&pub, "p", ":8010", "Public address reachable by coordinator and other nodes")
	flag.StringVar(&cdr, "c", ":8000", "Coordinator address")
	flag.StringVar(&dbFile, "f", "dns.db", "Bolt DB database file")
	flag.Parse()

	// configure storage
	db := kv.New()
	n := node.New(node.Opts{
		Address:           addr,
		CdrAddress:        cdr,
		PubAddress:        pub,
		Store:             db,
		Transport:         netrpc.NewNodeClient,
		CoordinatorClient: netrpc.NewCoordinatorClient(),
		Log:               log.Default(),
	})

	// configure RPC
	b := netrpc.NodeBinding{Svc: n}
	if err := rpc.RegisterName("RPC", &b); err != nil {
		log.Fatal(err)
	}
	rpc.HandleHTTP()

	// connect to DHCP server(coordinator)
	go n.Start()

	// wait for client DNS requests
	port, err := strconv.Atoi(addr)
	if err != nil {
		log.Fatal("Invalid listen port " + addr)
	}
	log.Println("Listening external calls at " + addr)
	go dns.ServeDNS(n, port)

	// wait for RPC in DNS servers cluster
	log.Println("Listening internal calls at " + pub)
	http.ListenAndServe(pub, nil)
}
