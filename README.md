# DNS with Strong Consistency

## What
This is a mini-research project motivated by *PKU Computer Networks (Honor Tack) 21Fall*   
We try to achieve strong consistency requirement for DNS service (i.e. if a domain-name-IP mapping changes, all clients/servers must see it at once)
## Why
Existing DNS update scheme adapts TTL mechanism which reaches weak (eventual) consisteny. It works well today but it possibly won't fit mobile servers in the future.
## How
Basically we propose using CRAQ(Chain Replication with Apportioned Queries) system, which is a distributed system scheme published in 2009.
Unfortunately we can not modify DNS servers in real world but we can simulate a DNS server and some clients and a scenario where IP modification is rather frequent. 
## Material
[CRAQ paper](https://www.usenix.org/legacy/event/usenix09/tech/full_papers/terrace/terrace.pdf)  
[DNScup](https://ieeexplore.ieee.org/document/1648827) proposed a lease technique which essentially adapts a dynamic TTL  
[ECO-DNS](https://ieeexplore.ieee.org/document/7164912) also proposed a dynamic TTL scheme  
[DDNS RFC2136](https://datatracker.ietf.org/doc/html/rfc2136) now existing dynamic DNS update protocol which is pretty straightforward(another word for naive)  
More referenced materials are listed in `paper/`  
## Proposal 
Edit this [overleaf link](https://www.overleaf.com/8934546512bfqsfbjjppjb) to complish proposal

## TODO
- [ ] read section 3 and 4 of this [DNS format specification](https://datatracker.ietf.org/doc/html/rfc1035) 
- [ ] check `go-craq/dns/dns.go` for query and response format(which is the API between client and DNS servers)  