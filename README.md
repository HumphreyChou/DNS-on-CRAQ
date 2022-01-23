# DoCR: DNS with Strong Consistency

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
[DNS format specification](https://datatracker.ietf.org/doc/html/rfc1035)  
More referenced materials are listed in `paper/` 

## Prerequisite
- go: check `go-craq/go.mod`
- python >= 3.6

## Usage
```
cd go-craq
make all MODE=[CRAQ|TTL]
cd ../python-test
python do_test.py
``` 

## Result
Check `presentation/DoCR.pdf` for full story  
Check `python-test/result/` for raw test result data