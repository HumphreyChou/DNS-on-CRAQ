import socket
import time
import sys

name_list = []
name_map = {}
name_database = {}
dns_quest_id = 0
default_RTT = 0.5
local_ip = "192.168.1.1"
local_port = 10000
dhcp_ip = "192.168.2.1"
dhcp_port = 10000


# read dns table file
def read_dns_table(filename="dns_table.txt"):
    global name_list
    global name_map
    with open(filename, 'r') as fd1:
        name_list = fd1.readlines()
        for i in range(len(name_list)):
            tmp_list = name_list[i].split(" ")
            name_map[tmp_list[0]] = tmp_list[1]
            name_database[tmp_list[0]] = tmp_list[1:]
            name_list[i] = tmp_list[0]


# print steam with oct
def print_oct(stream):
    stream = bytes(stream)
    for i in stream:
        print("%02x" % i, end=" ")
    print("")


# build dns header
# id   2bytes
# flag 2bytes
# qdcount  2bytes
# ancount  2bytes
# nscount  2bytes
# arcount  2bytes
def dns_header_build(dns_id, flag=0, qdcount=1, ancount=0, nscount=0, arcount=0):
    dns_id = dns_id.to_bytes(2, byteorder="big")
    flag = flag.to_bytes(2, byteorder="big")
    qdcount = qdcount.to_bytes(2, byteorder="big")
    ancount = ancount.to_bytes(2, byteorder="big")
    nscount = nscount.to_bytes(2, byteorder="big")
    arcount = arcount.to_bytes(2, byteorder="big")
    header = dns_id+flag+qdcount+ancount+nscount+arcount
    return header


# build dns query record
#  qname   16 bytes
#  qtype   2 bytes
#  qclass  2 bytes
def dns_question_build(qname, qtype=1, qclass=1):
    qname = qname.encode('ascii')
    if len(qname) > 16:
        print("domain name is too long: %s" % qname)
        return bytes(0)
    suffix = bytes(16-len(qname))
    qtype = qtype.to_bytes(2, byteorder="big")
    qclass = qclass.to_bytes(2, byteorder="big")
    dns_question = qname+suffix+qtype+qclass
    return dns_question


def dns_build(qname, dns_id):
    header = dns_header_build(dns_id)
    query = dns_question_build(qname)
    if query == 0:
        return bytes(0)
    return header+query


# parse dns response packet
# header    12bytes
# query     20bytes per RR
# answer    30bytes per RR(default)
#       : name  16bytes
#       : type  2bytes
#       : class 2bytes
#       : ttl   4bytes
#       : rdlen 2bytes(default value: 4)
#       : rdata 4bytes(ip addr)
def dns_response_parse(msg):
    dns_response = msg
    print_oct(dns_response)

    # parse dns response header
    header = dns_response[:12]
    # id = int.from_bytes(header[:2],byteorder="big",signed=False)
    # flag = int.from_bytes(header[2:4],byteorder="big",signed=False)
    qdcount = int.from_bytes(header[4:6], byteorder="big", signed=False)
    ancount = int.from_bytes(header[6:8], byteorder="big", signed=False)

    if qdcount != 1 or ancount != 1:
        return False

    # parse query domain name
    name = dns_response[12:28]
    name_end = 0
    while name_end < 16:
        if name[name_end] == 0:
            break
        name_end += 1
    name = name[:name_end]
    name = name.decode('ascii')
    if name not in name_map:
        return False

    ans_start = 32
    # parse response
    ans_record = dns_response[ans_start:ans_start + 26]
    # ans_ttl = int.from_bytes(ans_record[20:24], byteorder="big", signed=False)
    ans_len = int.from_bytes(ans_record[24:], byteorder="big", signed=False)
    if ans_len != 4:
        return False
    ans_ip = int.from_bytes(dns_response[ans_start + 26:ans_start + 26 + ans_len], byteorder="big", signed=False)

    def ip_int_to_str(x: int) -> str:
        return '.'.join([str(x // (256 ** i) % 256) for i in range(4)][::-1])

    ip = ip_int_to_str(ans_ip)
    print("The response of %s is %s" % (name, ip))
    return True


# just for test
def create_dns_response_for_test():
    header = dns_header_build(1234, 0x8000, 1, 1, 0, 0)
    query = dns_question_build(name_list[0])

    # build answer record
    ans_name = int(0xc000).to_bytes(2, byteorder="big", signed=False)
    ans_type = int(0x0001).to_bytes(2, byteorder="big", signed=False)
    ans_class = int(0x0001).to_bytes(2, byteorder="big", signed=False)
    ans_ttl = int(0x0005).to_bytes(4, byteorder="big", signed=False)
    ans_len = int(0x0004).to_bytes(2, byteorder="big", signed=False)
    ans_ip = int(0xc0a80201).to_bytes(4, byteorder="big", signed=False)
    ans = ans_name+ans_type+ans_class+ans_ttl+ans_len+ans_ip
    return header+query+ans


# write only once with the first name
def simple_write_test():
    dns_packet = dns_build(name_list[0], 1)
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockfd.bind((local_ip, local_port))
    sockfd.settimeout(default_RTT)
    while True:
        try:
            dhcp_addr = (dhcp_ip, dhcp_port)
            sockfd.sendto(dns_packet, dhcp_addr)
            dns_response, addr = sockfd.recvfrom(1024)
            res = dns_response_parse(dns_response)
            if res:
                break
        except socket.timeout:
            continue
    sockfd.close()


# write all domain name, then don't change
def write_all_test():
    global dns_quest_id
    global default_RTT
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockfd.bind((local_ip, local_port))
    sockfd.settimeout(default_RTT)
    dhcp_addr = (dhcp_ip, dhcp_port)
    for i in range(len(name_list)):
        dns_query = dns_build(name_list[i], dns_quest_id)
        dns_quest_id += 1
        if dns_query == bytes(0):
            print("domain name: %s id: %d build query fault" % (name_list[i], dns_quest_id))
            continue
        while True:
            try:
                sockfd.sendto(dns_query, dhcp_addr)
                dns_response, addr = sockfd.recvfrom(1024)
                res = dns_response_parse(dns_response)
                if res:
                    break
            except socket.timeout:
                default_RTT += 0.1
    sockfd.close()


# write all domain name, then periodic renewal some domain name's ip
# t: run time;  interval: period;    n: the number of updating each time
def write_all_periodic_renewal_test(t=60, interval=10, n=3):
    global dns_quest_id
    global default_RTT
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockfd.bind((local_ip, local_port))
    sockfd.settimeout(default_RTT)
    dhcp_addr = (dhcp_ip, dhcp_port)

    # init
    for i in range(len(name_list)):
        dns_query = dns_build(name_list[i], dns_quest_id)
        dns_quest_id += 1
        if dns_query == bytes(0):
            print("domain name: %s id: %d build query fault" % (name_list[i], dns_quest_id))
            continue
        while True:
            try:
                sockfd.sendto(dns_query, dhcp_addr)
                dns_response, addr = sockfd.recvfrom(1024)
                res = dns_response_parse(dns_response)
                if res:
                    break
            except socket.timeout:
                default_RTT += 0.1

    sp = 0  # the start pointer of name_map in each turn
    # update n domain names
    for i in range(int(t/interval)):
        time.sleep(interval)
        for j in range(n):
            domain_name = name_list[(sp+j) % len(name_list)]
            dns_query = dns_build(domain_name, dns_quest_id)
            dns_quest_id += 1
            # send dns query
            while True:
                try:
                    sockfd.sendto(dns_query, dhcp_addr)
                    dns_response, addr = sockfd.recvfrom(1024)
                    res = dns_response_parse(dns_response)
                    if res:
                        break
                except socket.timeout:
                    default_RTT += 0.1
            # update ip
            for k in range(len(name_database[domain_name])):
                if name_database[domain_name][k] == name_map[domain_name]:
                    name_map[domain_name] = name_database[domain_name][(k+1) % len(name_database[domain_name])]
                    break
        sp = (sp+n) % len(name_list)

    sockfd.close()


# test write rtt
# t: time of test duration
def write_rtt_test(filename, t=60):
    global dns_quest_id
    global default_RTT
    with open(filename, 'w') as fd:
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockfd.bind((local_ip, local_port))
        sockfd.settimeout(default_RTT)
        dhcp_addr = (dhcp_ip, dhcp_port)
        sp = 0
        start_time = time.time()
        while time.time() - start_time < t:
            try:
                domain_name = name_list[sp]
                dns_query = dns_build(domain_name, dns_quest_id)
                start_rtt = time.time()
                sockfd.sendto(dns_query, dhcp_addr)
                dns_response, addr = sockfd.recvfrom(1024)
                if int.from_bytes(dns_response[:2], byteorder='big', signed=False) == dns_quest_id:
                    end_rtt = time.time()
                    fd.write("%s %s\n" % (start_rtt-start_time, end_rtt-start_rtt))
                sp = (sp + 1) % len(name_list)
                dns_quest_id = (dns_quest_id + 1) % 0xffff
            except socket.timeout:
                default_RTT += 0.1
            time.sleep(1)


def print_usage():
    print("Usage:")
    print("send one dns query for test:")
    print("python client_write.py simple local_ip local_port dhcp_ip dhcp_port")
    print("init domain name and not change:")
    print("python client_write.py write_all local_ip local_port dhcp_ip dhcp_port")
    print("init domain name and periodically change:")
    print("python client_write.py period local_ip local_port dhcp_ip dhcp_port (duration) (interval)")
    print("test write RTT:")
    print("python client_write.py rtt_test local_ip local_port dhcp_ip dhcp_port filename (duration)")


if __name__ == "__main__":
    read_dns_table()
    if len(sys.argv) == 1:
        print_usage()
    elif sys.argv[1] == "simple" and len(sys.argv) == 6:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        dhcp_ip = sys.argv[4]
        dhcp_port = int(sys.argv[5])
        simple_write_test()
    elif sys.argv[1] == "write_all" and len(sys.argv) == 6:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        dhcp_ip = sys.argv[4]
        dhcp_port = int(sys.argv[5])
        write_all_test()
    elif sys.argv[1] == "period" and len(sys.argv) == 6:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        dhcp_ip = sys.argv[4]
        dhcp_port = int(sys.argv[5])
        write_all_periodic_renewal_test()
    elif sys.argv[1] == "period" and len(sys.argv) == 8:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        dhcp_ip = sys.argv[4]
        dhcp_port = int(sys.argv[5])
        duration = int(sys.argv[6])
        interv = int(sys.argv[7])
        write_all_periodic_renewal_test(duration, interv)
    elif sys.argv[1] == "rtt_test" and len(sys.argv) == 7:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        dhcp_ip = sys.argv[4]
        dhcp_port = int(sys.argv[5])
        filename_ = sys.argv[6]
        write_rtt_test(filename_)
    elif sys.argv[1] == "rtt_test" and len(sys.argv) == 8:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        dhcp_ip = sys.argv[4]
        dhcp_port = int(sys.argv[5])
        filename_ = sys.argv[6]
        duration_ = int(sys.argv[7])
        write_rtt_test(filename_, duration_)
    else:
        print_usage()
