import socket
import time
import sys
import random

name_list = []
name_map = {}
name_database = {}
dns_quest_id = 0
default_RTT = 0.5
local_ip = "192.168.1.1"
local_port = 10001
server_ip = "192.168.2.1"
server_ports = [8000 + i for i in range(1, 4)]
server_port = 8002
head_port = server_ports[-1]


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


# read only once with the first name
def simple_read_test():
    dns_packet = dns_build(name_list[0], 1)
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockfd.bind((local_ip, local_port))
    sockfd.settimeout(default_RTT)
    while True:
        try:
            server_addr = (server_ip, server_port)
            sockfd.sendto(dns_packet, server_addr)
            dns_response, addr = sockfd.recvfrom(1024)
            res = dns_response_parse(dns_response)
            if res:
                break
        except socket.timeout:
            continue
    sockfd.close()


# test read rtt
def read_rtt_test(filename, t=60):
    global dns_quest_id
    global default_RTT
    with open(filename, 'w') as fd:
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockfd.bind((local_ip, local_port))
        sockfd.settimeout(default_RTT)
        server_addr = (server_ip, server_port)
        start_time = time.time()
        while time.time() - start_time < t:
            try:
                domain_name = name_list[0]
                dns_query = dns_build(domain_name, dns_quest_id)
                start_rtt = time.time()
                sockfd.sendto(dns_query, server_addr)
                dns_response, addr = sockfd.recvfrom(1024)
                if int.from_bytes(dns_response[:2], byteorder='big', signed=False) == dns_quest_id:
                    end_rtt = time.time()
                    fd.write("%s %s\n" % (start_rtt - start_time, end_rtt - start_rtt))
                dns_quest_id = (dns_quest_id + 1) % 0xffff
            except socket.timeout:
                fd.write("%s %s\n" % (start_rtt - start_time, default_RTT))
                default_RTT += 0.1
            time.sleep(2)


# test read accuracy
def read_accuracy_test(head_ip, head_port, filename, t=60):
    global dns_quest_id
    global default_RTT
    # record[t][0]: total pkt; record[t][1]: matched pkt
    record = {}
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockfd.bind((local_ip, local_port))
    sockfd.settimeout(default_RTT)
    head_addr = (head_ip, head_port)

    sp = 0
    start_time = time.time()
    while time.time() - start_time < t:
        try:
            domain_name = name_list[sp]
            dns_query = dns_build(domain_name, dns_quest_id)
            # randomly choose a node except head
            rand_server_port = random.choice(server_ports)
            while rand_server_port == head_port:
                rand_server_port = random.choice(server_ports)
            start_t = time.time()
            index = int(start_t - start_time)
            if index in record:
                record[index][0] += 1
            else:
                record[index] = [1, 0]
            server_addr = (server_ip, rand_server_port)
            sockfd.sendto(dns_query, head_addr) # MUST send to header first
            head_response, addr = sockfd.recvfrom(1024)
            sockfd.sendto(dns_query, server_addr)
            server_response, addr = sockfd.recvfrom(1024)
            if server_response[58:62] == head_response[58:62]:
                record[index][1] += 1
                print('domain name: {} -> ip: {}.{}.{}.{} CORRECT'.format(domain_name, server_response[58], server_response[59], server_response[60], server_response[61]))
            else:
                print('domain name: {} -> expected: {}.{}.{}.{}, recorded: {}.{}.{}.{} INCORRECT'.format(
                    domain_name, head_response[58], head_response[59], head_response[60], head_response[61],
                    server_response[58], server_response[59], server_response[60], server_response[61]
                ))
            dns_quest_id = (dns_quest_id + 1) % 0xffff
            sp = (sp + 1) % len(name_list) 
        except socket.timeout:
            print('domain name {} response ERROR'.format(domain_name))
            default_RTT += 0.1

        time.sleep(0.5)

    with open(filename, 'w') as fd:
        for i in record.keys():
            fd.write("%s %s %s %s\n" % (i, record[i][0], record[i][1], record[i][1]/record[i][0]))


# test read throughtput
def read_throughput_test(filename, t=60):
    global dns_quest_id
    global default_RTT
    record = [0] * (t+1)
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockfd.bind((local_ip, local_port))
    sockfd.settimeout(default_RTT)
    server_addr = (server_ip, server_port)

    start_time = time.time()
    while time.time() - start_time < t:
        try:
            domain_name = name_list[0]
            dns_query = dns_build(domain_name, dns_quest_id)
            start_t = time.time()
            sockfd.sendto(dns_query, server_addr)
            dns_response, addr = sockfd.recvfrom(1024)
            if int.from_bytes(dns_response[:2], byteorder='big', signed=False) == dns_quest_id:
                record[int(start_t - start_time)] += 1
            dns_quest_id = (dns_quest_id + 1) % 0xffff
        except socket.timeout:
            default_RTT += 0.1
        time.sleep(0.1)

    with open(filename, 'w') as fd:
        for i in range(t+1):
            fd.write("%s %s\n" % (i, record[i]))


def print_usage():
    print("Usage:")
    print("send one dns query for test:")
    print("python client_read.py simple local_ip local_port server_ip server_port")
    print("test read rtt:")
    print("python client_read.py rtt_read local_ip local_port server_ip server_port filename")
    print("test read throughput:")
    print("python client_read.py throughput_read local_ip local_port server_ip server_port filename (duration)")
    print("test read accuracy:")
    print("python client_read.py accuracy_read local_ip local_port "
          "head_ip head_port server_ip server_port filename (duration)")


if __name__ == "__main__":
    read_dns_table()
    if len(sys.argv) == 1:
        print_usage()
    elif sys.argv[1] == "simple" and len(sys.argv) == 6:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        server_ip = sys.argv[4]
        server_port = int(sys.argv[5])
        simple_read_test()
    elif sys.argv[1] == "rtt_read" and len(sys.argv) == 7:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        server_ip = sys.argv[4]
        server_port = int(sys.argv[5])
        read_rtt_test(sys.argv[6])
    elif sys.argv[1] == "rtt_read" and len(sys.argv) == 8:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        server_ip = sys.argv[4]
        server_port = int(sys.argv[5])
        read_rtt_test(sys.argv[6], int(sys.argv[7]))
    elif sys.argv[1] == "throughput_read" and len(sys.argv) == 7:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        server_ip = sys.argv[4]
        server_port = int(sys.argv[5])
        read_throughput_test(sys.argv[6])
    elif sys.argv[1] == "throughput_read" and len(sys.argv) == 8:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        server_ip = sys.argv[4]
        server_port = int(sys.argv[5])
        read_throughput_test(sys.argv[6], int(sys.argv[7]))
    elif sys.argv[1] == "accuracy_read" and len(sys.argv) == 9:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        head_ip_ = sys.argv[4]
        head_port_ = int(sys.argv[5])
        server_ip = sys.argv[6]
        server_port = int(sys.argv[7])
        read_accuracy_test(head_ip_, head_port_, sys.argv[8])
    elif sys.argv[1] == "accuracy_read" and len(sys.argv) == 10:
        local_ip = sys.argv[2]
        local_port = int(sys.argv[3])
        head_ip_ = sys.argv[4]
        head_port_ = int(sys.argv[5])
        server_ip = sys.argv[6]
        server_port = int(sys.argv[7])
        read_accuracy_test(head_ip_, head_port_, sys.argv[8], int(sys.argv[9]))
    else:
        print_usage()
