import socket
import time

name_list = []
name_map = {}
dns_quest_id = 0
default_TTL = 0.5
local_ip = "192.168.1.1"
local_port = 10000
dhcp_ip = "192.168.2.1"
dhcp_port = 10000

#read dns table file
def read_dns_table(filename="dns_table.txt"):
    global name_list
    global name_map
    with open(filename,'r') as fd1:
        name_list = fd1.readlines()
        for i in range(0,len(name_list)):
            name_list[i] = name_list[i].split(" ")
            name_map[name_list[i][0]]=name_list[i][1]
            name_list[i] = name_list[i][0]


# print steam with oct
def print_oct(stream):
    stream = bytes(stream)
    for i in stream:
        print("%02x"%(i),end = " ")
    print("")

# build dns header
# id   2bytes
# flag 2bytes
# qdcount  2bytes
# ancount  2bytes
# nscount  2bytes
# arcount  2bytes
def dns_header_build(id,flag = 0,qdcount = 1,ancount = 0,nscount = 0,arcount = 0):
    id = id.to_bytes(2,byteorder="big")
    flag = flag.to_bytes(2,byteorder="big")
    qdcount = qdcount.to_bytes(2,byteorder="big")
    ancount = ancount.to_bytes(2,byteorder="big")
    nscount = nscount.to_bytes(2,byteorder="big")
    arcount = arcount.to_bytes(2,byteorder="big")
    header = id+flag+qdcount+ancount+nscount+arcount
    return header

# build dns query record
#  qname   16 bytes
#  qtype   2 bytes
#  qclass  2 bytes
def dns_question_build(qname,qtype = 1,qclass = 1):
    qname = qname.encode('ascii')
    if len(qname) > 16:
        return bytes(0)
    suffix = bytes(16-len(qname))
    qtype = qtype.to_bytes(2,byteorder="big")
    qclass = qclass.to_bytes(2,byteorder="big")
    dns_question = qname+suffix+qtype+qclass
    return dns_question

# parse dns response packet
# header    12bytes
# query     20bytes per RR
# answer    16bytes per RR(default)
#       : name  2bytes
#       : type  2bytes
#       : class 2bytes
#       : ttl   4bytes
#       : rdlen 2bytes(default value: 4)
#       : rdata 4bytes(ip addr)
def dns_response_parse(msg):
    dns_response = msg
    print_oct(dns_response)

    #parse dns response header
    header = dns_response[:12]
    id = int.from_bytes(header[:2],byteorder="big",signed=False)
    flag = int.from_bytes(header[2:4],byteorder="big",signed=False)
    qdcount = int.from_bytes(header[4:6],byteorder="big",signed=False)
    ancount = int.from_bytes(header[6:8],byteorder="big",signed=False)

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
    ans_record = dns_response[ans_start:ans_start+12]
    ans_ttl = int.from_bytes(ans_record[6:10],byteorder="big",signed=False)
    ans_len = int.from_bytes(ans_record[10:],byteorder="big",signed=False)
    if ans_len != 4:
        return False
    ans_ip = int.from_bytes(dns_response[ans_start+12:ans_start+12+ans_len],byteorder="big",signed=False)
    ip_int_to_str = lambda x: '.'.join([str(x//(256**i) % 256) for i in range(4)][::-1])
    ip = ip_int_to_str(ans_ip)
    print("The response of %s is %s"%(name,ip))
    return True

#just for test
def create_dns_response_for_test():
    header = dns_header_build(1234,0x8000,1,1,0,0)
    query = dns_question_build(name_list[0])

    # build answer record
    ans_name = int(0xc000).to_bytes(2,byteorder="big",signed=False)
    ans_type = int(0x0001).to_bytes(2,byteorder="big",signed=False)
    ans_class = int(0x0001).to_bytes(2,byteorder="big",signed=False)
    ans_ttl = int(0x0005).to_bytes(4,byteorder="big",signed=False)
    ans_len = int(0x0004).to_bytes(2,byteorder="big",signed=False)
    ans_ip = int(0xc0a80201).to_bytes(4,byteorder="big",signed=False)
    ans = ans_name+ans_type+ans_class+ans_ttl+ans_len+ans_ip
    return header+query+ans

if __name__ == "__main__":
    read_dns_table()
    dns_header = dns_header_build(1)
    dns_question = dns_question_build(name_list[0])
    if dns_question == bytes(0):
        exit(0)
    dns_packet = dns_header+dns_question
    print_oct(dns_packet)
    # sockfd = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    # sockfd.bind((local_ip,local_port))
    # sockfd.settimeout(default_TTL)
    # while True:
    #     try:
    #         start_t = time.time()
    #         dhcp_addr = (dhcp_ip,dhcp_port)
    #         sockfd.sendto(dns_packet,dhcp_addr)
    #         dns_response, addr = sockfd.recvfrom(1024)
    #         res = dns_response_parse(dns_response)
    #         if res:
    #             break
    #     except socket.timeout:
    #         continue
    # sockfd.close()
    dns_response = create_dns_response_for_test()
    print_oct(dns_response)
    dns_response_parse(dns_response)





