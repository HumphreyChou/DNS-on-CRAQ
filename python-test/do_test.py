from os import read
import subprocess
import time

node_ports = [8000 + i for i in range(1, 10)]

def run_dhcp():
    dhcp = subprocess.Popen('../go-craq/bin/dhcp', shell=True)
    print('DHCP is running')
    return dhcp

def run_nodes(num):
    nodes = []
    for i in range(num):
        cmd = '../go-craq/bin/server -a {} -p :{}'.format(node_ports[i], node_ports[i] + 1000)
        node = subprocess.Popen(cmd, shell=True)
        nodes.append(node)
        time.sleep(0.1)
    return nodes

def shutdown():
    subprocess.run('pkill -f bin/dhcp', shell=True)
    subprocess.run('pkill -f bin/server', shell=True)
    time.sleep(1)

def write_rtt_test(num, mode):
    dhcp = run_dhcp()
    nodes = run_nodes(num)
    cmd_w = 'python client_write.py rtt_test 127.0.0.1 10000 127.0.0.1 8000 result/{}_write_rtt_{}.txt 60'.format(mode, num)
    writer = subprocess.Popen(cmd_w, shell=True)
    writer.wait()
    print('writer done')
    shutdown()

def read_rtt_test(num, mode, freq):
    dhcp = run_dhcp()
    nodes = run_nodes(num) 
    w_interval = 10 if freq == 'low' else 2
    cmd_w = 'python client_write.py period 127.0.0.1 10000 127.0.0.1 8000 60 {}'.format(w_interval)
    cmd_r = 'python client_read.py rtt_read 127.0.0.1 10001 127.0.0.1 8003 result/{}_{}_read_rtt_{}.txt'.format(mode, freq, num)
    writer = subprocess.Popen(cmd_w, shell=True)
    time.sleep(0.1)
    reader = subprocess.Popen(cmd_r, shell=True)
    writer.wait() 
    print('writer done')
    reader.wait()
    print('reader done')
    shutdown()

def read_throughput_test(num, mode, freq):
    dhcp = run_dhcp()
    nodes = run_nodes(num) 
    w_interval = 10 if freq == 'low' else 2
    cmd_w = 'python client_write.py period 127.0.0.1 10000 127.0.0.1 8000 60 {}'.format(w_interval)
    cmd_r = 'python client_read.py throughput_read 127.0.0.1 10001 127.0.0.1 8003 result/{}_{}_read_throughput_{}.txt 60'.format(mode, freq, num)
    writer = subprocess.Popen(cmd_w, shell=True)
    time.sleep(0.1)
    reader = subprocess.Popen(cmd_r, shell=True)
    writer.wait() 
    print('writer done')
    reader.wait()
    print('reader done')
    shutdown()

def read_accuracy_test(num, mode, freq):
    dhcp = run_dhcp()
    nodes = run_nodes(num) 
    w_interval = 10 if freq == 'low' else 2
    cmd_w = 'python client_write.py period 127.0.0.1 10000 127.0.0.1 8000 60 {}'.format(w_interval)
    cmd_r = 'python client_read.py accuracy_read 127.0.0.1 10001 127.0.0.1 8003 127.0.0.1 8002 result/{}_{}_read_accuracy_{}.txt 60'.format(mode, freq, num)
    writer = subprocess.Popen(cmd_w, shell=True)
    time.sleep(0.1)
    reader = subprocess.Popen(cmd_r, shell=True)
    writer.wait() 
    print('writer done')
    reader.wait()
    print('reader done')
    shutdown() 


if __name__ == '__main__':
    # write_rtt_test(9, 'ttl')
    # read_rtt_test(9, 'ttl', 'high')
    # read_throughput_test(3, 'ttl', 'low')
    read_accuracy_test(3, 'ttl', 'low')
    read_accuracy_test(3, 'ttl', 'high')
    # ls = [[0, 0]] * 10
    # ls[0][1] = 1
    # print(ls)
