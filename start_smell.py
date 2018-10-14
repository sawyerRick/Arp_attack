#!/usr/bin/python
# coding=utf-8
#必须以root运行
import socket, threading, time, sys, os, time, json
from netaddr import IPNetwork
from scapy.all import *

#监听的主机  
host = socket.gethostbyname(socket.gethostname())
subnet = input('>>subnet(前缀表达式):')
# prefix = int(input(">>网络前缀位数(10进制):"))
ip_stack = []
arp_dict = {} 
  
#创建原始套接字，然后绑定在公开接口上  
if os.name == "nt":  
    socket_protocol = socket.IPPROTO_IP
    sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocol)  
    sniffer.bind((host,0))  
    #设置在捕获的数据包中包含IP头  
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    #在Windows平台上，我们需要设置IOCTL以启动混杂模式
    sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)  
else:  
    socket_protocol = socket.IPPROTO_ICMP  
  
#读取单个数据包
def start_sniff():
    print("[+] Start sniffing at %s..." % host)
    global isOn
    while isOn:
        response_ip = str(sniffer.recvfrom(65565)[1][0])
        print("[*] who response:%s" % response_ip) 
        #只记录同网络号,不重复Ip
        if (response_ip != host and \
            response_ip not in ip_stack):
            ip_stack.append(response_ip)
            print("[+++] Append ip %s" % response_ip)
            

def input_to_file():
    print("[+] Writing to file--arp_dict.json")
    global arp_dict
    with open("arp_dict.json", "w") as f:
        for ip in ip_stack:
            arp_dict[ip] = get_mac(ip)
        json.dump(arp_dict,f)
        print("[-] Done...")

def get_mac(ip_address):
    print("[+] Require mac for ip : %s" % ip_address)    
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)  
    #返回从响应数据中获取的Mac地址  
    for s,r in responses:  
        return r[Ether].src  
  
    return None

def send_udp():
    print("[+] About to send udp to subnet...")
    CLientSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    for ip in IPNetwork(subnet):
        time.sleep(0)
        try:
            CLientSocket.sendto(b'Hello!', (bytes(str(ip), encoding="utf8"), 1234))
            print("[+] Sussefully send to ", ip)
        except Exception as e:
            print("[-] Fail to send to ", ip)
            print(e)
     

if __name__ == "__main__":
    isOn = 1
    sniff_thread = threading.Thread(target=start_sniff)
    udp_thread = threading.Thread(target=send_udp)
    sniff_thread.start()
    udp_thread.start()
    udp_thread.join()
    try:
        print("[+] Enter Control + C to exit...")
        while 1:
            input("[+] Waiting...exit")
    except KeyboardInterrupt:     
        isOn = 0
        input_to_file()
        #在Windows平台上关闭混杂模式  
        if os.name == "nt":  
            sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
        print("[-] Ending sniff...")
        sys.exit(0)

