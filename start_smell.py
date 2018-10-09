#!/usr/bin/python
# coding=utf-8
import socket  
import os  
import threading, time, sys
  
#监听的主机  
host = input(">>监听主机ip:")
ip_stack = []  
  
#创建原始套接字，然后绑定在公开接口上  
if os.name == "nt":  
    socket_protocol = socket.IPPROTO_IP  
else:  
    socket_protocol = socket.IPPROTO_ICMP  
  
sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocol)  
sniffer.bind((host,0))  
#设置在捕获的数据包中包含IP头  
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)  
#在Windows平台上，我们需要设置IOCTL以启动混杂模式  
if os.name == "nt":  
    sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON) 
  
#读取单个数据包
def start_smell():
    global isOn
    while isOn:
        response_ip = sniffer.recvfrom(65565)[1][0]
        if response_ip not in ip_stack:
            ip_stack.append(response_ip)
            print("who response:%s" % response_ip) 

def input_to_file():
    with open("iptables.txt", "a") as f:
        for ip in ip_stack:
            f.write(str(ip) + '\n')
     

if __name__ == "__main__":
    isOn = 1
    smell_thread = threading.Thread(target=start_smell)
    smell_thread.start()
    while 1:
        try:
            time.sleep(2)
        except KeyboardInterrupt:     
            isOn = 0
            input_to_file()
            #在Windows平台上关闭混杂模式  
            if os.name == "nt":  
                sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
            print("Ending sniff...")
            sys.exit(0)

