import socket
from netaddr import IPNetwork
import time

subnet = input('subnet(前缀表达式):')
CLientSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)


def send_udp_msg():
    for ip in IPNetwork(subnet):
        time.sleep(0)
        try:
            CLientSocket.sendto(b'Hello!', (bytes(str(ip), encoding="utf8"), 1234))
            print("[+] Sussefully send to ", ip)
        except Exception as e:
            print("[-] Fail to send to ", ip)
            print(e)

send_udp_msg()
# print ips