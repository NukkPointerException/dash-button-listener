from scapy.all import *
from scapy.layers.l2 import ARP
from requests import *

#Initial state of light
lightOn = True

def callHueController():
    global lightOn
    print(lightOn)
    if lightOn:
        print("turning light off")
        get('http://192.168.0.80:1138/1251/bedroomLight/off')
        lightOn = False
    else:
        print("turning light on")
        get('http://192.168.0.80:1138/1251/bedroomLight/on')
        lightOn = True


def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
        print("sniffed")
        #call 192.168.0.80
        callHueController()
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")


# Setup dictionary of names:mac addresses
macAddresses = {}
#File in format of name=macaddress
with open("dash.macs") as dashMacs:
    for line in dashMacs:
        name, mac = line.partition("=")[::2]
        macAddresses[name.strip()] = mac


sniff(prn=arp_monitor_callback, lfilter=lambda d: d.src == macAddresses["SCOTT"], store=0)
