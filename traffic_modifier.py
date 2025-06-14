# Here is a simple Python example using Scapy to capture and modify HTTP (unencrypted) traffic. This script listens for TCP packets on port 80, 
# replaces the word "Hello" with "Hi" in the payload, and resends the modified packet.


from scapy.all import sniff, send, IP, TCP, Raw

def modify_packet(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        # Replace 'Hello' with 'Hi' in the payload
        modified_payload = payload.replace(b'Hello', b'Hi')
        packet[Raw].load = modified_payload
        # Recalculate checksums
        del packet[IP].chksum
        del packet[TCP].chksum
        send(packet)
        print("Modified and sent a packet.")

# Capture TCP packets on port 80 (HTTP)
sniff(filter="tcp port 80", prn=modify_packet, store=0)

# 