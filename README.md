Basic Network Sniffer

Build a network sniffer in Python that captures and
analyzes network traffic. This project will help you
understand how data flows on a network and how
network packets are structured


Install in Terminal:

<ul>
<li>pip install scapy <br></li>
<li>ip link show <i>/from this you should see your interface/</i><br></li>
<li>sudo python main.py -i < interface >   <i>/for example eth0</i>/<br></li>
</ul>


```python
# main.py
from scapy.all import sniff, TCP, IP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse


def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"New Packet: {ip_layer.src} -> {ip_layer.dst}")
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"  TCP {tcp_layer.sport} -> {tcp_layer.dport}")

            # Check if the packet contains Raw layer
            if packet.haslayer(Raw):
                payload = packet.getlayer(Raw).load.decode('utf-8', errors='ignore')

                # Check if it's an HTTP POST request
                if 'POST' in payload:
                    print("  HTTP POST request found")
                    if 'username' in payload or 'password' in payload:
                        print("    Possible login data detected")
                        # Extracting data from the payload
                        payload_lines = payload.split('\n')
                        for line in payload_lines:
                            if 'username' in line or 'password' in line:
                                print(f"    {line.strip()}")


def start_sniffing(interface):
    print(f"Starting sniffing on interface: {interface}")
    sniff(iface=interface, prn=process_packet, store=False)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple Network Packet Sniffer")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to sniff on")
    args = parser.parse_args()
    start_sniffing(args.interface)

```
