import sys
from scapy.all import *

#Generic Port Scanner
#Steven Shadders

def scan_ports(target_ip, ports):
    open_ports = []

    for port in ports:
        # Create a TCP SYN packet
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

        # Send the packet and wait for a response
        response = sr1(packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:
                # Port is open
                open_ports.append(port)
                try:
                    # Attempt to retrieve the banner by sending a request
                    banner = sr1(IP(dst=target_ip) / TCP(dport=port, flags="S"), timeout=1, verbose=0)
                    if banner:
                        banner_data = banner.getlayer(Raw).load
                        print(f"Port {port} is open - Banner: {banner_data.decode('utf-8', 'ignore').strip()}")
                    else:
                        print(f"Port {port} is open")
                except Exception:
                    print(f"Port {port} is open")
            elif response[TCP].flags == 0x14:
                # Port is closed
                pass

    return open_ports

def main():
    if len(sys.argv) != 4:
        print("Usage: python port_scanner.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    ports = range(start_port, end_port + 1)

    open_ports = scan_ports(target_ip, ports)

    if not open_ports:
        print("No open ports found on {}.".format(target_ip))

if __name__ == "__main__":
    main()
