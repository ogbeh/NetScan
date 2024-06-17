from scapy.all import ARP, Ether, srp
import argparse

def get_args():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-t", "--target", help="Target IP range (e.g. 192.168.1.0/24)", required=True)
    args = parser.parse_args()
    return args.target

def scan_network(target):
    # Create ARP request
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send packet and capture responses
    result = srp(packet, timeout=3, verbose=0)[0]

    # Parse results
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return clients

def display_results(clients):
    print("Available devices in the network:")
    print("IP Address\tMAC Address")
    print("-----------------------------------------")
    for client in clients:
        print(f"{client['ip']}\t{client['mac']}")

def save_results(clients, filename="scan_results.txt"):
    with open(filename, 'w') as file:
        file.write("IP Address\tMAC Address\n")
        file.write("-----------------------------------------\n")
        for client in clients:
            file.write(f"{client['ip']}\t{client['mac']}\n")

if __name__ == "__main__":
    target = get_args()
    clients = scan_network(target)
    display_results(clients)
    save_results(clients)

