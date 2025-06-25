from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dot11 import Dot11, Dot11Elt
from scapy.layers.l2 import Ether

# Known MACs for intrusion detection
known_macs = {
    "00:11:22:33:44:55",  # Example known device
    "66:77:88:99:AA:BB"
}

def extract_macs(pkt):
    mac_src = None
    mac_dst = None
    if pkt.haslayer(Dot11):
        mac_src = pkt.addr2
        mac_dst = pkt.addr1
    elif pkt.haslayer(Ether):
        mac_src = pkt.src
        mac_dst = pkt.dst
    return mac_src, mac_dst

def extract_features_from_packet(pkt):
    if not pkt.haslayer(IP):
        return None
    proto = pkt[IP].proto
    length = len(pkt)
    sport = 0
    dport = 0
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    return [length, proto, sport, dport]

def classify_traffic_heuristic(pkt):
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        if dport in [80, 443]:
            return "Browsing"
        if dport in [1935, 554]:
            return "Streaming"
        if dport in [5060, 5061]:
            return "VoIP"
        return "Other-TCP"
    elif pkt.haslayer(UDP):
        dport = pkt[UDP].dport
        if dport in [5060, 5004]:
            return "VoIP"
        return "Other-UDP"
    return "Unknown"

def check_intrusion(pkt):
    mac_src, _ = extract_macs(pkt)
    if mac_src and mac_src not in known_macs:
        return f"[INTRUSION ALERT] Unknown MAC detected: {mac_src}"
    return None
