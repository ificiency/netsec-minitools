from scapy.all import sniff
from datetime import datetime

# Define high-risk indicators
SUSPICIOUS_PORTS = [4444, 5555, 6666]
SUSPICIOUS_FLAGS = ["S", "F", "U"]  # SYN, FIN, URG

def risk_score(pkt):
    score = 0
    flags = ""

    if pkt.haslayer("TCP"):
        tcp = pkt["TCP"]
        flags = str(tcp.flags)

        if tcp.dport in SUSPICIOUS_PORTS:
            score += 2
        if any(f in flags for f in SUSPICIOUS_FLAGS):
            score += 1

    elif pkt.haslayer("UDP") and pkt["UDP"].dport in SUSPICIOUS_PORTS:
        score += 2

    return score, flags

def analyze_packet(pkt):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src = pkt[0][1].src if pkt.haslayer("IP") else "Unknown"
    dst = pkt[0][1].dst if pkt.haslayer("IP") else "Unknown"
    proto = pkt.name

    score, flags = risk_score(pkt)

    print(f"[{ts}] [{proto}] {src} → {dst} | Risk Score: {score} | Flags: {flags}")

print("[*] Starting Real-Time Packet Monitor with Risk Scoring...")
sniff(prn=analyze_packet, store=0)
