import socket
from datetime import datetime

HOST = '0.0.0.0'
PORT = 9999

print(f"[+] Honeypot listening on {HOST}:{PORT}...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)

    while True:
        conn, addr = s.accept()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[!] Connection from {addr[0]} at {timestamp}")

        try:
            banner = conn.recv(1024).decode(errors='ignore')
        except:
            banner = 'N/A'

        with open("sample_logs/ip_log.txt", "a") as f:
            f.write(f"{timestamp} - {addr[0]} - {banner}\n")

        conn.close()
