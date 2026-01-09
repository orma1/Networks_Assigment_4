import socket

# Configuration
IP = "0.0.0.0"
PORT = 8080

# Create UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP, PORT))

print(f"✅ UDP Server listening on {PORT}...")

while True:
    # 1. Wait for a packet (even an empty one)
    data, addr = sock.recvfrom(1024)
    print(f"📩 Packet received from {addr}! Sending reply...")
    
    # 2. Automatically send a reply back
    sock.sendto(b"Hello Scanner!", addr)