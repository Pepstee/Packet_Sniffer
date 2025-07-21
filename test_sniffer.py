from scapy.all import sniff

print("Starting minimal sniffer on interface 'WiFi'...")
print("Press Ctrl+C to stop.")

def process_packet(packet):
    print(packet.summary())

try:
    # We are using iface="WiFi" as determined before
    sniff(prn=process_packet, iface="WiFi", store=False)
except Exception as e:
    print(f"An error occurred: {e}")