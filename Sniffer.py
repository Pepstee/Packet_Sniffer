import streamlit as st
import pandas as pd
import threading
import time
import queue
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, conf

# --- Constants & Helper Functions ---
IP_PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# --- Packet Sniffer Logic ---
if 'packet_data' not in st.session_state:
    st.session_state.packet_data = []

def run_sniffer(stop_event, iface_name, packet_q):
    def process_packet_local(packet):
        packet_info = {}
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            protocol_num = ip_layer.proto
            packet_info['Timestamp'] = time.strftime("%H:%M:%S")
            packet_info['Source IP'] = ip_layer.src
            packet_info['Destination IP'] = ip_layer.dst
            packet_info['Protocol'] = IP_PROTOS.get(protocol_num, f"Other({protocol_num})")
            packet_info['Info'] = ''

            if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
                packet_info['Info'] = f"DNS Query: {packet[DNSQR].qname.decode('utf-8')}"
            elif packet.haslayer(TCP):
                packet_info['Info'] = f"Src Port: {packet[TCP].sport} -> Dst Port: {packet[TCP].dport}"
            elif packet.haslayer(UDP):
                packet_info['Info'] = f"Src Port: {packet[UDP].sport} -> Dst Port: {packet[UDP].dport}"

            packet_q.put(packet_info)

    try:
        sniff(prn=process_packet_local, iface=iface_name, stop_filter=lambda p: stop_event.is_set(), store=0)
    except Exception as e:
        print(f"ERROR: Sniffer thread encountered an error: {e}")

# --- Streamlit Dashboard UI ---
st.set_page_config(page_title="Packet Sniffer Dashboard", layout="wide")
st.title("🚀 State of the Art Packet Sniffer")

# Initialize session state
if 'sniffing' not in st.session_state:
    st.session_state.sniffing = False
    st.session_state.packet_queue_instance = queue.Queue()
    st.session_state.start_time = None

# --- Sidebar for Controls ---
with st.sidebar:
    st.header("Sniffer Controls")
    
    available_interfaces = [iface.name for iface in conf.ifaces.values()]
    selected_interface = st.selectbox("Select Interface:", options=available_interfaces, index=available_interfaces.index("WiFi") if "WiFi" in available_interfaces else 0)

    if st.button('Start Sniffing', disabled=st.session_state.sniffing):
        st.session_state.packet_data.clear()
        while not st.session_state.packet_queue_instance.empty():
            st.session_state.packet_queue_instance.get_nowait()
        st.session_state.sniffing = True
        st.session_state.start_time = time.time()
        st.session_state.stop_event = threading.Event()
        st.session_state.thread = threading.Thread(target=run_sniffer, args=(st.session_state.stop_event, selected_interface, st.session_state.packet_queue_instance))
        st.session_state.thread.daemon = True
        st.session_state.thread.start()

    if st.button('Stop Sniffing', disabled=not st.session_state.sniffing):
        if st.session_state.get('stop_event'):
            st.session_state.stop_event.set()
        st.session_state.sniffing = False
    
    st.markdown("---")
    st.subheader("Status")
    if st.session_state.sniffing:
        st.success(f"Running on {selected_interface}")
    else:
        st.error("Stopped")

# --- Main Dashboard Area ---
# Get packets from queue
while not st.session_state.packet_queue_instance.empty():
    st.session_state.packet_data.append(st.session_state.packet_queue_instance.get_nowait())

df = pd.DataFrame(st.session_state.packet_data)

# --- KPI Metrics ---
st.header("Live Capture Summary")
col1, col2, col3 = st.columns(3)
total_packets = len(df)
capture_duration = time.time() - st.session_state.start_time if st.session_state.start_time else 0
packets_per_sec = total_packets / capture_duration if capture_duration > 0 else 0

col1.metric("Total Packets", f"{total_packets}")
col2.metric("Capture Duration (s)", f"{capture_duration:.2f}")
col3.metric("Packets per Second", f"{packets_per_sec:.2f}")

# --- Tabs for Organized Display ---
tab1, tab2 = st.tabs(["📊 Live Packet Feed", "📈 Protocol Analysis"])

with tab1:
    st.subheader("Captured Packets")
    # CHANGED: Added a check to prevent sorting an empty dataframe
    if not df.empty and 'Timestamp' in df.columns:
        st.dataframe(df.tail(200).sort_values(by='Timestamp', ascending=False), use_container_width=True, height=500)
    elif not df.empty:
        st.dataframe(df.tail(200), use_container_width=True, height=500) # Display without sorting if timestamp is missing
    else:
        st.info("No packets captured yet. Start the sniffer to see live data.")


with tab2:
    st.subheader("Protocol Distribution")
    if not df.empty and 'Protocol' in df.columns:
        protocol_counts = df['Protocol'].value_counts()
        st.bar_chart(protocol_counts)
    else:
        st.info("No protocol data to display yet.")

# --- Auto-Refresh Logic ---
if st.session_state.sniffing:
    time.sleep(1)
    st.rerun()