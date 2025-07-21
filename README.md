# Packet_Sniffer
Packet Sniffer
Real-Time Network Traffic Analyzer

1. Project Overview

This project is a Python-based network packet sniffer and real-time traffic analyzer. It captures live network packets and presents the data in an interactive web-based dashboard. The primary goal is to provide an intuitive tool for network monitoring and security analysis, demonstrating practical skills in network programming, data visualization, and cybersecurity principles.

This tool moves beyond basic packet capture by providing high-level metrics, protocol distribution analysis, and DNS query resolution, making it a valuable asset for identifying network anomalies and understanding traffic patterns.

2. Features

    Live Packet Capture: Sniffs network packets in real-time on a selected network interface.

    Interactive Dashboard: A user-friendly web UI built with Streamlit for data presentation.

    Real-Time Metrics: Displays key performance indicators (KPIs) such as Total Packets Captured, Capture Duration, and Packets per Second.

    Protocol Analysis: Automatically identifies and visualizes the distribution of common protocols (TCP, UDP, ICMP).

    DNS Query Resolution: Extracts and displays domain names from DNS queries to monitor web traffic.

    Clean, Organized UI: Uses a sidebar for controls and tabs for different data views to maintain a professional and uncluttered user experience.

3. Technical Stack

    Language: Python

    Core Libraries:

        Scapy: For packet sniffing and manipulation.

        Streamlit: For building the interactive web dashboard.

        Pandas: For data handling and analysis.

    Packet Driver: Requires Npcap on Windows (or libpcap on Linux/macOS) for packet capture.

4. Setup and Usage

Prerequisites:

    Python 3.8+

    Npcap (for Windows users), installed with "WinPcap API-compatible Mode" enabled.

Instructions:

    Clone the repository or download the project files into a single folder.

    Run the startup script: Simply double-click the start.bat file. This script will automatically:

        Create a Python virtual environment.

        Install all required dependencies from requirements.txt.

        Launch the Streamlit application.

    Open your browser: The application will open in your default web browser at http://localhost:8501.

    Run with Administrator privileges: For the script to capture packets, you may need to run start.bat as an administrator.

5. Cybersecurity Industry Relevance

This project directly demonstrates skills applicable to several cybersecurity domains and aligns with industry best practices.
NIST Cybersecurity Framework Alignment

The features of this tool map directly to the NIST Cybersecurity Framework:

    Identify (ID.AM): By allowing the user to select and monitor specific network interfaces, the tool assists in identifying and managing assets on the network.

    Detect (DE.AE): This is the primary function. The tool continuously monitors network traffic to detect anomalies and potential security events, such as unusual protocol distributions or suspicious DNS lookups.

    Respond (RS.AN): While not an automated response tool, the data gathered (e.g., source IP of an anomaly) provides the critical information needed for security analysts to begin an investigation and response process.
