# Here is a simple Python script that uses the scapy library to analyze network traffic:

This script defines a function analyze_packet that takes a packet as input and extracts various information such as source and destination IP addresses, source and destination ports, protocol, and raw data if available. It then prints this information for each packet.

The main function uses the sniff function from scapy to start capturing network traffic. It specifies the prn parameter as the analyze_packet function, which is called for each captured packet.

To run this script, make sure you have the scapy library installed (pip install scapy) and run it with administrative privileges to allow packet capture.

Note: Running this script on a live network can be dangerous, as it can potentially capture sensitive information. It's recommended to use it on a network you have permission to monitor and analyze.
