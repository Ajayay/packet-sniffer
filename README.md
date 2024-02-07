Introduction:

This project contains a Python script packetAnalyzer.py that reads packets from a .pcap file and produces a detailed summary of those packets. It works like tcpdump and Wireshark combined, and runs as a shell command. The program first reads packets from a specified file, then extracts and displays the different headers of the captured packets, specifically the Ethernet header fields, the IP header, and the packets encapsulated in the IP datagram.

Requirements:

Python 3.x

Usage:

Open a terminal or command prompt and navigate to the directory containing the source code.
Run the following command to execute the script:

usage: packetAnalyzer.py [-h] -r PCAP_FILE [-c COUNT] [--host HOST] [--port PORT] [--protocol PROTOCOL]


where:

-r PCAP_FILE, --pcap_file PCAP_FILE: Required argument to specify the .pcap file to be analyzed.
-c COUNT, --count COUNT: Optional argument to limit the number of packets to be analyzed.
--host HOST: Optional argument to filter packets by host.
--port PORT: Optional argument to filter packets by port.
--protocol PROTOCOL: Optional argument to filter packets by protocol (tcp, udp, or icmp).

Note: 

1.If the required argument -r PCAP_FILE is not provided, the script will return the following error:
	packetAnalyzer.py: error: the following arguments are required: -r/--pcap_file

2. give all the input in lowercase
