import argparse

def main():
    # adding the filteration requirements
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--pcap_file', type=str, help='Path to the PCAP file', required=True)
    parser.add_argument('-c', '--count', type=int, help='Limit the number of packets to be analyzed')
    parser.add_argument('--host', type=str, help='Host IP address')
    parser.add_argument('--port', type=int, help='Port number')
    parser.add_argument('--protocol', type=str, help='Protocol (tcp, udp, icmp, etc.)')

    # Parse the command line arguments
    args = parser.parse_args()
    print("These are arguments", args)
    # open file to read pcap data
    with open("today.pcap", "rb") as file:
        magic_number = file.read(4)
        version_major = file.read(2)
        version_minor = file.read(2)
        time_zone = file.read(4)
        timestamp_accuracy = file.read( 4)
        snap_length = file.read(4)
        link_layer_type = file.read(4)
        

        count = 0
        while True:
    
            flag = True
            # parsing the global data
            timestamp_seconds = file.read(4)
            if timestamp_seconds == b'':
                break
            timestamp_microseconds = file.read(4)
            captured_length = file.read(4)
            captured_length = int.from_bytes(captured_length, "little")
            original_length = file.read(4)
            original_length = int.from_bytes(original_length, "little")

            # parsing ether data
            packet_data = file.read(captured_length)
            destination_address = packet_data[0:6]
            ip_ether_hex = ':'.join([format(b, 'x') for b in destination_address])
            source_address = packet_data[6:12]
            ip_src_ether_hex = ':'.join([format(b, 'x') for b in source_address])
            ether_type = packet_data[12:14]
            hex_ether_type = ''.join('{:02x}'.format(byte) for byte in ether_type)
            
            
            # parsing ip data
            version_internet_head = packet_data[14]
            version = (version_internet_head & 0b11110000) >> 4
            header_length = (version_internet_head & 0b00001111) * 4
            type_of_service = packet_data[15]
            precedence = type_of_service >> 5
            delay = (type_of_service & 16) >> 4
            throughput = (type_of_service & 8) >> 3
            reliability = (type_of_service & 4) >> 2
            total_length = packet_data[16:18]
            int_total_len = int.from_bytes(total_length, 'big')
            identification = packet_data[18:20]
            int_identification = int.from_bytes(identification, 'big')
            flags = packet_data[20:21]
            hexadecimal_flags = int.from_bytes(flags, byteorder='big')
            dont_fragment = (hexadecimal_flags & 2**6) == 0
            more_fragment = (hexadecimal_flags & 2**5) == 0
            fragment_offset = packet_data[21:22]
            int_fragment_offset= int.from_bytes(fragment_offset, 'big')
            ttl = packet_data[22]
            protocol = packet_data[23]
            header_checksum = packet_data[24:26]
            int_header_checksum = int.from_bytes(header_checksum, 'big')
            hex_header_checksum = hex(int_header_checksum)
            source_address_ip = packet_data[26:30]
            decimal = 0
            for i in range(len(source_address_ip)):
                decimal = decimal * 256 + source_address_ip[i]
            ip_address = '.'.join([str(decimal >> (i * 8) & 0xff) for i in range(4)[::-1]])
            destination_address_ip = packet_data[30:34]
            ip_dec = ".".join(str(byte) for byte in destination_address_ip)
            
            # adding filtering condition of host
            if args.host is not None and (args.host != ip_dec or args.host != ip_address):
                flag =False
            
            # adding filteration condition for protocol
            if protocol == 6 and ((args.protocol is not None and args.protocol == 'tcp') or( args.protocol is None)):
                # if conditions true print and compute 
                source_port = packet_data[34:36]
                int_source_port = int.from_bytes(source_port, 'big')
                destination_port = packet_data[36:38]
                int_dest_port = int.from_bytes(destination_port, 'big')
                sequence_number = packet_data[38:42]
                int_seq_num = int.from_bytes(sequence_number, 'big')
                acknowledgement_number = packet_data[42:46]
                int_ack_num = int.from_bytes(acknowledgement_number, 'big')
                data_offset = packet_data[46]
                tcp_flags = packet_data[47:49]
                flags = tcp_flags[0]
                flag_bits = bin(flags)[2:].zfill(8)
                
                window = packet_data[49:51]
                int_window = int.from_bytes(window, 'big')
                checksum = packet_data[51:53]
                int_tcp_checksum = int.from_bytes(checksum, 'big')
                hex_tcp_checksum = hex(int_tcp_checksum)
                urgent_pointer = packet_data[53:55]
                int_urgent = int.from_bytes(urgent_pointer, 'big')
                # adding filteration condition for port and count
                if args.port is not None and args.port != source_port and args.port != destination_port:
                    flag = False
                # adding filter for count 
                if args.count is not None and args.count<1:
                    flag = False
                
                # if conditions true print and compute 
                if flag:
                    print("ETHER: -----Ether Header-----")
                    print("ETHER:")
                    print("ETHER: Packet size =", captured_length, "bytes")
                    print("ETHER: Destination =", ip_ether_hex)
                    print("ETHER: Source      =", ip_src_ether_hex)
                    print("ETHER: Ethertype   =", hex_ether_type, "(IP)")
                    print("ETHER:")
                    print("")
                    print("IP:  ----IP Header----")
                    print("IP:")
                    print("IP: Version     =", version)
                    print("IP: Header length =", header_length, "bytes")
                    print("IP: Type of service =", type_of_service  )
                    
                    if precedence == 0:
                        print("IP: XXX. .... = ",str(precedence)," (precedence)" )
                    else:
                        print("IP: XXX. .... = ",str(precedence)," (precedence)" )
                    
                    if delay == 0:
                        print("IP: ...",str(delay)," .... = normal delay" )
                    else:
                        print("IP: ...",str(delay)," .... = low delay" )

                    if throughput == 0:
                        print("IP: .... ",str(throughput),"... = normal throughput")
                    else:
                        print("IP: .... ",str(throughput),"... = high throughput")

                    if reliability == 0:
                        print("IP: .... .",str(reliability),".. = normal reliability")
                    else:
                        print("IP: .... .",str(reliability),".. = high reliability")
                    
                    print("IP: Total length =", int_total_len, "bytes")
                    print("IP: Identification =", int_identification)
                    print("IP: Flags = 0x{:x}".format(hexadecimal_flags))
                    print("IP: .0.. .... = don't fragment" if dont_fragment else "IP: .1.. .... = fragment")
                    print("IP: ..0. .... = More fragment" if more_fragment else "IP: ..1. .... = Last fragment")
                    
                    print("IP: fragment_offset =", int_fragment_offset)
                    print("IP: Time to live =", str(ttl), " seconds/hops")
                    if protocol == 17:
                        print("IP: Protocol = ",protocol,"(UDP)")
                    if protocol == 6:
                        print("IP: Protocol = ",protocol,"(TCP)")
                    if protocol == 1:
                        print("IP: Protocol = ",protocol,"(ICMP)")
                    print("IP: Header checksum = ", hex_header_checksum)
                    print("IP: Source Address =", ip_address)
                    print("IP: Destination Address =", ip_dec)
                    print("")
                    print("TCP: ----- TCP Header -----")
                    print("TCP: ")
                    print("TCP: Source port = " ,int_source_port )
                    print("TCP: Destination port = ",int_dest_port)
                    print("TCP: Sequence number = ", int_seq_num)
                    print("TCP: Acknowledgement number = ", int_ack_num )
                    print("TCP: Data offset = ",data_offset," bytes")
                    print("TCP: Flags = 0x{:x}".format(flags))
                    print("TCP: ..{0}. .... = No urgent pointer".format(flag_bits[0]))
                    print("TCP: ...{0} .... = Acknowledgement".format(flag_bits[1]))
                    print("TCP: .... {0}... = Push".format(flag_bits[2]))
                    print("TCP: .... .{0}.. = No reset".format(flag_bits[3]))
                    print("TCP: ..... ..{0}. = No Syn".format(flag_bits[4]))
                    print("TCP: .... ...{0} = No Fin".format(flag_bits[5]))
                    print("TCP: Window = ", int_window)
                    print("TCP: Checksum = ",hex_tcp_checksum)
                    print("TCP: Urgent pointer = ", int_urgent )
                    print("TCP: No options")
                    print("")
            # if data packet is UDP, parsing the header and adding the filter for protocol
            if protocol == 17 and ((args.protocol is not None and args.protocol == 'udp') or( args.protocol is None)):
                udp_source_port = packet_data[34:36]
                int_udp_src_port = int.from_bytes(udp_source_port, 'big')
                udp_dest_port = packet_data[36:38]
                int_udp_dest = int.from_bytes(udp_dest_port, 'big')
                udp_len = packet_data[38:40]
                int_udp_len = int.from_bytes(udp_len, 'big')
                udp_checksum = packet_data[40:42]
                int_udp_checksum = int.from_bytes(udp_checksum, 'big')
                hex_udp_checksum = hex(int_udp_checksum)
                
                if args.port is not None and args.port != int_udp_src_port and args.port != int_udp_dest:
                    flag = False
                
                if args.count is not None and args.count<1:
                    flag = False
                
                if flag:
                    # if conditions true print and compute 
                    print("ETHER: -----Ether Header-----")
                    print("ETHER:")
                    print("ETHER: Packet size =", captured_length, "bytes")
                    print("ETHER: Destination =", ip_ether_hex)
                    print("ETHER: Source      =", ip_src_ether_hex)
                    print("ETHER: Ethertype   =", hex_ether_type, "(IP)")
                    print("ETHER:")
                    print("")
                    print("IP: ----IP Header----")
                    print("IP:")
                    print("IP: Version     =", version)
                    print("IP: Header length =", header_length, "bytes")
                    print("IP: Type of service =", type_of_service  )
                    
                    if precedence == 0:
                        print("IP: XXX. .... = ",str(precedence)," (precedence)" )
                    else:
                        print("IP: XXX. .... = ",str(precedence)," (precedence)" )
                    
                    if delay == 0:
                        print("IP: ...",str(delay)," .... = normal delay" )
                    else:
                        print("IP: ...",str(delay)," .... = low delay" )

                    if throughput == 0:
                        print("IP: .... ",str(throughput),"... = normal throughput")
                    else:
                        print("IP: .... ",str(throughput),"... = high throughput")

                    if reliability == 0:
                        print("IP: .... .",str(reliability),".. = normal reliability")
                    else:
                        print("IP: .... .",str(reliability),".. = high reliability")
                    
                    print("IP: Total length =", int_total_len, "bytes")
                    print("IP: Identification =", int_identification)
                    print("IP: Flags = 0x{:x}".format(hexadecimal_flags))
                    print("IP: .0.. .... = don't fragment" if dont_fragment else "IP: .1.. .... = fragment")
                    print("IP: ..0. .... = More fragment" if more_fragment else "IP: ..1. .... = Last fragment")
                    print("IP: fragment_offset =", int_fragment_offset)
                    print("IP: Time to live =", str(ttl)," seconds/hops")
                    if protocol == 17:
                        print("IP: Protocol = ",protocol,"(UDP)")
                    if protocol == 6:
                        print("IP: Protocol = ",protocol,"(TCP)")
                    if protocol == 1:
                        print("IP: Protocol = ",protocol,"(ICMP)")
                    print("IP: Header checksum = ", hex_header_checksum)
                    print("IP: Source Address =", ip_address)
                    print("IP: Destination Address =", ip_dec)
                    print("")
                    print("UDP: ----- UDP Header -----")
                    print("UDP:")
                    print("UDP: Source port = ", int_udp_src_port )
                    print("UDP: Destination port = ", int_udp_dest)
                    print("UDP: Length = ", int_udp_len)
                    print("UDP: Checksum = ", hex_udp_checksum)
            
            # if the data packet is udp, parsing and adding filteration for protocol
            if protocol ==1 and ((args.protocol is not None and args.protocol == 'icmp') or( args.protocol is None)):
                icmp_type = packet_data[34]
                icmp_code = packet_data[35]
                icmp_checksum = packet_data[36:38]
                int_icmp_checksum = int.from_bytes(icmp_checksum, 'big')
                hex_icmp_checksum = hex(int_icmp_checksum)
                # adding filter for count
                if args.count is not None and args.count<1:
                    flag = False
                if flag:
                    # if conditions true print and compute 
                    print("ETHER: -----Ether Header-----")
                    print("ETHER:")
                    print("ETHER: Packet size =", captured_length, "bytes")
                    print("ETHER: Destination =", ip_ether_hex)
                    print("ETHER: Source      =", ip_src_ether_hex)
                    print("ETHER: Ethertype   =", hex_ether_type, "(IP)")
                    print("ETHER:")
                    print("")
                    print("IP: ----IP Header----")
                    print("IP:")
                    print("IP: Version     =", version)
                    print("IP: Header length =", header_length, "bytes")
                    print("IP: Type of service =", type_of_service  )
                    if precedence == 0:
                        print("IP: XXX. .... = ",str(precedence)," (precedence)" )
                    else:
                        print("IP: XXX. .... = ",str(precedence)," (precedence)" )
                    
                    if delay == 0:
                        print("IP: ...",str(delay)," .... = normal delay" )
                    else:
                        print("IP: ...",str(delay)," .... = low delay" )

                    if throughput == 0:
                        print("IP: .... ",str(throughput),"... = normal throughput")
                    else:
                        print("IP: .... ",str(throughput),"... = high throughput")

                    if reliability == 0:
                        print("IP: .... .",str(reliability),".. = normal reliability")
                    else:
                        print("IP: .... .",str(reliability),".. = high reliability")
                    
                    print("IP: Total length =", int_total_len, "bytes")
                    print("IP: Identification =", int_identification)
                    print("IP: Flags = 0x{:x}".format(hexadecimal_flags))
                    print("IP: .0.. .... = don't fragment" if dont_fragment else "IP: .1.. .... = fragment")
                    print("IP: ..0. .... = More fragment" if more_fragment else "IP: ..1. .... = Last fragment")
                    print("IP: fragment_offset =", int_fragment_offset)
                    print("IP: Time to live =", str(ttl), "seconds/hops")
                    if protocol == 17:
                        print("IP: Protocol = ",protocol,"(UDP)")
                    if protocol == 6:
                        print("IP: Protocol = ",protocol,"(TCP)")
                    if protocol == 1:
                        print("IP: Protocol = ",protocol,"(ICMP)")
                    print("IP: Header checksum = ", hex_header_checksum)
                    print("IP: Source Address =", ip_address)
                    print("IP: Destination Address =", ip_dec)
                    print("")
                    print("ICMP: ----- ICMP Header -----")
                    print("ICMP:")
                    print("ICMP: Type = ", icmp_type)
                    print("ICMP: Code = " , icmp_code)
                    print("ICMP: Checksum = ",hex_icmp_checksum )
                    print("ICMP: ")
                    
                    
            if args.count is not None:
                args.count  -=1
                    

        

        print("after reading packet:", count - 1)


if __name__ == '__main__':
    main()
