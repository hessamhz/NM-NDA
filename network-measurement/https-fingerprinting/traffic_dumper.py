import pandas as pd
import numpy as np
import pyshark 


# Create a LiveCapture object
cap = pyshark.LiveCapture(interface='eno1') #, bpf_filter="tcp or dns or http or ssl or tls")

# Create an empty list to store the captured packets
packet_list = []
url = "https://www.nypost.com"
url_name = "nypost"



# Start capturing packets
for packet in cap.sniff_continuously():
    
    # Check if the packet is a TCP packet and has an IP layer
    if 'ip' in packet:

        packet_dict = {}

        # Extract the fields of the IP layer
        ip_layer = packet['ip']
        packet_dict['ip.src'] = ip_layer.src
        packet_dict['ip.dst'] = ip_layer.dst
        packet_dict['ip.proto'] = ip_layer.proto

        packet_dict['highest_layer'] = packet.highest_layer
        packet_dict['length'] = packet.length
        packet_dict['number'] = packet.number
        packet_dict['sniff_time'] = packet.sniff_time
        packet_dict['sniff_timestamp'] = packet.sniff_timestamp

        if 'dns' in packet:
            dns_layer = packet['dns']
            packet_dict['dns.id'] = dns_layer.id
            packet_dict['dns.flags.response'] = dns_layer.flags_response
            packet_dict['dns.qry.name'] = dns_layer.qry_name
            try: 
                packet_dict['dns.resp.name'] = dns_layer.resp_name
            except:
                packet_dict['dns.resp.name'] = ""
            packet_dict['dns.qry.type'] = dns_layer.qry_type
            packet_dict['dns.qry.class'] = dns_layer.qry_class
            packet_dict['dns.count.queries'] = dns_layer.count_queries
            packet_dict['dns.count.answers'] = dns_layer.count_answers
            packet_dict['dns.count.authority'] = dns_layer.count_auth_rr
            packet_list.append(packet_dict)
            df = pd.DataFrame(packet_list)
            df.to_csv(f"da_{url_name}.csv")
            continue


        if 'tcp' in packet:
            # Extract the fields of the TCP layer
            tcp_layer = packet['tcp']
            packet_dict['tcp.srcport'] = tcp_layer.srcport
            packet_dict['tcp.dstport'] = tcp_layer.dstport
            packet_dict['tcp.flags'] = tcp_layer.flags
            packet_dict['tcp.seq'] = tcp_layer.seq
            packet_dict['tcp.ack'] = tcp_layer.ack

        if 'tls' in packet:
            tls_layer = packet['tls']
            packet_dict['tls'] = str(tls_layer)

            packet_list.append(packet_dict)
            df = pd.DataFrame(packet_list)
            df.to_csv(f"da_{url_name}.csv")
cap.close()

