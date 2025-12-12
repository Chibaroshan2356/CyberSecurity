import streamlit as st
from scapy.all import IP,TCP,UDP,rdpcap,ICMP
import tempfile
import pandas as pd
from collections import Counter,defaultdict


st.set_page_config(page_title="WireShark",layout="wide")


st.title("Network Packect Analyzer: ")


st.write("Please upload the pcap file (.pcap/.pcapng)")




uploaded_file=st.file_uploader(
    "Upload a PCAP file",type=["pcap"]
)


# Lets design packects functions


def load_packects(file_bytes):
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        temp.write(file_bytes)
        temp_path=temp.name
    packets=rdpcap(temp_path)
    return packets


def analyze_packets(packets):
    total_packets=len(packets)
    total_bytes=0
    protocol_counter=Counter()
    src_ip_counter=Counter()
    dst_ip_counter=Counter()
    dst_port_counter=Counter()


    src_to_dst_ports=defaultdict(set)
    src_packet_count=Counter()


    rows=[]


    for pkt in packets:
        total_bytes +=len(pkt)
        src_ip=dst_ip=proto_name="-"
        sport=dport=None


        if IP in pkt:
            ip=pkt[IP]
            src_ip=ip.src
            dst_ip=ip.dst
            src_ip_counter[src_ip]+=1
            dst_ip_counter[dst_ip]+=1
            src_packet_count[src_ip]+=1


            if TCP in pkt:
                proto_name="TCP"
                sport=pkt[TCP].sport
                dport=pkt[TCP].dport


                protocol_counter["TCP"]+=1
                dst_ip_counter[dport]+=1
                src_to_dst_ports[src_ip].add(dport)
            elif UDP in pkt:
                proto_name="UDP"
                sport=pkt[UDP].sport
                dport=pkt[UDP].dport
                protocol_counter["UDP"]+=1
                dst_port_counter[dport]+=1
                src_to_dst_ports[src_ip].add(dport)


            elif ICMP in pkt:
                proto_name="ICMP"
                protocol_counter["ICMP"]+=1
            else:
                proto_name=f"Other" ({ip.proto})
                protocol_counter["Other"]+=1
       
        else:
            protocol_counter["Non-Ip"]+=1


        rows.append(
            {
                "Source IP":src_ip,
                "Destination IP":dst_ip,
                "Protocol":proto_name,
                "Src Port":sport,
                "Dst Port":dport,
                "Length":len(pkt),
            }
        )


    df=pd.DataFrame(rows)


    stats={
            "total_packects":total_packets,
            "total_bytes":total_bytes,
            "proto_counter":protocol_counter,
            "Src_Ip_counter":src_ip_counter,
            "Dst_Ip_counter":dst_ip_counter,
            "Dst_port_counter":dst_port_counter,
            "Src_to_dst_ports":src_to_dst_ports,
            "src_packect_count":src_packet_count,
            "df":df,
    }


    return stats


def detect_suspicious(stats):
    alerts=[]


    src_packect_count=stats["src_packect_count"]
    src_to_dst_ports=stats["Src_to_dst_ports"]


    for src,count in src_packect_count.items():
        if count>200:
            alerts.append(
                f"High Traficc {src} {count} packets Possibily of DOS and requires Scan"
            )
    for src,ports in src_to_dst_ports.items():
        if len(ports)>30:
            alerts.append(
                f"{src} Connects Many different destination ports ({len(ports)}) ports"
            )
    if not alerts:
        alerts.append("No obvious suspicious patterns. SAFE")
    return alerts




#--- MAIN  LOGIC ---#


if uploaded_file is not None:
    st.success("File uploaded successfully")


    with st.spinner("Reading And analysing packects"):
        file_bytes=uploaded_file.read()
        packets=load_packects(file_bytes)
        stats=analyze_packets(packets)
        alerts=detect_suspicious(stats)


    df=stats["df"]




    # CREATING TABLE


    col1,col2,col3=st.columns(3)


    col1.metric("Total Packets",stats["total_packects"])
    col2.metric("Total Bytes",stats["total_bytes"])


    avg_len=(
        stats["total_bytes"]//stats["total_packects"]
        if stats["total_packects"]>0
        else 0
    )
    col3.metric("Avg Packect Size(bytes)",avg_len)


    st.markdown("---")
   
    #Protocol Section
    st.subheader("Protocol Types: ")
    proto_df=pd.DataFrame.from_dict(
        stats["proto_counter"],orient="index",columns=["Count"]
    )
    proto_df=proto_df.sort_values("Count",ascending=False)




else:
    st.info("Please upload a .pcap or .pcapng file")