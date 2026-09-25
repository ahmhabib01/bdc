import os
from scapy.all import ICMP, rdpcap

def extract_icmp_file(pcap_path="capture.pcap"): # capture.pcap এর জায়গায় আপনার ফাইলের নাম দিন
    print("[*] Reading PCAP file...")
    packets = rdpcap(pcap_path)
    seq_payloads = {}

    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8: # শুধুমাত্র ICMP Echo Request
            seq = pkt[ICMP].seq
            payload = bytes(pkt[ICMP].payload)
            
            # Linux Ping সাধারণত প্রথম ৮ বা ১৬ বাইটে Timestamp পাঠায়। সেটি বাদ দিয়ে মূল ডেটা নেওয়া হচ্ছে।
            if len(payload) > 8 and not payload[:4].isascii():
                seq_payloads[seq] = payload[8:]
            else:
                seq_payloads[seq] = payload

    # প্যাকেটগুলো সঠিক অর্ডারে সাজিয়ে জোড়া লাগানো
    sorted_data = bytearray()
    for seq in sorted(seq_payloads.keys()):
        sorted_data.extend(seq_payloads[seq])

    # বাইনারি ফাইলে সেভ করা
    output_filename = "extracted_file.bin"
    with open(output_filename, "wb") as f:
        f.write(sorted_data)
    
    print(f"[+] File successfully reconstructed and saved to '{output_filename}'")

extract_icmp_file()
