from scapy.all import rdpcap, ICMP

def dump_first_packets(pcap_path="capture.pcap"):
    print(f"[*] Loading {pcap_path}...")
    packets = rdpcap(pcap_path)
    
    # শুধুমাত্র Echo Requests ফিল্টার করা এবং Sequence Number অনুযায়ী সাজানো
    reqs = [p for p in packets if p.haslayer(ICMP) and p[ICMP].type == 8]
    reqs.sort(key=lambda x: x[ICMP].seq)
    
    print("\n[*] Hex Dump of the first 3 sorted packets:")
    for i in range(min(3, len(reqs))):
        load = bytes(reqs[i][ICMP].payload)
        seq = reqs[i][ICMP].seq
        print(f"\n--- Packet {i+1} (Seq: {seq}, Payload Length: {len(load)}) ---")
        
        # Hex ফরম্যাটে সুন্দর করে প্রিন্ট করা
        hex_chunks = [load[j:j+16].hex(" ") for j in range(0, len(load), 16)]
        ascii_chunks = ["".join(chr(b) if 32 <= b <= 126 else "." for b in load[j:j+16]) for j in range(0, len(load), 16)]
        
        for h, a in zip(hex_chunks, ascii_chunks):
            print(f"{h:<48} | {a}")

dump_first_packets()
