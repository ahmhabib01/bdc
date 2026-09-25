import re
from scapy.all import IP, ICMP, Raw, rdpcap

def deep_icmp_analyze(pcap_path="capture.pcap"):
    print("[*] Running Deep ICMP Analysis...")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[-] File load error: {e}")
        return

    lengths = bytearray()
    ip_ids = bytearray()
    offset_8 = bytearray()
    offset_16 = bytearray()

    for pkt in packets:
        # শুধুমাত্র ICMP Echo Request (type 8) চেক করা হবে
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            
            # ১. IP ID ফিল্ড চেক
            if pkt.haslayer(IP):
                ip_ids.append(pkt[IP].id & 0xFF)  # Lower byte of IP ID
                
            # ২. Payload Length এবং Offset চেক
            if pkt.haslayer(Raw):
                load = pkt[Raw].load
                
                # Length Based Exfiltration (প্যাকেটের সাইজ = ASCII Character)
                # অনেক সময় Length এর সাথে অতিরিক্ত কিছু ডেটা থাকে, তাই 256 দিয়ে মডিউলাস করা হয়
                lengths.append(len(load) % 256)
                
                # Offset Based Exfiltration (প্রথম ৮/১৬ বাইট লিনাক্স টাইমস্ট্যাম্প স্কিপ করে)
                if len(load) > 8:
                    offset_8.append(load[8])
                if len(load) > 16:
                    offset_16.append(load[16])

    candidates = {
        "Packet Length (Data Size)": lengths,
        "IP Identification Field": ip_ids,
        "Payload Data (Offset 8)": offset_8,
        "Payload Data (Offset 16)": offset_16
    }

    flag_regex = re.compile(rb"bcsctf\{[^}]+\}", re.IGNORECASE)
    found = False

    for method_name, data in candidates.items():
        match = flag_regex.search(data)
        if match:
            print("\n" + "★" * 50)
            print(f"[🎉] SUCCESS! Data was exfiltrated via: {method_name}")
            print(f"[+] FLAG: {match.group(0).decode('utf-8', errors='ignore')}")
            print("★" * 50 + "\n")
            found = True
            break

    if not found:
        print("\n[-] Exact flag structure not found. Printing printable strings from all methods:")
        for method_name, data in candidates.items():
            printable = "".join(chr(b) for b in data if 32 <= b <= 126)
            if len(printable) > 10:
                print(f"\n--- From {method_name} ---")
                print(printable[:150])

deep_icmp_analyze()
