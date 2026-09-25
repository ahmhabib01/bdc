import re
from scapy.all import rdpcap, ICMP

def ctf_killer(pcap_path="capture.pcap"):
    print("[*] Running Advanced CTF Payload Reassembler...")
    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        print("[-] 'capture.pcap' file not found. Ensure the name is correct.")
        return

    # শুধুমাত্র Echo Requests নিচ্ছি
    reqs = [p for p in packets if p.haslayer(ICMP) and p[ICMP].type == 8]
    
    # [!] CRITICAL FIX: 'de ad' এর পর থাকা কাস্টম Sequence Number অনুযায়ী প্যাকেটগুলো সাজানো
    try:
        reqs.sort(key=lambda x: int.from_bytes(bytes(x[ICMP].payload)[2:4], 'little'))
    except Exception:
        pass

    payloads = [bytes(p[ICMP].payload) for p in reqs]
    flag_regex = re.compile(rb'bcsctf\{[^}]+\}', re.IGNORECASE)

    # পরিচিত ফাইলের ম্যাজিক সিগনেচার (যাতে সরাসরি আনজিপ/ওপেন করা যায়)
    magics = {
        b'\x50\x4b\x03\x04': 'zip',
        b'\x89\x50\x4e\x47': 'png',
        b'\xff\xd8\xff': 'jpg',
        b'\x25\x50\x44\x46': 'pdf',
        b'\x7f\x45\x4c\x46': 'elf',
        b'\x1f\x8b\x08': 'gz'
    }

    found = False
    
    # হেডার ২ থেকে ২০ বাইট পর্যন্ত হতে পারে, সব সম্ভাবনা চেক করা হচ্ছে
    for skip in range(2, 22, 2):
        data = bytearray()
        for pl in payloads:
            if len(pl) > skip:
                data.extend(pl[skip:])
                
        if not data: continue
        
        # ১. প্লেইন টেক্সট ফ্ল্যাগ চেক
        match = flag_regex.search(data)
        if match:
            print(f"\n" + "★" * 50)
            print(f"[+] BINGO! Flag found directly (Skipped {skip} byte custom header):")
            print(match.group(0).decode('utf-8', errors='ignore'))
            print("★" * 50 + "\n")
            found = True
            break
            
        # ২. XOR এনক্রিপশন ব্রুট-ফোর্স (যদি অ্যাটাকার ফাইল এনক্রিপ্ট করে থাকে)
        for key in range(256):
            xored = bytearray([b ^ key for b in data])
            match = flag_regex.search(xored)
            if match:
                print(f"\n" + "★" * 50)
                print(f"[+] BINGO! Flag found (Header: {skip} bytes, XOR Key: {hex(key)}):")
                print(match.group(0).decode('utf-8', errors='ignore'))
                print("★" * 50 + "\n")
                found = True
                break
        if found: break
                
        # ৩. হিডেন ফাইল রিকভারি (ZIP, PNG ইত্যাদি)
        for magic, ext in magics.items():
            if data.startswith(magic):
                print(f"\n[+] SUCCESS! Identified a hidden .{ext} file! (Header Size: {skip} bytes)")
                out_name = f"recovered_secret.{ext}"
                with open(out_name, "wb") as f:
                    f.write(data)
                print(f"[+] The exact exfiltrated file is saved as: {out_name}")
                if ext == 'zip':
                    print(f"[*] Run 'unzip {out_name}' in terminal to get the flag.")
                else:
                    print(f"[*] Open {out_name} to view the flag.")
                found = True
                break
        if found: break

    if not found:
        print("\n[-] Automated extraction didn't find a direct flag or file format.")
        print("[*] Creating raw dumps for manual binwalk analysis...")
        for skip in [4, 6, 8, 10]:
            with open(f"raw_dump_{skip}.bin", "wb") as f:
                f.write(b''.join([pl[skip:] for pl in payloads if len(pl) > skip]))
        print("[*] Use 'binwalk -e raw_dump_*.bin' to check the saved files.")

ctf_killer()
