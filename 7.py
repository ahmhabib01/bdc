import zlib
import re
from scapy.all import rdpcap, ICMP

def extract_precise_data(pcap_path="capture.pcap"):
    print("[*] Parsing ICMP variable-length payloads...")
    packets = rdpcap(pcap_path)
    
    # Filter Echo Requests
    reqs = [p for p in packets if p.haslayer(ICMP) and p[ICMP].type == 8]
    
    # Sort packets based on Sequence Number (bytes 2-3 in payload)
    sorted_reqs = []
    for p in reqs:
        load = bytes(p[ICMP].payload)
        if len(load) >= 8 and load[:2] == b'\xde\xad':
            seq = int.from_bytes(load[2:4], 'little')
            data_len = load[6]  # Byte index 6 contains exact data length
            valid_payload = load[8 : 8 + data_len]
            sorted_reqs.append((seq, valid_payload))
            
    sorted_reqs.sort(key=lambda x: x[0])
    
    # Reassemble exact payload stream
    reassembled_data = bytearray()
    for _, chunk in sorted_reqs:
        reassembled_data.extend(chunk)
        
    print(f"[+] Successfully extracted {len(reassembled_data)} bytes of clean payload.")
    
    # Strategy 1: Direct Regex Check
    flag_regex = re.compile(rb'bcsctf\{[^}]+\}', re.IGNORECASE)
    match = flag_regex.search(reassembled_data)
    if match:
        print("\n" + "★" * 50)
        print(f"[🎉] SUCCESS! Direct Flag Found:")
        print(match.group(0).decode('utf-8', errors='ignore'))
        print("★" * 50 + "\n")
        return

    # Strategy 2: Zlib / Deflate Decompression
    print("[*] Attempting zlib / deflate decompression...")
    for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16]:
        try:
            decompressed = zlib.decompress(bytes(reassembled_data), wbits)
            match = flag_regex.search(decompressed)
            if match:
                print("\n" + "★" * 50)
                print(f"[🎉] SUCCESS! Flag found after Decompression:")
                print(match.group(0).decode('utf-8', errors='ignore'))
                print("★" * 50 + "\n")
                return
            else:
                print(f"[+] Decompressed {len(decompressed)} bytes successfully. Content:")
                print(decompressed[:200])
                with open("decompressed_out.bin", "wb") as f:
                    f.write(decompressed)
                return
        except Exception:
            pass

    # Strategy 3: Save clean binary for manual inspection
    with open("clean_extracted.bin", "wb") as f:
        f.write(reassembled_data)
    print("[-] Flag not found in raw form. Clean binary saved as 'clean_extracted.bin'.")

extract_precise_data()
