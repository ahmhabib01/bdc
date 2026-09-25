import os
import re
import base64
from scapy.all import *

print("[*] Running Ultimate ICMP CTF Solver...")

# Read PCAP and filter ONLY Echo Requests (Type 8) to avoid Request/Reply duplication
packets = rdpcap('ch.pcapng')
requests = [p for p in packets if ICMP in p and p[ICMP].type == 8]
if not requests:
    requests = [p for p in packets if ICMP in p]

payloads = [bytes(p[ICMP].payload) for p in requests if p[ICMP].payload]
flag_regex = re.compile(b'bcsctf{.*?}', re.IGNORECASE)

def check_flag(data, context):
    matches = flag_regex.findall(data)
    if matches:
        print(f"\n[+] FLAG FOUND IN {context}:")
        for m in matches:
            print("=>", m.decode('utf-8', errors='ignore'))
        return True
    return False

# 1. Vertical Offsets (Decoding Base64 / Base85)
print("[*] Checking vertical columns (1 byte per packet)...")
if payloads:
    min_len = min(len(pl) for pl in payloads)
    for i in range(min_len):
        col_bytes = bytes([pl[i] for pl in payloads])
        if check_flag(col_bytes, f"Offset {i}"): continue
        
        # Strip non-printable and attempt decoding
        clean_col = b"".join([bytes([b]) for b in col_bytes if 32 <= b <= 126])
        if len(clean_col) > 10:
            try: check_flag(base64.b64decode(clean_col + b"==="), f"Base64 Offset {i}")
            except: pass
            try: check_flag(base64.b85decode(clean_col), f"Base85 (b85) Offset {i}")
            except: pass
            try: check_flag(base64.a85decode(clean_col), f"Ascii85 (a85) Offset {i}")
            except: pass

# 2. Check ICMP Headers
print("[*] Checking ICMP Headers (TTL, Sequence)...")
ttls = bytes([p[IP].ttl for p in requests if IP in p])
check_flag(ttls, "TTLs")
seqs = bytes([p[ICMP].seq % 256 for p in requests])
check_flag(seqs, "Sequence Numbers")

# 3. Horizontal Reassembly (Skipping timestamps)
print("[*] Reassembling payload data to check for hidden files...")
for skip in [0, 8, 16]:
    extracted = b"".join([pl[skip:] for pl in payloads])
    if check_flag(extracted, f"Reassembled Data (Skip {skip})"): continue
    
    no_nulls = extracted.replace(b'\x00', b'')
    if check_flag(no_nulls, f"Reassembled Data without nulls (Skip {skip})"): continue
    
    # Save cleanly to disk
    with open(f"extracted_skip{skip}.bin", 'wb') as f:
        f.write(extracted)
    with open(f"extracted_skip{skip}_nonull.bin", 'wb') as f:
        f.write(no_nulls)

print("\n[*] File types of carved payloads:")
os.system("file extracted_skip*.bin")
print("\n[*] Done! If a file above says 'Zip archive' or 'PNG image', unzip/open it to get your flag.")
