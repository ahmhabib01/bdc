import re
from scapy.all import ICMP, rdpcap


def solve_final_clean():
  print("[*] Slicing exact payload lengths and removing ICMP padding...")
  try:
    pkts = rdpcap("capture.pcap")
  except FileNotFoundError:
    print("[-] capture.pcap file not found!")
    return

  # Filter Echo Requests starting with magic bytes 'de ad'
  reqs = [
      p
      for p in pkts
      if p.haslayer(ICMP)
      and p[ICMP].type == 8
      and bytes(p[ICMP].payload)[:2] == b"\xde\xad"
  ]

  extracted_chunks = []
  for p in reqs:
    load = bytes(p[ICMP].payload)
    if len(load) >= 8:
      # Chunk Index (bytes 4-5) & Data Length (byte 6)
      chunk_idx = int.from_bytes(load[4:6], "little")
      data_len = load[6]

      # Slice ONLY the valid payload, stripping trailing ICMP garbage padding
      valid_bytes = load[8 : 8 + data_len]
      extracted_chunks.append((chunk_idx, valid_bytes))

  # Sort chunks in exact order
  extracted_chunks.sort(key=lambda x: x[0])
  clean_data = b"".join(chunk for idx, chunk in extracted_chunks)

  print(f"[+] Clean payload assembled without padding: {len(clean_data)} bytes\n")

  # 1. Plaintext Check
  flag_match = re.search(rb"bcsctf\{[^}]+\}", clean_data, re.IGNORECASE)
  if flag_match:
    print("★" * 55)
    print("[🎉] PERFECT FLAG FOUND!")
    print(f"[+] FLAG: {flag_match.group(0).decode('utf-8', errors='ignore')}")
    print("★" * 55 + "\n")
    return

  # 2. XOR Check
  for key in range(256):
    xored = bytes([b ^ key for b in clean_data])
    flag_match = re.search(rb"bcsctf\{[^}]+\}", xored, re.IGNORECASE)
    if flag_match:
      print("★" * 55)
      print(f"[🎉] PERFECT FLAG FOUND WITH XOR KEY ({hex(key)})!")
      print(f"[+] FLAG: {flag_match.group(0).decode('utf-8', errors='ignore')}")
      print("★" * 55 + "\n")
      return

  print("[*] Raw Clean Stream:")
  print(clean_data.decode("utf-8", errors="ignore"))


solve_final_clean()
