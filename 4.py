import re
from scapy.all import ICMP, Raw, rdpcap


def extract_icmp_data(pcap_path="capture.pcap"):
  print(f"[*] Analyzing {pcap_path}...")
  try:
    packets = rdpcap(pcap_path)
  except Exception as e:
    print(f"[-] Error loading pcap: {e}")
    return

  all_payloads_req = []
  all_payloads_rep = []
  single_bytes_req = []
  single_bytes_rep = []

  for pkt in packets:
    if pkt.haslayer(ICMP):
      icmp_layer = pkt[ICMP]
      # RAW payload check
      if pkt.haslayer(Raw):
        raw_data = pkt[Raw].load

        # ICMP Request (Type 8)
        if icmp_layer.type == 8:
          all_payloads_req.append(raw_data)
          if len(raw_data) > 0:
            single_bytes_req.append(raw_data[-1:])  # Last byte

        # ICMP Reply (Type 0)
        elif icmp_layer.type == 0:
          all_payloads_rep.append(raw_data)
          if len(raw_data) > 0:
            single_bytes_rep.append(raw_data[-1:])  # Last byte

  # Combine strategies
  candidates = [
      ("Full Request Payload Concatenation", b"".join(all_payloads_req)),
      ("Full Reply Payload Concatenation", b"".join(all_payloads_rep)),
      ("Last Byte of Requests", b"".join(single_bytes_req)),
      ("Last Byte of Replies", b"".join(single_bytes_rep)),
  ]

  # Flag Pattern Search
  flag_pattern = re.compile(rb"bcsctf\{[^}]+\}", re.IGNORECASE)

  found = False
  for desc, data_bytes in candidates:
    match = flag_pattern.search(data_bytes)
    if match:
      print("\n" + "★" * 50)
      print(f"[🎉] SUCCESS! Found Flag via: {desc}")
      print(f"[+] FLAG: {match.group(0).decode('utf-8', errors='ignore')}")
      print("★" * 50 + "\n")
      found = True
      break

  if not found:
    print(
        "\n[-] Exact flag string (bcsctf{...}) not found with standard"
        " methods."
    )
    print("[*] Printing printable character sequences extracted from ICMP:")
    text = "".join(
        [
            chr(b)
            for b in b"".join(single_bytes_req)
            if 32 <= b <= 126 or b in (10, 13)
        ]
    )
    print("--- Stream Start ---")
    print(text)
    print("--- Stream End ---")


extract_icmp_data()
