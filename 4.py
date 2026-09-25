import re
from scapy.all import ICMP, rdpcap


def extract_icmp_flag(pcap_path):
  packets = rdpcap(pcap_path)

  # Collect payload indexed by ICMP sequence number to preserve order
  seq_payloads = {}

  for pkt in packets:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # ICMP Echo Request
      seq = pkt[ICMP].seq
      raw_payload = bytes(pkt[ICMP].payload)

      # Standard Linux ping includes an 8-byte timestamp header before custom payload.
      # If the payload length is greater than 8, slice after timestamp if needed.
      seq_payloads[seq] = raw_payload

  # Sort by sequence number and concatenate
  sorted_data = bytearray()
  for seq in sorted(seq_payloads.keys()):
    payload = seq_payloads[seq]
    # If standard 8-byte timestamp is present, payload[8:] extracts the exfiltrated char
    if len(payload) > 8 and payload[:4].isascii() == False:
      sorted_data.extend(payload[8:])
    else:
      sorted_data.extend(payload)

  raw_bytes = bytes(sorted_data)

  # Search for the flag pattern
  flag_match = re.search(rb"bcsctf\{[^}]+\}", raw_bytes)
  if flag_match:
    print(f"[+] FLAG FOUND: {flag_match.group(0).decode()}")
  else:
    print("[*] Reconstructed Data Stream:")
    print(raw_bytes)


extract_icmp_flag("capture.pcap")
