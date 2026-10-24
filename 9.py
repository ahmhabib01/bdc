import re
from scapy.all import rdpcap, ICMP


def kpa_xor_search(data, target=b"bcsctf{"):
    target_len = len(target)
    if len(data) < target_len:
        return None, None

    for i in range(len(data) - target_len):
        key_candidate = bytes([data[i + j] ^ target[j] for j in range(target_len)])

        for klen in range(1, target_len + 1):
            key = key_candidate[:klen]
            decrypted = bytes([data[idx] ^ key[idx % klen] for idx in range(len(data))])
            if b"bcsctf{" in decrypted.lower():
                match = re.search(rb'bcsctf\{[^}]+\}', decrypted, re.IGNORECASE)
                if match:
                    return key, match.group(0)
    return None, None


def solve_icmp_kpa():
    print("[*] Loading capture.pcap for Known-Plaintext Attack...")
    try:
        pkts = rdpcap("capture.pcap")
    except FileNotFoundError:
        print("[-] capture.pcap file not found!")
        return

    reqs = [p for p in pkts if p.haslayer(ICMP) and p[ICMP].type == 8]

    reqs.sort(key=lambda p: int.from_bytes(bytes(p[ICMP].payload)[2:4], 'little') if len(p[ICMP].payload) >= 4 else 0)
    payloads = [bytes(p[ICMP].payload) for p in reqs]

    print(f"[*] Found {len(payloads)} ICMP Echo Request packets.")

    for skip in [8, 0, 4, 6, 10, 12, 16, 20, 24, 28, 32]:
        full_stream = b"".join([pl[skip:] for pl in payloads if len(pl) > skip])

        key, flag = kpa_xor_search(full_stream)
        if flag:
            print("\n" + "★" * 55)
            print(f"[🎉] BINGO! FLAG FOUND WITH KNOWN-PLAINTEXT ATTACK!")
            print(f"[+] Header Skip: {skip} bytes")
            print(f"[+] Detected XOR Key (Hex): {key.hex()} (Key Length: {len(key)})")
            print(f"[+] FLAG: {flag.decode('utf-8', errors='ignore')}")
            print("★" * 55 + "\n")
            return

    print("[-] KPA check completed. If not found, checking raw stream strings...")


solve_icmp_kpa()
