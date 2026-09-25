import re
import base64

def analyze_clean_binary(file_path="clean_extracted.bin"):
    print(f"[*] Analyzing {file_path} (561 bytes)...")
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[-] {file_path} not found.")
        return

    # ১. প্রথম ৩২ বাইটের হেক্স ডাম্প (Magic Signature বোঝার জন্য)
    print("\n[*] First 32 Bytes (Hex Dump):")
    print(data[:32].hex(" "))
    print("ASCII Preview:", "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:32]))

    flag_regex = re.compile(rb'bcsctf\{[^}]+\}', re.IGNORECASE)

    # ২. XOR ব্রুট-ফোর্স (0x01 - 0xFF)
    print("\n[*] Checking XOR keys (0x01 - 0xFF)...")
    for k in range(1, 256):
        xored = bytes([b ^ k for b in data])
        match = flag_regex.search(xored)
        if match:
            print("\n" + "★" * 50)
            print(f"[🎉] BINGO! Found Flag with XOR Key: {hex(k)} ({k})")
            print(f"[+] FLAG: {match.group(0).decode('utf-8', errors='ignore')}")
            print("★" * 50 + "\n")
            return

    # ৩. Base64 / Base85 / Ascii85 চেক
    print("[*] Checking Base64 / Base85 / Ascii85 encodings...")
    clean_text = "".join(chr(b) for b in data if 32 <= b <= 126)
    decoders = [
        ("Base64", base64.b64decode),
        ("Base85", base64.b85decode),
        ("Ascii85", base64.a85decode)
    ]
    for name, fn in decoders:
        try:
            decoded = fn(clean_text)
            match = flag_regex.search(decoded)
            if match:
                print("\n" + "★" * 50)
                print(f"[🎉] BINGO! Flag found via {name}:")
                print(f"[+] FLAG: {match.group(0).decode('utf-8', errors='ignore')}")
                print("★" * 50 + "\n")
                return
        except Exception:
            pass

    # ৪. ফাইলের ভেতরের সব রিডেবল স্ট্রিং প্রিন্ট করা
    print("\n[*] All Printable Strings inside binary:")
    printable_strings = re.findall(rb'[\x20-\x7e]{4,}', data)
    for s in printable_strings:
        print("  ->", s.decode('utf-8', errors='ignore'))

analyze_clean_binary()
