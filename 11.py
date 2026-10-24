from PIL import Image
import re


def solve_contact_sheet(img_path="contact_sheet.png"):
    print(f"[*] Analyzing {img_path}...")
    try:
        img = Image.open(img_path)
    except Exception as e:
        print(f"[-] Error opening image: {e}")
        return

    print(f"[+] Image Mode: {img.mode}, Size: {img.size}")

    if 'A' in img.getbands():
        alpha = img.getsplit()[3]
        print("[+] Found Alpha Channel (Opacity Register). Extracting...")
        alpha.save("alpha_channel.png")

    pixels = img.load()
    data_bits = []

    for y in range(img.height):
        for x in range(img.width):
            p = pixels[x, y]
            if isinstance(p, int):
                data_bits.append(p & 1)
            else:
                for c in p[:3]:
                    data_bits.append(c & 1)
                if len(p) > 3:
                    data_bits.append(p[3] & 1)

    byte_array = bytearray()
    for i in range(0, len(data_bits) - 7, 8):
        byte = 0
        for b in range(8):
            byte = (byte << 1) | data_bits[i + b]
        byte_array.append(byte)

    flag_regex = re.compile(rb'bcsctf\{[^}]+\}', re.IGNORECASE)
    match = flag_regex.search(byte_array)

    if match:
        print("\n" + "★" * 50)
        print(f"[🎉] SUCCESS! FLAG FOUND: {match.group(0).decode('utf-8', errors='ignore')}")
        print("★" * 50 + "\n")
    else:
        print("[-] Direct flag not found in LSB. Saving extracted raw stream to 'extracted_fold.bin'...")
        with open("extracted_fold.bin", "wb") as f:
            f.write(byte_array)

solve_contact_sheet()
