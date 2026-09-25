import cv2
import numpy as np
from PIL import Image

def super_solver():
    print("[*] Super Solver Start Hocche... Ektu Opekkha Korun...")
    
    # Image Load
    img = Image.open("shattered_qr.png").convert("L")
    arr = np.array(img)
    N = arr.shape[0]
    
    Y, X = np.indices((N, N))

    # Arnold's Cat Map er shob dhoroner variation
    transforms = [
        ("Inverse (Standard)", lambda x, y: (2 * x - y) % N, lambda x, y: (-x + y) % N),
        ("Forward (Standard)", lambda x, y: (x + y) % N, lambda x, y: (x + 2 * y) % N),
        ("Inverse (Transposed)", lambda x, y: (x - y) % N, lambda x, y: (-x + 2 * y) % N),
        ("Forward (Transposed)", lambda x, y: (2 * x + y) % N, lambda x, y: (x + y) % N)
    ]

    detector = cv2.QRCodeDetector()
    success = False

    for name, fx, fy in transforms:
        curr = arr.copy()
        
        # 9 Passes Transformation
        for _ in range(9):
            src_x = fx(X, Y)
            src_y = fy(X, Y)
            curr = curr[src_y, src_x]

        # [!] CRITICAL FIX: Image-ke 10x upscale kora hocche Nearest Neighbor diye
        scaled = cv2.resize(curr, (N * 10, N * 10), interpolation=cv2.INTER_NEAREST)

        # charipashe 50px shada border (Quiet Zone) add kora hocche
        padded = np.pad(scaled, pad_width=50, mode="constant", constant_values=255)

        # Decode korar try kora hocche
        data, bbox, _ = detector.detectAndDecode(padded)
        if data:
            print("\n" + "★" * 50)
            print(f"[!] BINGO! Pattern Matched: {name}")
            print(f"[+] YOUR FLAG / TOKEN IS: {data}")
            print("★" * 50 + "\n")
            success = True
            break
            
    if not success:
        print("\n[-] Kono error hocche. File name 'shattered_qr.png' thik ache kina check korun.")

super_solver()
