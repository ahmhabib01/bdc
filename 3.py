import cv2
import numpy as np
from PIL import Image

def final_solver():
    print("[*] Exact Grid Solver Start Hocche...")
    
    img = Image.open("shattered_qr.png").convert("L")
    arr = np.array(img)
    size = arr.shape[0]  # 540
    
    # Arnold's Cat Map Variations
    transforms = [
        ("Inverse Standard", lambda x, y, n: (2 * x - y) % n, lambda x, y, n: (-x + y) % n),
        ("Forward Standard", lambda x, y, n: (x + y) % n, lambda x, y, n: (x + 2 * y) % n)
    ]
    
    detector = cv2.QRCodeDetector()
    found = False
    
    # 540 পিক্সেল ইমেজের সঠিক Block Size বের করার জন্য লুপ
    block_sizes = [c for c in range(2, 35) if size % c == 0]
    
    for c in block_sizes:
        N = size // c  # Grid size (যেমন: 540 // 12 = 45)
        
        # প্রতিটি ব্লক থেকে ১টি করে পিক্সেল নিয়ে আসল গ্রিড তৈরি
        small_arr = arr[::c, ::c].copy()
        Y, X = np.indices((N, N))
        
        for name, fx, fy in transforms:
            curr = small_arr.copy()
            
            # ৯ বার (9 passes) ফর্মুলা অ্যাপ্লাই
            for _ in range(9):
                src_x = fx(X, Y, N)
                src_y = fy(X, Y, N)
                curr = curr[src_y, src_x]
            
            # রিকভার করা গ্রিডটিকে স্ক্যান করার জন্য বড় করা হচ্ছে
            restored = cv2.resize(curr, (500, 500), interpolation=cv2.INTER_NEAREST)
            padded = np.pad(restored, pad_width=40, mode="constant", constant_values=255)
            
            # OpenCV দিয়ে সরাসরি ফ্ল্যাগ বের করার চেষ্টা
            data, _, _ = detector.detectAndDecode(padded)
            if data:
                print("\n" + "★" * 50)
                print(f"[!] SUCCESS! Matched Grid: {N}x{N}, Method: {name}")
                print(f"[+] YOUR FLAG: {data}")
                print("★" * 50 + "\n")
                found = True
                break
                
            # যদি টার্মিনালে না আসে, ইমেজটি সেভ করে রাখছি
            Image.fromarray(padded).save(f"test_qr_{N}x{N}.png")
            
        if found:
            break
            
    if not found:
        print("\n[-] OpenCV flag detect korte pareni, tobe file save hoyeche.")
        print("[-] 'cloudshell download test_qr_45x45.png' command diye file namiye phone diye scan korun!")

final_solver()
