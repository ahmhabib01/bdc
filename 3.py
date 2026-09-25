from PIL import Image
import numpy as np

def unshake_cat_map(img_path, passes=9, output_path="reconstructed_qr.png"):
    # Load image and convert to grayscale/numpy array
    img = Image.open(img_path).convert("L")
    arr = np.array(img)
    
    height, width = arr.shape
    assert height == width, "Image must be square (N x N)"
    N = height

    current_arr = arr.copy()

    # Perform 9 inverse Arnold's Cat Map passes
    for p in range(passes):
        prev_arr = np.zeros_like(current_arr)
        for y in range(N):
            for x in range(N):
                # Inverse matrix mapping: [2, -1; -1, 1]
                orig_x = (2 * x - y) % N
                orig_y = (-x + y) % N
                prev_arr[orig_y, orig_x] = current_arr[y, x]
        current_arr = prev_arr

    # Save reconstructed QR code
    restored_img = Image.fromarray(current_arr)
    restored_img.save(output_path)
    print(f"[+] Reconstructed QR code saved to: {output_path}")

    # Optionally attempt to auto-decode using pyzbar or OpenCV
    try:
        import cv2
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(cv2.imread(output_path))
        if data:
            print(f"[+] Emergency Access Token: {data}")
    except Exception:
        print("[!] Install opencv-python or pyzbar to auto-read, or scan reconstructed_qr.png with any QR reader.")

unshake_cat_map("shattered_qr.png", passes=9)
