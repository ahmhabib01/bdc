import os
import cv2
import numpy as np
from PIL import Image

# PyZbar অটোমেটিক ইন্সটল করবে যদি না থাকে
try:
  from pyzbar.pyzbar import decode
except ImportError:
  os.system("pip install pyzbar")
  from pyzbar.pyzbar import decode

# Shattered QR Image Load
img = Image.open("shattered_qr.png").convert("L")
arr = np.array(img)
N = arr.shape[0]

Y, X = np.indices((N, N))

# Cat Map Variational Formulas
transformations = [
    ("Inv_Std", lambda x, y: (2 * x - y) % N, lambda x, y: (-x + y) % N),
    ("Fwd_Std", lambda x, y: (x + y) % N, lambda x, y: (x + 2 * y) % N),
    ("Inv_Trp", lambda x, y: (x - y) % N, lambda x, y: (-x + 2 * y) % N),
    ("Fwd_Trp", lambda x, y: (2 * x + y) % N, lambda x, y: (x + y) % N),
]

found = False

for name, fx, fy in transformations:
  curr = arr.copy()
  # 9 passes Transformation
  for p in range(9):
    src_x = fx(X, Y)
    src_y = fy(X, Y)
    curr = curr[src_y, src_x]

  # Add padding & convert to uint8
  padded = np.pad(
      curr, pad_width=40, mode="constant", constant_values=255
  ).astype(np.uint8)

  # Method 1: PyZbar Decoding
  decoded_objects = decode(Image.fromarray(padded))
  for obj in decoded_objects:
    flag_text = obj.data.decode("utf-8")
    print("\n" + "=" * 50)
    print(f"[🎉] SUCCESS! FLAG FOUND: {flag_text}")
    print("=" * 50)
    found = True
    break

  if found:
    break

  # Method 2: Upscaled OpenCV Decoding
  resized = cv2.resize(
      padded, (0, 0), fx=2, fy=2, interpolation=cv2.INTER_NEAREST
  )
  detector = cv2.QRCodeDetector()
  data, _, _ = detector.detectAndDecode(resized)
  if data:
    print("\n" + "=" * 50)
    print(f"[🎉] SUCCESS! FLAG FOUND: {data}")
    print("=" * 50)
    found = True
    break

if not found:
  print("\n[-] Auto-decoding with pyzbar failed.")
