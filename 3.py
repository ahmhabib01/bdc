import cv2
import numpy as np
from PIL import Image


def solve_cat_map(image_path="shattered_qr.png", passes=9):
  # Load grayscale image
  img = Image.open(image_path).convert("L")
  arr = np.array(img)
  N = arr.shape[0]

  print(f"[*] Image dimensions: {N}x{N}")
  Y, X = np.indices((N, N))

  # Define all potential Cat Map coordinate transformations
  # Format: (Name, Source_X_formula, Source_Y_formula)
  transformations = [
      # Standard Inverse: [[2, -1], [-1, 1]]
      ("Inv_Std_1", lambda x, y: (2 * x - y) % N, lambda x, y: (-x + y) % N),
      ("Inv_Std_2", lambda x, y: (2 * y - x) % N, lambda x, y: (-y + x) % N),
      # Standard Forward: [[1, 1], [1, 2]]
      ("Fwd_Std_1", lambda x, y: (x + y) % N, lambda x, y: (x + 2 * y) % N),
      ("Fwd_Std_2", lambda x, y: (y + x) % N, lambda x, y: (y + 2 * x) % N),
      # Transposed Inverse: [[1, -1], [-1, 2]]
      ("Inv_Trp_1", lambda x, y: (x - y) % N, lambda x, y: (-x + 2 * y) % N),
      ("Inv_Trp_2", lambda x, y: (y - x) % N, lambda x, y: (-y + 2 * x) % N),
      # Transposed Forward: [[2, 1], [1, 1]]
      ("Fwd_Trp_1", lambda x, y: (2 * x + y) % N, lambda x, y: (x + y) % N),
      ("Fwd_Trp_2", lambda x, y: (2 * y + x) % N, lambda x, y: (y + x) % N),
  ]

  detector = cv2.QRCodeDetector()
  found = False

  for name, fx, fy in transformations:
    curr = arr.copy()

    # Apply 9 passes
    for _ in range(passes):
      src_x = fx(X, Y)
      src_y = fy(X, Y)
      curr = curr[src_y, src_x]

    out_name = f"res_{name}.png"
    Image.fromarray(curr).save(out_name)

    # Auto detect QR Code
    data, bbox, _ = detector.detectAndDecode(curr)
    if data:
      print("\n" + "=" * 50)
      print(f"[!!!] SUCCESS! Matched Pattern: {name}")
      print(f"[+] EMERGENCY ACCESS TOKEN: {data}")
      print("=" * 50)
      Image.fromarray(curr).save("FLAG_QR.png")
      found = True
      break
    else:
      print(f"[-] Tried {name} -> Saved to {out_name}")

  if not found:
    print("\n[!] OpenCV auto-detect korte pareni.")
    print("[!] Folder-er 'res_*.png' file gulo dekhoon jekontat QR pattern ashche.")


solve_cat_map("shattered_qr.png", passes=9)
