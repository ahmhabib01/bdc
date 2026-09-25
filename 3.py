import numpy as np
from PIL import Image

# 1. Image load korun
img = Image.open("shattered_qr.png").convert("L")
arr = np.array(img)
N = arr.shape[0]

Y, X = np.indices((N, N))

# 2. Variant 1 Inverse Map (Matrix: [[2, -1], [-1, 1]])
curr1 = arr.copy()
for _ in range(9):
  prev_X = (2 * X - Y) % N
  prev_Y = (-X + Y) % N
  curr1 = curr1[prev_Y, prev_X]

Image.fromarray(curr1).save("reconstructed_qr_v1.png")

# 3. Variant 2 Inverse Map (Matrix: [[1, -1], [-1, 2]])
curr2 = arr.copy()
for _ in range(9):
  prev_X = (X - Y) % N
  prev_Y = (-X + 2 * Y) % N
  curr2 = curr2[prev_Y, prev_X]

Image.fromarray(curr2).save("reconstructed_qr_v2.png")

print(
    "[+] Extraction complete! 'reconstructed_qr_v1.png' ebong"
    " 'reconstructed_qr_v2.png' check korun."
)
