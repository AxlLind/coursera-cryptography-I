import time
from Crypto.Cipher import AES
from Crypto.Util   import Padding

# Note: When I did this exercise the padding oracle server was down
#       so this script runs against a simulated HTTP server with a
#       random input I generated myself.

IV = b"DLC93kbZj2NOH5NS"
KEY = b"mQwnjVVQhYDWYBoR"
TARGET = bytes.fromhex("47709899582a1e39001d2e93a5577276698039f3b73427a4b78456b0f3a16c06bf1c47c10928af9c48167868f858062b2a6c8bc491748612090ed8af6d164fea")

def oracle_test(iv: bytes, ciphertext: bytes) -> int:
  time.sleep(0.016) # sleep 16ms to simulate HTTP request
  plaintext = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ciphertext)
  try:
    Padding.unpad(plaintext, AES.block_size)
  except ValueError:
    return 403
  return 404

GUESS_ORDER = b" abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ0123456789,." + bytes(range(2,16))

def decrypt_byte(text: list[int], block: list[int], b: int) -> int:
  for guess in GUESS_ORDER:
    text[-1-b] ^= (b+1) ^ guess
    ciphertext = bytes(text[16:] + block)
    if oracle_test(bytes(text[:16]), ciphertext) != 403:
      return guess
    text[-1-b] ^= (b+1) ^ guess
  raise Exception("Could not guess the byte!")

def pad_oracle_decrypt(msg: bytes, iv: bytes) -> bytes:
  iv, msg = list(iv), list(msg)
  plaintext = []
  for i in range(0, len(msg), 16):
    decrypted = []
    for b in range(16):
      text = iv + msg[0:i]
      for j,x in enumerate(decrypted):
        text[-1-j] ^= (b+1) ^ x
      decrypted += [decrypt_byte(text, msg[i:i+16], b)]
    plaintext += reversed(decrypted)
  return Padding.unpad(bytes(plaintext), AES.block_size)

def main() -> None:
  plaintext = pad_oracle_decrypt(TARGET, IV)
  print("Decrypted:", plaintext)

if __name__ == "__main__":
  main()
