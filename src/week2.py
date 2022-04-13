from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def xor(a: bytes, b: bytes) -> bytes:
  return bytes(x^y for x,y in zip(a,b))

def as_blocks(s: str) -> list[bytes]:
  lst = bytes.fromhex(s)
  return [bytes(lst[i:i + 16]) for i in range(0, len(lst), 16)]

def blocks_to_str(blocks: list[bytes], *, unpad: bool) -> str:
  ans = bytes(b for block in blocks for b in block)
  if unpad:
    unpadder = padding.PKCS7(128).unpadder()
    ans = unpadder.update(ans) + unpadder.finalize()
  return ans.decode("ascii")

def aes_ebc(key: bytes, block: bytes, *, decrypt: bool = False) -> bytes:
  cipher = Cipher(algorithms.AES(key), modes.ECB())
  fn = cipher.decryptor() if decrypt else cipher.encryptor()
  return fn.update(block) + fn.finalize()

def aes_cbc_decrypt(key: bytes, ciphertext: str) -> str:
  cipherblocks, plaintext = as_blocks(ciphertext), []
  for i in reversed(range(1, len(cipherblocks))):
    plaintext += [xor(cipherblocks[i-1], aes_ebc(key, cipherblocks[i], decrypt=True))]
  return blocks_to_str([b for b in plaintext[::-1]], unpad=True)

def aes_ctr_decrypt(key: bytes, ciphertext: str) -> str:
  cipherblocks = as_blocks(ciphertext)
  iv = int.from_bytes(cipherblocks[0], "big")
  plaintext = []
  for i, block in enumerate(cipherblocks[1:]):
    next_iv = (iv + i).to_bytes(16, byteorder="big")
    plaintext += [xor(block, aes_ebc(key, next_iv))]
  return blocks_to_str(plaintext, unpad=False)

def main() -> None:
  cbc_key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
  ctr_key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
  print("cbc 1:", aes_cbc_decrypt(cbc_key, "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"))
  print("cbc 2:", aes_cbc_decrypt(cbc_key, "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"))
  print("ctr 1:", aes_ctr_decrypt(ctr_key, "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"))
  print("ctr 2:", aes_ctr_decrypt(ctr_key, "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"))

if __name__ == "__main__":
  main()
