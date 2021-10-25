from Crypto.Cipher import AES

block = list[int]

def xor(a: block, b: block) -> block:
  return [x^y for x,y in zip(a,b)]

def as_blocks(s: str) -> list[block]:
  lst = bytes.fromhex(s)
  return [lst[i:i + 16] for i in range(0, len(lst), 16)]

def blocks_to_bytes(blocks: list[block]) -> str:
  return bytes(b for block in blocks for b in block)

def aes_ebc(key: block, block: block, mode: str) -> block:
  cipher = AES.new(bytes(key), AES.MODE_ECB)
  fn = cipher.decrypt if mode == "decrypt" else cipher.encrypt
  return list(fn(bytes(block)))

def aes_cbc_decrypt(key: block, ciphertext: list[block]) -> list[block]:
  plaintext = []
  for i in reversed(range(1, len(ciphertext))):
    plaintext += [xor(ciphertext[i-1], aes_ebc(key, ciphertext[i], "decrypt"))]
  return reversed(plaintext)

def aes_ctr_decrypt(key: block, ciphertext: list[block]) -> list[block]:
  iv = int.from_bytes(bytes(ciphertext[0]), "big")
  plaintext = []
  for i, block in enumerate(ciphertext[1:]):
    next_iv = (iv + i).to_bytes(16, byteorder="big")
    plaintext += [xor(block, aes_ebc(key, next_iv, "encrypt"))]
  return plaintext

def main() -> None:
  cbc_key = as_blocks("140b41b22a29beb4061bda66b6747e14")[0]
  ctr_key = as_blocks("36f18357be4dbd77f050515c73fcf9f2")[0]
  ciphertexts = [
    as_blocks("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"),
    as_blocks("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"),
    as_blocks("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"),
    as_blocks("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"),
  ]

  print("cbc 1:", blocks_to_bytes(aes_cbc_decrypt(cbc_key, ciphertexts[0])))
  print("cbc 2:", blocks_to_bytes(aes_cbc_decrypt(cbc_key, ciphertexts[1])))
  print("ctr 1:", blocks_to_bytes(aes_ctr_decrypt(ctr_key, ciphertexts[2])))
  print("ctr 2:", blocks_to_bytes(aes_ctr_decrypt(ctr_key, ciphertexts[3])))

if __name__ == "__main__":
  main()
