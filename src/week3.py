import os
import hashlib

INPUTS_DIR = f"{os.path.dirname(os.path.realpath(__file__))}/../inputs"

def chunks(s: bytes, n: int) -> list[bytes]:
  return [bytes(s[i:i+n]) for i in range(0, len(s), n)]

def sha256(*blocks: bytes) -> bytes:
  hasher = hashlib.sha256()
  for block in blocks:
    hasher.update(block)
  return hasher.digest()

def video_hash(path: str) -> str:
  file = open(path, 'rb').read()
  first_block, *blocks = reversed(chunks(file, 1024))
  h = sha256(first_block)
  for block in blocks:
    h = sha256(block, h)
  return h.hex()

def main() -> None:
  test_hash = "03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8"
  assert video_hash(f"{INPUTS_DIR}/6.2.birthday.mp4_download") == test_hash
  print("Answer:", video_hash(f"{INPUTS_DIR}/6.1.intro.mp4_download"))

if __name__ == "__main__":
  main()
