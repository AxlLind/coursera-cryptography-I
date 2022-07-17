from pathlib import Path
from cryptography.hazmat.primitives import hashes

INPUTS_DIR = Path(__file__).parent / '..' / 'inputs'

def chunks(s: bytes, n: int) -> list[bytes]:
  return [bytes(s[i:i+n]) for i in range(0, len(s), n)]

def sha256(*blocks: bytes) -> bytes:
  hasher = hashes.Hash(hashes.SHA256())
  for block in blocks:
    hasher.update(block)
  return hasher.finalize()

def video_hash(path: Path) -> str:
  first_block, *blocks = reversed(chunks(path.read_bytes(), 1024))
  h = sha256(first_block)
  for block in blocks:
    h = sha256(block, h)
  return h.hex()

def main() -> None:
  test_hash = "03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8"
  assert video_hash(INPUTS_DIR / '6.2.birthday.mp4_download') == test_hash
  print("Hash:", video_hash(INPUTS_DIR / '6.1.intro.mp4_download'))

if __name__ == "__main__":
  main()
