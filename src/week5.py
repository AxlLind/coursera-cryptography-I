from typing import Iterable

def repeated_mul(state: int, factor: int, modulus: int, times: int) -> Iterable[tuple[int,int]]:
  for i in range(times):
    state = (state * factor) % modulus
    yield (i+1, state)

def build_hashtable(g: int, p: int, h, B: int) -> dict[int, int]:
  table = {}
  for x1, y in repeated_mul(1, pow(g, -1, p), p, B):
    table[h * y % p] = x1
  return table

def dlog(p: int, g: int, h: int, B: int) -> int:
  table = build_hashtable(g, p, h, B)
  for x0, y in repeated_mul(1, pow(g, B, p), p, B):
    if y in table:
      return (x0 * B + table[y]) % p
  raise Exception("Could not find inverse?")

def main() -> None:
  p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
  g = 11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568
  h = 3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333
  B = 1 << 20

  x = dlog(p, g, h, B)
  assert pow(g, x, p) == h

  print(f"x = {x}")

if __name__ == "__main__":
  main()
