from random import getrandbits, randrange
from sympy import isprime

P_BIT_LENGTH = 2048
Q_BIT_LENGTH = 256

class DSA:
  def __init__(self):
    self.p = 0
    self.q = 0
    self.g = 0
    self.x = 0
    self.y = 0

  def keygen(self):
    p = 0
    g = 1

    while not isprime(p) and not p.bit_length() == P_BIT_LENGTH:
      k = randrange(2**1791, 2**1792)
      q = self._rand_prime(Q_BIT_LENGTH)
      p = (k*q) + 1

    while g == 1:
      # randrange is not inclusive from right
      h = randrange(2, p-1)
      g = pow(h,k,p)

    # randrange is not inclusive from right
    x = randrange(1,q)

    y = pow(g,x,p)

    self.p = p
    self.q = q
    self.g = g
    self.x = x
    self.y = y

  def save_keys(self, private_key_path, public_key_path):
    f = open(private_key_path, 'w')
    f.write(str(self.x))
    f.close()

    f = open(public_key_path, 'w')
    f.write(f'{self.p}\n')
    f.write(f'{self.q}\n')
    f.write(f'{self.g}\n')
    f.write(f'{self.y}\n')
    f.close()

  def load_keys(self, private_key_path, public_key_path):
    f = open(private_key_path, 'r')
    self.x = int(f.readline())
    f.close()

    f = open(public_key_path, 'r')
    lines = f.readlines()
    ints = list(map(int, lines))
    [self.p, self.q, self.g, self.y] = ints
    f.close()

  def _rand_prime(self, bit_length):
    while True:
      x = getrandbits(bit_length)

      if isprime(x):
        return x

