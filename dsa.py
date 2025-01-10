from random import getrandbits, randrange
from sympy import isprime
from hashlib import sha256

P_BIT_LENGTH = 2048
Q_BIT_LENGTH = 256

class DSA:
  def __init__(self):
    # Params
    self.p = 0
    self.q = 0
    self.g = 0
    # Private key
    self.x = 0
    # Public key
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
    f.write(f'{self.p}\n')
    f.write(f'{self.q}\n')
    f.write(f'{self.g}\n')
    f.write(f'{self.x}\n')
    f.close()

    f = open(public_key_path, 'w')
    f.write(f'{self.p}\n')
    f.write(f'{self.q}\n')
    f.write(f'{self.g}\n')
    f.write(f'{self.y}\n')
    f.close()

  def load_private_key(self, path):
    f = open(path, 'r')
    lines = f.readlines()
    ints = list(map(int, lines))
    [self.p, self.q, self.g, self.x] = ints
    f.close()

  def load_public_key(self, path):
    f = open(path, 'r')
    lines = f.readlines()
    ints = list(map(int, lines))
    [self.p, self.q, self.g, self.y] = ints
    f.close()

  def sign(self, message, signature_path):
    sha = sha256(message.encode()).hexdigest()
    H = int(sha, 16)
    s = 0
    r = 0

    while s == 0 or r == 0:
      k = randrange(1,self.q)
      invk = pow(k, -1, self.q)
      r = pow(self.g,k,self.p) % self.q
      s = H + self.x*r
      s = (s * invk) % self.q

    print(r, s)

    f = open(signature_path, 'w')
    f.write(f'{r}\n')
    f.write(f'{s}\n')
    f.close()

  def validate(self, message, signature_path):
    sha = sha256(message.encode()).hexdigest()
    H = int(sha, 16)

    f = open(signature_path, 'r')
    lines = f.readlines()
    ints = list(map(int, lines))
    [r, s] = ints
    f.close()

    w = pow(s, -1, self.q)
    v1 = (H * w) % self.q
    v2 = (r * w) % self.q
    v = pow(self.g, v1, self.p)
    v = v * pow(self.y, v2, self.p)
    v = v % self.p
    v = v % self.q

    return v == r

  def _rand_prime(self, bit_length):
    while True:
      x = getrandbits(bit_length)

      if isprime(x):
        return x

