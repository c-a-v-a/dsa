from random import getrandbits, randrange
from sympy import isprime
from hashlib import sha256

P_BIT_LENGTH = 2048
Q_BIT_LENGTH = 256

class DSA:
  def keygen(self):
    p = 0
    g = 1

    while not isprime(p) or not p.bit_length() == P_BIT_LENGTH:
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

  def export_private_key(self):
    return f'{self.p}\n{self.q}\n{self.g}\n{self.x}'

  def export_public_key(self):
    return f'{self.p}\n{self.q}\n{self.g}\n{self.y}'

  def load_private_key(self, content):
    lines = content.splitlines()
    ints = list(map(int, lines))
    [self.p, self.q, self.g, self.x] = ints

  def load_public_key(self, content):
    lines = content.splitlines()
    ints = list(map(int, lines))
    [self.p, self.q, self.g, self.y] = ints

  def sign(self, message):
    if not self._are_params_loaded() or self.x == 0:
      raise Exception('Error. Key was not loaded.')

    H = self._hash(message)
    s = 0
    r = 0

    while s == 0 or r == 0:
      k = randrange(1,self.q)
      invk = pow(k, -1, self.q)
      r = pow(self.g,k,self.p) % self.q
      s = (invk *(H + self.x*r)) % self.q

    return f'{r}\n{s}'

  def verify(self, message, signature):
    if not self._are_params_loaded() or self.y == 0:
      raise Exception('Error. Key was not loaded.')

    H = self._hash(message)

    lines = signature.splitlines()
    ints = list(map(int, lines))
    [r, s] = ints

    if r < 0 or r > self.q or s < 0 or s > self.q:
      raise Exception('Error. Invalid signature format.')

    w = pow(s, -1, self.q)
    v1 = (H * w) % self.q
    v2 = (r * w) % self.q
    v = ((pow(self.g, v1, self.p) * pow(self.y, v2, self.p)) % self.p) % self.q

    return v == r

  def _rand_prime(self, bit_length):
    while True:
      x = getrandbits(bit_length)

      if isprime(x):
        return x

  def _hash(self, message):
    m = str.encode(message)
    h = sha256(m).digest()
    return int.from_bytes(h, 'big') % self.q

  def _are_params_loaded(self):
    return not (self.p == 0 or self.q == 0 or self.g == 0)
