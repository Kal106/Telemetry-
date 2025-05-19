import random
import sympy
import hashlib
import math


def logger(msg):
    print("Logger ", msg)

def find_generator(p):
    """Finds a primitive root (generator) for a given prime p."""
    factors = sympy.factorint(p - 1)  # Prime factorization of (p-1)
    
    for g in range(2, p):  # Try values from 2 to p-1
        if all(pow(g, (p-1)//q, p) != 1 for q in factors):
            return g
    return None 

def modinv(a, p):    
    return pow(a, -1, p)



class ElGamal:
    def __init__(self, p=None, g=None, x=None):
        if p is None:
            p = sympy.randprime(2**(128-1), 2**128) 
        if g is None:
            g = find_generator(p)  
        if x is None:
            x = random.randint(2,p - 2)  
        self.p = p
        self.g = g
        self.x = x
        self.y = pow(self.g, self.x, self.p)  

    def find_generator(self, p):
        for g in range(2, p):
            if self.is_generator(g, p):
                return g
        raise ValueError("No generator found")

    def is_generator(self, g, p):
        if g <= 1 or g >= p:
            return False
        factors = sympy.factorint(p-1)
        for q in factors:
            if pow(g, (p-1)//q, p) == 1:
                return False
        return True

    def public_key(self):
        return (self.p, self.g, self.y)

    def private_key(self):
        return self.x

    def encrypt(self, m , y ):
        k = random.randint(2, self.p-2)
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(y, k, self.p)) % self.p
        return (c1, c2)
    
    def decrypt(self, ciphertext):
        c1, c2 = ciphertext
        s = pow(c1, self.x, self.p)
        s_inv = modinv(s, self.p)
        m = (c2 * s_inv) % self.p
        return m

    def sign(self, m):
        k = random.randint(2, self.p-2)
        while math.gcd(k, self.p-1) != 1:
            k = random.randint(2, self.p-2)
        r = pow(self.g, k, self.p)
        s = (m - self.x * r) * pow(k, -1, self.p-1) % (self.p-1)
        return (r, s)


    def verify(self, m, r, s, pb):
        if r <= 0 or r >= self.p or s <= 0 or s >= self.p-1:
            return False
        left = pow(self.g, m, self.p)
        right = (pow(pb, r, self.p) * pow(r, s, self.p)) % self.p
        logger(left)
        logger(right)
        return  left == right
