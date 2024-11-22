from django.db import models
import random
from matma import utils

# Định nghĩa lớp RSA
class RSAKey(models.Model):
    p = models.TextField()
    q = models.TextField()
    e = models.TextField()
    n = models.TextField(editable=False)
    phi = models.TextField(editable=False)
    d_prv = models.TextField(editable=False)
    
    def save(self, *args, **kwargs):
        # Nếu p và q là chuỗi, chuyển chúng thành số nguyên
        if self.p and self.q and self.e:
            self.p = int(self.p)
            self.q = int(self.q)
            self.e = int(self.e)
            self.n = self.p * self.q
            self.phi = (self.p - 1) * (self.q - 1)
            self.__d = utils.nghichdao(self.e, self.phi)
    
    def private_key(self):
        return (self.p, self.q, self.d_prv)
    
    # Khóa công khai
    def public_key(self):
        return (self.n, self.e)
    
    # Mã hóa
    def encrypt(self, txt):
        n, e = self.public_key()
        m = utils.hash_map(txt)
        return utils.pow_mod(m, e, n)
    
    # Giải mã
    def decrypt(self, y):
        return utils.pow_mod(y, self.d_prv, self.n)
    

# Định nghĩa lớp RSA_signature
class RSA_sig:
    def __init__(self, p, q, a):
        self.p = p
        self.q = q
        self.__a = a
        self.n = p*q
        self.phi = (p-1)*(q-1)
        self.b = utils.nghichdao(a, self.phi)
    
    # Khóa bí mật
    def private_key(self):
        return (self.p, self.q, self.__a)
    
    # Khóa công khai
    def public_key(self):
        return (self.n, self.b)
    
    # Chữ ký   
    def sig(self, txt):
        m = utils.hash_map(txt)
        return utils.pow_mod(m, self.__a, self.n)
    
    # Kiểm thử chữ ký
    def ver(self, x, y):
        n, b = self.public_key()
        return utils.hash_map(x) == utils.pow_mod(y, b, n)
        
        
# Định nghĩa lớp ELGamal
class ElGamal:
    def __init__(self, p, alpha, a):
        self.p = p
        self.alpha = alpha
        self.__a = a
        self.beta = utils.pow_mod(alpha, a, p)
        
    # Khóa bí mật
    def private_key(self):
        return (self.__a)
    
    # Khóa công khai
    def public_key(self):
        return (self.p, self.alpha, self.beta)
    
    # Mã hóa
    def encrypt(self, txt):
        p, alpha, beta = self.public_key()
        m = utils.hash_map(txt)
        k = random.randint(0, self.p - 1)
        y1 = utils.pow_mod(alpha, k, p)
        y2 = m * utils.pow_mod(beta, k, p) % p
        return (y1, y2)
    
    # Giải mã
    def decrypt(self, y1, y2):
        a = self.private_key()
        y1 = utils.pow_mod(y1, self.p - 1 - a, self.p)
        return y1 * y2 % self.p
    

# Định nghĩa lớp ELGamal_signature
class ElGamal_sig:
    def __init__(self, p, alpha, a):
        self.p = p
        self.alpha = alpha
        self.__a = a
        self.beta = utils.pow_mod(alpha, a, p)
        
    # Khóa bí mật
    def private_key(self):
        return (self.__a)
    
    # Khóa công khai
    def public_key(self):
        return (self.p, self.alpha, self.beta)
    
    # Chữ ký
    def sig(self, txt):
        a = self.private_key()
        m = utils.hash_map(txt)
        k = random.randint(0, self.p - 1)
        while utils.gcd(k, self.p-1) != 1:
            k = random.randint(0, self.p-1)
        gamma = utils.pow_mod(self.alpha, k, self.p)
        sigma = (m - a * gamma) * utils.nghichdao(k, self.p - 1)
        sigma %= (self.p-1)
        return (gamma, sigma)
    
    # Kiểm thử chữ ký
    def ver(self, x, gamma, sigma):
        p, alpha, beta = self.public_key()
        m = utils.hash_map(x)
        VP = utils.pow_mod(alpha, m, p)
        VT = utils.pow_mod(beta, gamma, p) * utils.pow_mod(gamma, sigma, p) % p
        return VT == VP
    
    
# Định nghĩa lớp ECC
class ECC:
    def __init__(self, a, b, p, P, s):
        self.a = a
        self.b = b
        self.p = p
        self.P = P
        self.__s = s
        self.B = utils.mul_k_point(P, s, 0, a, p)
      
    # Khóa công khai
    def public_key(self):
        return (self.a, self.b, self.p, self.P, self.B)
    
    # Khóa bí mật  
    def private_key(self):
        return self.__s
    
    # Mã hóa
    def encrypt(self, txt):
        a, b, p, P, B = self.public_key()
        m = utils.hash_map(txt)
        m1 = utils.find_thangdubac2(m, a, b, p)
        M = [m, m1]
        k = random.randint(0, p)
        M1 = utils.mul_k_point(P, k, 0, a, p)
        kB = utils.mul_k_point(B, k, 0, a, p)
        M2 = utils.add_point(M, kB, 0, a, p)
        return (M1, M2)
        
    # Giải mã  
    def decrypt(self, M1, M2):
        s = self.private_key()
        sM1 = utils.mul_k_point(M1, s, 0, self.a, self.p)
        sM1 = utils.neg(sM1)
        return utils.add_point(M2, sM1, 0, self.a, self.p)
    

# Định nghĩa lớp ECC
class ECC_sig:
    def __init__(self, a, b, p, P, s, n):
        self.a = a
        self.b = b
        self.p = p
        self.P = P
        self.__s = s
        self.n = n
        self.B = utils.mul_k_point(P, s, 0, a, p)
      
    # Khóa công khai
    def public_key(self):
        return (self.a, self.b, self.p, self.P, self.B, self.n)
    
    # Khóa bí mật  
    def private_key(self):
        return self.__s
    
    # Chữ ký
    def sig(self, txt):
        d = self.private_key()
        m = utils.hash_map(txt)
        k = random.randint(1, self.n)
        T = utils.mul_k_point(self.P, k, 0, self.a, self.p)
        r = T[0] % self.n
        s = (m + d * r) * utils.nghichdao(k, self.n) % self.n
        return (r, s)
    
    # Kiểm thử chữ ký
    def ver(self, x, r, s):
        a, b, p, P, B, n = self.public_key()
        m = utils.hash_map(x)
        w = utils.nghichdao(s, n)
        u1 = m * w % n
        u2 = r * w % n
        u1P = utils.mul_k_point(P, u1, 0, a, p)
        u2B = utils.mul_k_point(B, u2, 0, a, p)
        T = utils.add_point(u1P, u2B, 0, a, p)
        return T[0] % n == r  