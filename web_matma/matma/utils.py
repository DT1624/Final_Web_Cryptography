import math
import random
from django.http import JsonResponse

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime

from ecdsa import SECP160r1

import base64
# Hàm băm bản tin
def hash_map(txt):
    ans = 0
    for i in range(len(txt)):
        ans = ans * 26 + ord(txt[i]) - ord('A') + 1
    return ans

# Hàm ngược của hàm băm
def unhash_map(n):
    s = []
    while n > 0:
        s.append(chr((n - 1) % 26 + ord('A')))
        n = (n - 1) //26
    return ''.join(s[::-1])
    
# Tìm phần tử nghịch đảo của a theo mod b (hay a.x = 1 mod b)
def nghichdao(a, b):
    m = b
    x1, x2 = 0, 1
    while b > 0:
        q = a // b
        r = a % b
        x = x2 - x1 * q
        x2, x1 = x1, x
        a, b = b, r
    while x2 < 0:
        x2 += m
    return x2

# Hàm a^b mod n
def pow_mod(a, b, n):
    a %= n
    ans = 1
    if b == 0:
        return 1
    while b > 0:
        if b % 2 == 1:
            ans = (ans * a) % n
        a = (a * a) % n
        b //= 2
    return ans

# Hàm tìm x thỏa mãn a.x = b mod n
def pt_mod(a, b, n):
    c = nghichdao(a, n)
    # d = pow_mod(a, n - 2, n)
    return (b * c ) % n

# Hàm kiểm tra a có phải thặng dư bậc 2 của p không (a = x^2 mod p) 
def thangdubac2(a, p):
    return pow_mod(a, p // 2, p) == 1

# Kiểm tra hoàng độ m có thuộc E_p(a, b) không
def point_in_elliptic(m, a, b, p):
    x = (m**3 + a*m + b) % p
    return thangdubac2(x, p)

# Tìm tung độ của 1 điểm có hoành độ m trên E_p(a, b)
def find_thangdubac2(m, a, b, p):
    x = (m**3 + a*m + b) % p
    return pow_mod(x, (p+1)//4, p)

# Hàm chuyển 1 số thành chuỗi nhị phân
def str_cs2(n):
    s = []
    while n > 0:
        s.append(chr(n % 2 + ord('0')))
        n //= 2
    return ''.join(s[::-1])

# Cộng 2 điểm P, Q trên đường cong y^2 = x^3 + ax^2 + bx + c mod p
def add_point(P, Q, a, b, p):
    if P == [0, 0]:
        return Q
    if Q == [0, 0]:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return [0, 0]
    
    if P == Q:
        lamda = pt_mod(2 * P[1], 3 * P[0] * P[0] + 2 * a * P[0] + b, p)
    else:
        lamda = pt_mod(Q[0] - P[0], Q[1] - P[1], p)
    
    first = lamda * lamda - P[0] - Q[0]
    second = lamda * (P[0] - first) - P[1]
    return [first % p, second % p]

# Tích 2 k.P trên đường cong y^2 = x^3 + ax^2 + bx + c mod p
def mul_k_point(P, k, a, b, p):
    if k <= 0:
        return [0, 0]
    s = str_cs2(k)
    T = P
    for i in range(1, len(s)):
        T = add_point(T, T, a, b, p)
        if s[i] == '1':
            T = add_point(T, P, a, b, p)  
    return T

# Điểm đối của một điểm trên đường cong
def neg(P):
    return [P[0], -P[1]]

# UCLN của 2 số
def gcd(a, b):
    return a if b == 0 else gcd(b, a % b)

# BCNN của 2 số
def lcm(a, b):
    return a * b / gcd(a, b)

# Note
# Trong hệ mật mã hóa, giải mã thì khóa công khai để encrypt, còn khóa bí mật để decrypt
# (Người lạ có khóa công khai thì có thể mã hóa rồi gửi cho người A, người A lấy khóa bí mật để giải mã xem nội dung)
# Trong hệ chữ ký, khóa bí mật để mã hóa chữ ký, còn khóa công khai để kiểm thử 
# (Người lạ có khóa công khai có thể kiểm tra xem có đúng khóa của ai đó k)

# generate cryptosystem key
def generate_cryptosystem_key(request):
    key = request.GET.get('key')
    bit = request.GET.get('bit')
    if key == "rsa_key":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=int(bit),
        )
        public_key = private_key.public_key()
    elif key == "elgamal_key":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=int(bit),
        )
        public_key = private_key.public_key()
        
    elif key == "ecc_key":
        if bit == "ecc_192": ecc = ec.SECP192R1()
        elif bit == "ecc_384": ecc = ec.SECP384R1()
        elif bit == "ecc_521": ecc = ec.SECP521R1()
        private_key = ec.generate_private_key(ecc)  # Dùng đường cong SECP256R1
        public_key = private_key.public_key()
        
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public, key_private = str(public_pem), str(private_pem)
    print(public_key, private_key)
    # key = [public_pem, private_pem]
    return JsonResponse({'public_key': str(key_public), 'private_key': str(key_private)})

def en_de_algorithm(request):
    choice = request.GET.get('choice')
    al = request.GET.get('al')
    text = request.GET.get('text').upper()
    key = request.GET.get('key').replace("\\n", "\n")[2:-2].encode('utf-8')
    
    output = 0
    if choice == "encrypt":
        try:
            public_key = serialization.load_pem_public_key(key)
            if al == "rsa_al":
                if not isinstance(public_key, rsa.RSAPublicKey):
                    return JsonResponse({'output': "Unknown RSA Public Key Format"})
                n = int(public_key.public_numbers().n)
                e = int(public_key.public_numbers().e)
                x = hash_map(text)
                c = pow_mod(x, e, n)
                y = unhash_map(c)
                output = y
            elif al == "elgamal_al":
                if not isinstance(public_key, rsa.RSAPublicKey):
                    return JsonResponse({'output': "Unknown ElGamal Public Key Format"})
                p = 76845003044794536074339659305878857461079573847700583991870893182480014210131054177468909348054473709147625596034318296488274243490315457311363415674136180655141984587704964326446766830222039513409868481015835270115854297552564160969370315635720716919210812609866884917376474714878609831094390410686288105187
                alpha = 57162259114223956540390256735488580341733137051413567467718811024260955644773232698600285742926727696682557332185951798023317454581226237435903756662666899751438029288018402686998620692567506212938524717459121900252361520404839156040151695433617674480177124792431074414769248467677791065386612097670819656441
                a = 67338436989466821135075813059392402797990471615066937445520587702283364542910761281859414496208832896950366710403588799519204673552290042756519608323165965444033559794780507996065049315868775251804312937508141465291151946286021927701501748818153938216069529101119422389694852969724242221608014301570186434586
                beta = pow_mod(alpha, a, p)
                m = hash_map(text)
                k = random.randint(0, p - 1)
                y1 = pow_mod(alpha, k, p)
                y2 = m * pow_mod(beta, k, p) % p
                y1 = unhash_map(y1) + "0" + unhash_map(y2)
                output = y1
            elif al == "ecc_al":
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    return JsonResponse({'output': "Unknown ECDSA Public Key Format"})
                p = 6277101735386680763835789423207666416083908700390324961279
                # n_point = 6277101735386680763835789423176059013767194773182842284081
                a = 6277101735386680763835789423207666416083908700390324961276
                b = 2455155546008943817740293915197451784769108058161191238065
                P = [602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641]
                B = [1264694880160769981750968260840999921235119489055224053030, 2572557741425984736595042581788070353944857404234055800302]
                m = hash_map(text)
                m1 = find_thangdubac2(m, a, b, p)
                M = [m, m1]
                k = random.randint(0, p)
                M1 = mul_k_point(P, k, 0, a, p)
                kB = mul_k_point(B, k, 0, a, p)
                M2 = add_point(M, kB, 0, a, p)
                x = unhash_map(M1[0]) + "0" + unhash_map(M1[1])
                y = unhash_map(M2[0]) + "0" + unhash_map(M2[1])
                x = x + "0" + y
                output = x            
        except Exception as e:
            output = "Error during public key identification"
            return JsonResponse({'output': str(output)})
        public_key = serialization.load_pem_public_key(key)
        
        
              
        
                       
    elif choice == "decrypt": 
        try:
            private_key = serialization.load_pem_private_key(
                key, password=None
            )
            if al == "rsa_al":
                if not isinstance(private_key, rsa.RSAPrivateKey):
                    return JsonResponse({'output': "Unknown RSA Private Key Format"})
                a = private_key
                n = int(a.public_key().public_numbers().n)
                d = int(a.private_numbers().d)
                y = hash_map(text)
                c = pow_mod(y, d, n)
                m = pow_mod(c, d, n)
                x = unhash_map(c)
                output = x
            elif al == "elgamal_al":
                if not isinstance(private_key, rsa.RSAPrivateKey):
                    return JsonResponse({'output': "Unknown ElGamal Private Key Format"})
                p = 76845003044794536074339659305878857461079573847700583991870893182480014210131054177468909348054473709147625596034318296488274243490315457311363415674136180655141984587704964326446766830222039513409868481015835270115854297552564160969370315635720716919210812609866884917376474714878609831094390410686288105187
                a = 67338436989466821135075813059392402797990471615066937445520587702283364542910761281859414496208832896950366710403588799519204673552290042756519608323165965444033559794780507996065049315868775251804312937508141465291151946286021927701501748818153938216069529101119422389694852969724242221608014301570186434586
                arr = text.split('0')
                y1, y2 = hash_map(arr[0]), hash_map(arr[1])
                y1 = y2 * pow_mod(y1, p - a - 1, p) % p
                output = unhash_map(y1)
            elif al == "ecc_al":
                if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                    return JsonResponse({'output': "Unknown ECC Private Key Format"})
                s = 2613675773981726554479122989230401936091670071283083923986
                p = 6277101735386680763835789423207666416083908700390324961279
                # n_point = 6277101735386680763835789423176059013767194773182842284081
                a = 6277101735386680763835789423207666416083908700390324961276
                arr = text.split('0')
                # print(arr)
                M1 = [hash_map(arr[0]), hash_map(arr[1])]
                M2 = [hash_map(arr[2]), hash_map(arr[3])]
                sM1 = mul_k_point(M1, s, 0, a, p)
                sM1 = neg(sM1)
                M2 = add_point(M2, sM1, 0, a, p)
                output = unhash_map(M2[0])                
        except Exception as e:
            return JsonResponse({'output': "Error during private key identification"})
    return JsonResponse({'output': str(output)})
# cần xét xem key có phải key đúng hay không? nếu không có thể return 1 alert gì đó
def sig_ver_algorithm(request):
    choice = request.GET.get('choice')
    al = request.GET.get('al')
    text = request.GET.get('text').upper()
    key = request.GET.get('key').replace("\\n", "\n")[2:-2].encode('utf-8')
    output = 0
    
    if choice == "sig":
        try:
            private_key = serialization.load_pem_private_key(
                key, password=None
            )
            if al == "rsa_sig":
                if not isinstance(private_key, rsa.RSAPrivateKey):
                    return JsonResponse({'output': "Unknown RSA Private Key Format"})
                n = int(private_key.public_key().public_numbers().n)
                d = int(private_key.private_numbers().d)
                x = hash_map(text)
                c = pow_mod(x, d, n)
                y = unhash_map(c)
                output = text + "0" + y
            elif al == "elgamal_sig":
                if not isinstance(private_key, rsa.RSAPrivateKey):
                    return JsonResponse({'output': "Unknown ElGamal Private Key Format"})
                p = 76845003044794536074339659305878857461079573847700583991870893182480014210131054177468909348054473709147625596034318296488274243490315457311363415674136180655141984587704964326446766830222039513409868481015835270115854297552564160969370315635720716919210812609866884917376474714878609831094390410686288105187
                alpha = 57162259114223956540390256735488580341733137051413567467718811024260955644773232698600285742926727696682557332185951798023317454581226237435903756662666899751438029288018402686998620692567506212938524717459121900252361520404839156040151695433617674480177124792431074414769248467677791065386612097670819656441
                a = 67338436989466821135075813059392402797990471615066937445520587702283364542910761281859414496208832896950366710403588799519204673552290042756519608323165965444033559794780507996065049315868775251804312937508141465291151946286021927701501748818153938216069529101119422389694852969724242221608014301570186434586
                beta = pow_mod(alpha, a, p)
                m = hash_map(text)
                k = random.randint(0, p - 1)
                while gcd(k, p-1) != 1:
                    k = random.randint(0, p - 1)
                gamma = pow_mod(alpha, k, p)
                sigma = (m - a*gamma) * nghichdao(k, p-1) % (p-1)
                output = text + "0" + unhash_map(gamma) + "0" + unhash_map(sigma)
                
            elif al == "ecc_sig":
                if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                    return JsonResponse({'output': "Unknown ECC Private Key Format"})
                p = 6277101735386680763835789423207666416083908700390324961279
                s = 4685000730669452116403471902086780059568887554984161560293
                n_point = 6277101735386680763835789423176059013767194773182842284081
                a = 6277101735386680763835789423207666416083908700390324961276
                b = 2455155546008943817740293915197451784769108058161191238065
                P = [602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641]
                m = hash_map(text)
                while True:
                    k = random.randint(0, n_point - 1)
                    kA = mul_k_point(P, k, 0, a, p)
                    r = kA[0] % n_point
                    rr = nghichdao(k, n_point) * (m + s * r) % n_point
                    if r != 0 and rr != 0:
                        break
                output = text + "0" + unhash_map(r) + "0" + unhash_map(rr)
        except Exception as e:
            output = "Error during private key identification"
            return JsonResponse({'output': str(output)})
                   
                       
    elif choice == "ver": 
        try:
            public_key = serialization.load_pem_public_key(key)
            if al == "rsa_sig":
                if not isinstance(public_key, rsa.RSAPublicKey):
                    return JsonResponse({'output': "Unknown RSA Public Key Format"})
                public_key = serialization.load_pem_public_key(key)
                n = int(public_key.public_numbers().n)
                e = int(public_key.public_numbers().e)
                arr = text.split('0')
                y = hash_map(arr[1])
                c = pow_mod(y, e, n)
                x = unhash_map(c)
                output = "Access Verify"  if arr[0] == x else "Not Access Verify"
            
            elif al == "elgamal_sig":
                if not isinstance(public_key, rsa.RSAPublicKey):
                    return JsonResponse({'output': "Unknown ElGamal Public Key Format"})
                p = 76845003044794536074339659305878857461079573847700583991870893182480014210131054177468909348054473709147625596034318296488274243490315457311363415674136180655141984587704964326446766830222039513409868481015835270115854297552564160969370315635720716919210812609866884917376474714878609831094390410686288105187
                alpha = 57162259114223956540390256735488580341733137051413567467718811024260955644773232698600285742926727696682557332185951798023317454581226237435903756662666899751438029288018402686998620692567506212938524717459121900252361520404839156040151695433617674480177124792431074414769248467677791065386612097670819656441
                a = 67338436989466821135075813059392402797990471615066937445520587702283364542910761281859414496208832896950366710403588799519204673552290042756519608323165965444033559794780507996065049315868775251804312937508141465291151946286021927701501748818153938216069529101119422389694852969724242221608014301570186434586
                beta = pow_mod(alpha, a, p)
                arr = text.split('0')
                x = pow_mod(beta, hash_map(arr[1]), p) * pow_mod(hash_map(arr[1]), hash_map(arr[2]), p) - pow_mod(alpha, hash_map(arr[0]), p)
                x %= p
                output = "Access Verify"  if x == 0 else "Not Access Verify"

                
            elif al == "ecc_sig":
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    return JsonResponse({'output': "Unknown ECDSA Public Key Format"})
                s = 2613675773981726554479122989230401936091670071283083923986
                p = 6277101735386680763835789423207666416083908700390324961279
                n_point = 6277101735386680763835789423176059013767194773182842284081
                a = 6277101735386680763835789423207666416083908700390324961276
                P = [602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641]
                B = [1507093096363319536856270861177873055543485765157790545472, 1288765725552792643224888534645455199211706007448232892623]
                arr = text.split('0')
                # print(arr)
                w = nghichdao(hash_map(arr[2]), n_point)
                i = w * hash_map(arr[0]) % n_point 
                j = w * hash_map(arr[1]) % n_point
                iP = mul_k_point(P, i, 0, a, p)
                jB = mul_k_point(B, j, 0, a, p)
                uv = add_point(iP, jB, 0, a, p)
                
                output = "Access Verify"  if uv[0] % n_point == hash_map(arr[1]) % n_point else "Not Access Verify"
        except Exception as e:
            output = "Error during public key identification"
            return JsonResponse({'output': str(output)})
        

    return JsonResponse({'output': str(output)})