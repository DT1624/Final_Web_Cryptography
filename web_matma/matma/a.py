# # # from PIL import Image

# # # def remove_background(input_gif, output_gif, background_color=(255, 255, 255)):
# # #     # Open the GIF file
# # #     gif = Image.open(input_gif)
    
# # #     # Get all frames of the GIF
# # #     frames = []
# # #     for frame in range(gif.n_frames):
# # #         gif.seek(frame)
# # #         frame_image = gif.convert("RGBA")
        
# # #         # Remove background color
# # #         data = frame_image.getdata()
# # #         new_data = []
# # #         for item in data:
# # #             if item[:3] == background_color:
# # #                 new_data.append((255, 255, 255, 0))  # Make the background transparent
# # #             else:
# # #                 new_data.append(item)
# # #         frame_image.putdata(new_data)
# # #         frames.append(frame_image)
    
# # #     # Save the new GIF
# # #     frames[0].save(output_gif, save_all=True, append_images=frames[1:], loop=0, transparency=0)

# # # # Example usage
# # # remove_background("D:\\code btap mat ma\\Web\\web_matma\\static\\images\\a.gif", "D:\\code btap mat ma\\Web\web_matma\\static\\images\\a1.gif")

# from cryptography.hazmat.primitives import serialization

# pem_data = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC86pE11THTb4D3dzREWUNMeemJ\nJUVymq15dQpDe5XPC24c5ijg06actpjiKxS4TK0jQ7+BeN22B9cbp6Emet813PgM\ne97LmSoUHpfCexIihtm+gmMortQzB2v42IhwYmzeY7mMfdBpuMYsNO3hNgTUm9O8\n7aB5tzLveavB5kowDwIDAQAB\n-----END PUBLIC KEY-----\n'


# # Load the public key
# public_key = serialization.load_pem_public_key(pem_data)

# # Extract details
# if hasattr(public_key, "public_numbers"):
#     numbers = public_key.public_numbers()
#     print("Modulus (n):", numbers.n)
#     print("Exponent (e):", numbers.e)

# from cryptography.hazmat.primitives import serialization

# pem_data = b'-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALdfrJOBakhMlBC1\nDPuyKnDB07rvTLbJng81htiCl4rvVaZAfIxHa8+GY8lcYr8ivMijxZG6FLLy7/n0\n6isb98lTVQsUnljYlBK34OPR1sdvxZpY7NVUdKmEabkS3ttBX8Rr67iofmkLV1Fv\n5DAMoIjAiP3Ey9ElknulJtUztsT5AgMBAAECgYBvGdV6rW9SjKstEDTkjobuOFFr\nMi99k9xjBKBFr6HXeLig+PM9HsywOJFe382oVoig27EJYP/HiC9jd0MliVVvq53J\n75FYcPnKIF3hK89UYW4ccJZ8WWbLGXR1F8v47dv7Y3umnm7yTgGy+dyiwO2U1kOu\noV5nTTMNaOmEbr2CPQJBAN5odB2p9NCJ7hB3v5EobCk8TLvtY6gHTa/2Hk8c5tF8\nPuOhqt8iZ9EoQN9MaeOAXUd/WbpnWb6zqCavOOoKjI8CQQDTEe9XR+UpK6EhKPtX\nL2PdYqckMla+hGXajbMLFTdQspk00RjHTjdDBDq9K+bMoAoGjQkyfnUSDGXNF3RQ\nNen3AkEAuSAq3vI0BE17KpvyigoileRKXvcHR7rkkH4F1oZRHrgTxPgxuc/yqGeg\nL/5z+VlEy5mWf5E9Y345jhG2ByHGwwJATKaevJunZSQrB9fSLv9OzP8eo86EIfwC\n4TPEaanyxKOXb87fqMGG4BeRHVHsJzOXcHmXdXbnHP7TmX+DBf4OUQJAUlYdWMcH\n3WRsRe2R+Rk3ZFq/2twH40SK8VhzKcK1UABK+dWPsKwZp1ky7DHIpQ6CAO3xbUoY\naDmKsqXS7GRnCQ==\n-----END PRIVATE KEY-----\n'


# # Load the private key
# private_key = serialization.load_pem_private_key(pem_data, password=None)

# # Extract details
# numbers = private_key.private_numbers()
# print("Modulus (n):", numbers.public_numbers.n)
# print("Public Exponent (e):", numbers.public_numbers.e)
# print("Private Exponent (d):", numbers.d)
# print("Prime 1 (p):", numbers.p)
# print("Prime 2 (q):", numbers.q)
# print("Exponent1 (d mod (p-1)):", numbers.dmp1)
# print("Exponent2 (d mod (q-1)):", numbers.dmq1)
# print("Coefficient (q^(-1) mod p):", numbers.iqmp)
# from cryptography.hazmat.primitives.asymmetric import elgamal
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization, hashes
# import cryptography.hazmat.primitives.ciphers as aa
# print(dir(aa))

# def generate_elgamal_keys(bits):
#     private_key = elgamal.generate_private_key(
#         public_exponent=65537,
#         key_size=bits,
#         backend=default_backend()
#     )
    
#     public_key = private_key.public_key()
    
#     # Chuyển đổi khóa thành PEM
#     private_pem = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=serialization.NoEncryption()
#     )
    
#     public_pem = public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )
    
#     return private_pem.decode('utf-8'), public_pem.decode('utf-8')

# # Hàm gọi và in khóa
# if __name__ == '__main__':
#     private_key, public_key = generate_elgamal_keys(2048)
    
#     print("Khóa bí mật:")
#     print(private_key)
    
#     print("\nKhóa công khai:")
#     print(public_key)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Giả sử bạn đã có giá trị private_value (khóa riêng) và tọa độ công khai (x, y)
private_value = 123456789  # Giá trị khóa riêng
x = 987654321  # Tọa độ x của khóa công khai
y = 123987654  # Tọa độ y của khóa công khai

# Tạo đối tượng khóa riêng từ private_value
private_key = ec.derive_private_key(private_value, ec.SECP192R1(), default_backend())

# Tạo đối tượng khóa công khai từ tọa độ x, y
public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes([0x04]) + x.to_bytes(32, 'big') + y.to_bytes(32, 'big'))

# Mã hóa private key thành PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# Mã hóa public key thành PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# In khóa PEM
print("Private Key (PEM format):")
print(private_pem.decode())

print("\nPublic Key (PEM format):")
print(public_pem.decode())

