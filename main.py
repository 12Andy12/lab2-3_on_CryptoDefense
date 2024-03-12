import CryptoUser
import CryptoDef
from base64 import b64encode
from base64 import b64decode

user_1 = CryptoUser.cryptoUser("Andy")
user_2 = CryptoUser.cryptoUser("Ivan")

# CryptoUser.send_message_as_shamir(user_1, user_2, "text")

# CryptoUser.send_message_as_DeffiHelfman_Ceaser(user_1, user_2, "text")

# CryptoUser.send_message_as_ElGamal(user_1, user_2, "text")

# CryptoUser.send_message_as_RSA(user_1, user_2, "text")

# CryptoUser.send_message_as_Verman(user_1, user_2, "text")

# CryptoUser.send_file_as_Verman(user_1, user_2, "Billi.png", "data")

# CryptoUser.send_file_as_Verman(user_1, user_2, "Billi.png", "data")

# CryptoUser.send_file_as_shamir(user_1, user_2, "Billi.png", "data")

# CryptoUser.send_file_as_ElGamal(user_1, user_2, "Billi.png", "data")

# CryptoUser.send_file_as_RSA(user_1, user_2, "file1.txt", "data")

# CryptoUser.send_file_as_ElGamal(user_1, user_2, "file1.txt", "data")

# CryptoUser.gost_signature(user_1, user_2, "file1.txt", "data")

print(pow(11, 7, 23))
print((6 * 7) % 23)

# p = 23
# k = CryptoDef.generate_friend_simple_numper(p - 1)
# r = pow(5, k, p)
# hash = "f"
# u = [(int(i, 16) - 9 * r) % (p - 1) for i in hash]
# print([(CryptoDef.gcd(k, p - 1)[1] * i) % (p - 1) for i in u])