import CryptoUser
from base64 import b64encode
from base64 import b64decode

user_1 = CryptoUser.cryptoUser("Andy")
user_2 = CryptoUser.cryptoUser("Ivan")

# CryptoUser.send_message_as_shamir(user_1, user_2, "text")
#
# CryptoUser.send_message_as_DeffiHelfman_Ceaser(user_1, user_2, "text")
#
# CryptoUser.send_message_as_ElGamal(user_1, user_2, "text")
#
# CryptoUser.send_message_as_RSA(user_1, user_2, "text")
#
# CryptoUser.send_message_as_Verman(user_1, user_2, "text")

# CryptoUser.send_file_as_Verman(user_1, user_2, "Billi.png", "data")

CryptoUser.send_file_as_Verman(user_1, user_2, "Billi.png", "data")

# file = open("data/Billi.png", "rb").read()
# encryptFile = open("data/encrypt_Verman_Billi.png", "wb")
# # mes = "some text".encode()
# # s = ""
# # print(mes.decode())
# # print(mes)
# mes = b64decode(file)
# # print(mes)
# mes = b64encode(mes)
# # print(mes)
# print("\n\n\n\n\n\n\n\n\n\n\n")
#
# print(file)
# # a = b"\xe8y\xff/t\x89/\xce%\xcb\xdc\xdd\x00\x00\x00\x00IEND\xaeB`\x82"
# a = file
# print("\n\n\n")
# print(chr(a[0]))
# print(ord(chr(a[0])))
# res = ""
# for i in a:
#     res += chr(i)
# print(f"res = {res}")
#
#
# print(f"str(a) = {str(a)}")
# result = bytes(res, 'raw_unicode_escape')
# print(f"bytes(res, 'raw_unicode_escape') = {result}")
# print(file[len(file) - 1])
# encryptFile.write(result)
