import CryptoUser

user_1 = CryptoUser.cryptoUser("Andy")
user_2 = CryptoUser.cryptoUser("Ivan")

CryptoUser.send_message_as_shamir(user_1, user_2, "text")

CryptoUser.send_message_as_DeffiHelfman_Ceaser(user_1, user_2, "text")

CryptoUser.send_message_as_ElGamal(user_1, user_2, "text")

CryptoUser.send_message_as_RSA(user_1, user_2, "text")


CryptoUser.send_message_as_Verman(user_1, user_2, "text")