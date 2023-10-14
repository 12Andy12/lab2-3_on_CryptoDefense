from random import randint
import CryptoDef


def str_to_list(message: str):
    res = []
    for i in message:
        res.append(ord(i))
    return res


def list_to_str(message: str):
    res = ""
    for i in message:
        res += chr(i)
    return res


class cryptoUser(object):
    P = 10001779
    G = 10000763
    Q = None

    @staticmethod
    def generate_Vernam_keys(message_size):
        cryptoUser.keys = [randint(0, 255) for i in range(message_size)]
        print("---------------------------------------------------------")
        print("Keys for Verman's code have been generated|")
        print("---------------------------------------------------------")

    @staticmethod
    def generate_parametrs():
        cryptoUser.Q = randint(0, 10 ** 9)
        cryptoUser.P = cryptoUser.Q * 2 + 1

        while not CryptoDef.ferma(cryptoUser.P) or not CryptoDef.ferma(cryptoUser.Q):
            cryptoUser.Q = randint(0, 10 ** 9)
            cryptoUser.P = cryptoUser.Q * 2 + 1

        cryptoUser.G = 2
        while cryptoUser.G < (cryptoUser.P - 1) and pow(cryptoUser.G, cryptoUser.Q, cryptoUser.P) != 1:
            cryptoUser.G += 1

        print("---------------------------------------------------------")
        print("Parametrs for Deffi-Helfman protocol have been completed|")
        print("---------------------------------------------------------")

    def __init__(self, name="None"):
        self.user_name = name
        # Деффи-Хелфман
        self.init_deffi_helfman_key()

        # Шамир
        self.generate_p()
        self.generate_CD()

    def init_deffi_helfman_key(self):
        self.__private_key = randint(10 ** 4, cryptoUser.P)
        self.__my_public_key = pow(cryptoUser.G, self.__private_key, cryptoUser.P)
        self.common_key = None

    def generate_CD(self):
        self.__C = CryptoDef.generate_friend_simple_numper(self.__p - 1)
        self.__D = CryptoDef.gcd(self.__p - 1, self.__C)[2]
        if (self.__D < 0):
            self.__D += self.__p - 1

    def generate_xC(self, message):
        res = []
        for i in message:
            res.append(pow(i, self.__C, self.__p))
        return res

    def generate_xD(self, x):
        res = []
        for i in x:
            res.append(pow(i, self.__D, self.__p))
        return res

    def generate_p(self):
        self.__p = CryptoDef.generate_simple_number(10 ** 4, 10 ** 9)

    def set_p(self, p):
        self.__p = p

    def get_p(self):
        return self.__p

    def get_my_private_key(self):
        return self.__private_key

    def get_my_public_key(self):
        return self.__my_public_key

    def get_my_common_key(self):
        return self.common_key

    def generate_common_key(self, other_public_key):
        self.other_public_key = other_public_key
        self.common_key = pow(self.other_public_key, self.__private_key, cryptoUser.P)

    def encrypt_message_as_Ceasar(self, message):
        encrypted_message = ""
        key = self.common_key
        for c in message:
            encrypted_message += chr(ord(c) + key % 10 + 1)
        return encrypted_message

    def decrypt_message_as_Ceasar(self, encrypted_message):
        decrypted_message = ""
        key = self.common_key
        for c in encrypted_message:
            decrypted_message += chr(ord(c) - key % 10 - 1)
        return decrypted_message

    def decrypt_message_as_ElGamal(self, message):
        return message * self.common_key % cryptoUser.P

    def encrypt_message_as_ElGamal(self, message):
        return message * pow(self.other_public_key, cryptoUser.P - 1 - self.__private_key, cryptoUser.P) % cryptoUser.P

    def generate_rsa_parametrs(self):
        self.__RSA_P = CryptoDef.generate_simple_number(10 ** 4, 10 ** 9)
        self.__RSA_Q = CryptoDef.generate_simple_number(10 ** 4, 10 ** 9)
        self.RSA_N = self.__RSA_P * self.__RSA_Q
        self.__RSA_F = (self.__RSA_P - 1) * (self.__RSA_Q - 1)
        self.RSA_D = CryptoDef.generate_friend_simple_numper(self.__RSA_F)
        self.__RSA_C = CryptoDef.gcd(self.RSA_D, self.__RSA_F)[1]

    def rsa_decrypt_message(self, message, other_D, other_N):
        return pow(message, other_D, other_N)

    def rsa_encrypt_message(self, message):
        return pow(message, self.__RSA_C, self.RSA_N)

    def Vernam_decrypt_message(self, message):
        return [message[i] ^ cryptoUser.keys[i] for i in range(len(message))]

    def Vernam_encrypt_message(self, message):
        return [message[i] ^ cryptoUser.keys[i] for i in range(len(message))]

def send_message_as_RSA(user1: cryptoUser(), user2: cryptoUser(), message):
    # user1.generate_rsa_parametrs()
    # print(f"{user1.user_name} generate rsa parametrs")
    user2.generate_rsa_parametrs()
    print(f"{user2.user_name} generate rsa parametrs")
    mes = str_to_list(message)
    decryptMes = []
    for i in mes:
        decryptMes.append(user1.rsa_decrypt_message(i, user2.RSA_D, user2.RSA_N))
    print(f"{user1.user_name} send message '{message}' as {decryptMes}")
    encryptMes = []
    for i in decryptMes:
        encryptMes.append(user2.rsa_encrypt_message(i))

    print(f"{user2.user_name} read message {decryptMes} as '{list_to_str(encryptMes)}'")



def send_message_as_ElGamal(user1: cryptoUser(), user2: cryptoUser(), message):
    cryptoUser.generate_parametrs()
    user1.init_deffi_helfman_key()
    user2.init_deffi_helfman_key()
    user1.generate_common_key(user2.get_my_public_key())
    user2.generate_common_key(user1.get_my_public_key())
    print(f"{user1.user_name}:\n"
          f"Privae_key = {hex(user1.get_my_private_key())}\n"
          f"Public_key = {hex(user1.get_my_public_key())}\n"
          f"Common_key = {hex(user1.get_my_common_key())}\n")

    print(f"{user2.user_name}:\n"
          f"Privae_key = {hex(user2.get_my_private_key())}\n"
          f"Public_key = {hex(user2.get_my_public_key())}\n"
          f"Common_key = {hex(user2.get_my_common_key())}\n")
    
    mes = str_to_list(message)
    decryptMes = []
    for i in mes:
        decryptMes.append(user1.decrypt_message_as_ElGamal(i))
        
    print(f"{user1.user_name} send message '{message}' as {decryptMes}")
    encryptMes = []
    for i in decryptMes:
        encryptMes.append(user2.encrypt_message_as_ElGamal(i))

    print(f"{user2.user_name} read message {decryptMes} as '{list_to_str(encryptMes)}'")
    
    
     

def send_message_as_DeffiHelfman_Ceaser(user1: cryptoUser(), user2: cryptoUser(), message):
    cryptoUser.generate_parametrs()
    user1.init_deffi_helfman_key()
    user2.init_deffi_helfman_key()
    user1.generate_common_key(user2.get_my_public_key())
    user2.generate_common_key(user1.get_my_public_key())
    print(f"{user1.user_name}:\n"
          f"Privae_key = {hex(user1.get_my_private_key())}\n"
          f"Public_key = {hex(user1.get_my_public_key())}\n"
          f"Common_key = {hex(user1.get_my_common_key())}\n")

    print(f"{user2.user_name}:\n"
          f"Privae_key = {hex(user2.get_my_private_key())}\n"
          f"Public_key = {hex(user2.get_my_public_key())}\n"
          f"Common_key = {hex(user2.get_my_common_key())}\n")

    mes = user1.decrypt_message_as_Ceasar(message)

    print(f"{user1.user_name} send mesage '{message}' as {mes}")
    print(f"{user2.user_name} read mesage {mes} as '{user2.encrypt_message_as_Ceasar(mes)}'")

def send_message_as_Verman(user1: cryptoUser(), user2: cryptoUser(), message):
    cryptoUser.generate_Vernam_keys(len(message))
    mes = str_to_list(message)
    decryptMes = user1.Vernam_decrypt_message(mes)
    print(f"{user1.user_name} send mesage '{message}' as {decryptMes}")
    encryptMes = user2.Vernam_encrypt_message(decryptMes)
    print(f"{user2.user_name} read mesage {decryptMes} as '{list_to_str(encryptMes)}'")




def send_message_as_shamir(user1: cryptoUser(), user2: cryptoUser(), message):
    message = str_to_list(message)
    user1.generate_p()
    p = user1.get_p()
    print(f"{user1.user_name} generated p and send it to {user2.user_name}:\n'{p}'\n")
    user2.set_p(p)
    print(f"{user1.user_name} get and set p:\n'{p}'\n")
    user1.generate_CD()
    user2.generate_CD()
    print(f"{user1.user_name} and {user2.user_name} generete C and D\n")

    print(f"{user1.user_name} send to {user2.user_name} message:\n'{list_to_str(message)}' <=> {message}\n")
    x1 = user1.generate_xC(message)
    print(f"{user1.user_name} generated x1 and send it to {user2.user_name}:\n'{x1}\n")
    x2 = user2.generate_xC(x1)
    print(f"{user2.user_name} generated x2 and send it to {user1.user_name}:\n{x2}\n")
    x3 = user1.generate_xD(x2)
    print(f"{user1.user_name} generated x3 and send it to {user2.user_name}:\n{x3}\n")
    x4 = user2.generate_xD(x3)
    print(f"{user2.user_name} generated x4 and read this:\n'{list_to_str(x4)}' <=> {x4}'")
