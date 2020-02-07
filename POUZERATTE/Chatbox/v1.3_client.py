#!/usr/bin/env python3

"""
@author Alexis Pouzeratte - INFRES11
@version 1.2
1. Client/Serveur monothread
~. Stockage des messages en DB 
2. Chiffrement des messages en AES256-GCM
3. Authentification par challenge
"""

import socket
import sys
import hashlib
import json

from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES

_PORT = 8181
_HOST = socket.gethostbyname('localhost')
_EXIT_STRINGS = "Extinction de la connexion."
_WRONG_USER_SERV = "WrongUser"
_WRONG_USER = "Identifiants incorrect."
_SALT = "za!oe@rpk12zfd"

# Client PassWord = p@ss123

class security:
    def __init__(self, key):
        self.json_k = [ 'nonce', 'msg_encrypted', 'tag' ]
        self.key = key

    def encrypt(self, msg):
        cipher = AES.new(self.key, AES.MODE_GCM)
        msg_encrypted, tag = cipher.encrypt_and_digest(msg)
        json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, msg_encrypted, tag) ]  
        enc = json.dumps(dict(zip(self.json_k, json_v))).encode('utf-8')
        return enc

    def decrypt(self, msg):
        try:
            msg = json.loads(msg)
            jv = {k:b64decode(msg[k]) for k in self.json_k}
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=jv['nonce'])
            msg_decrypted = cipher.decrypt_and_verify(jv['msg_encrypted'], jv['tag']).decode()
        except (ValueError, KeyError):
            print("Déchiffrement incorrect.. !")
            return ("", 0)
        
        return (msg_decrypted, 1)

    def get_hsaltpass(password, noise=_SALT):
        key = hashlib.sha256((password+noise).encode()).hexdigest()
        return key

def main():
    # Création du socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

    # Liaison du socket à notre configuration d'@
    try:
        client.connect((_HOST, _PORT))
    except socket.error:
        print("La liaison au serveur a échoué...\nFin du programme.")
        sys.exit()
    
    print("Connexion au serveur établie.")
    print("Veillez vous connecter :")

    username = input("Username : ")
    password = input("Password : ")
    client.send(username.encode("utf-8"))

    msgServer = client.recv(1024)
    if msgServer == _WRONG_USER_SERV:
        print(_WRONG_USER)
        client.close()
        sys.exit()
    else:
        rnd = msgServer
        rnd = msgServer.decode()

    hsaltpass = security.get_hsaltpass(password)
    challenge = security.get_hsaltpass(hsaltpass, rnd)
    sc = security(challenge[:32].encode("utf-8"))

    client.send(challenge.encode("utf-8"))

    while 1:
        msgServer = sc.decrypt(client.recv(1024).decode("utf-8"))
        if msgServer[1] == 0:
            print("Mauvais mot de passe...")
            break
        else:
            msgServer = msgServer[0]

        if msgServer.upper() == _EXIT_STRINGS.upper():
            break
        print("Server >>", msgServer)
        msgClient = input("Client >> ")
        client.send(sc.encrypt(msgClient.encode("utf-8")))
     
    # Fermeture de la connexion
    print("Connexion interrompue.")
    client.close()

if __name__ == '__main__':
    status = main()
    sys.exit(status)