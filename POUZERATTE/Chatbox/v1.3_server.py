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
import sqlite3
import time
import hashlib
import json
import random
import string

from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES

_PORT = 8181
_HOST = socket.gethostbyname('localhost')
_MSG_CONN = "Vous êtes connecté au serveur chatbox. Bienvenue (/*_*)/"
_EXIT_STRINGS = ["QUIT", "EXIT", "FIN", "TERMINE", "TERMINER", ""]
_WRONG_USER_SERV = "WrongUser"

# Liaison avec la base de données SQLite3
class database:
    _DB_INSERT_MESSAGES = "INSERT INTO messages (ip, port, `time`, message, isServer) \
                            VALUES (?, ?, ?, ?, ?)"
    _DB_SELECT_USER_HSALTPASS = "SELECT hsaltPass FROM users WHERE name=?"

    def __init__(self, db_name):
        self.db_conn = self.db_connect(db_name)
        self.db_curs = self.db_cursor()
        print("Connection à la base de données réussie.")

    def db_connect(self, db_name):
        try:
            db_conn = sqlite3.connect(db_name)
        except sqlite3.error:
            print("La connexion à la base de données a échouée...\nFin du programme.")
            sys.exit()
        return db_conn

    def db_cursor(self):
        try:
            db_curs = self.db_conn.cursor()
        except sqlite3.error:
            print("La création du curseur a échouée...\nFin du programme.")
            sys.exit()
        return db_curs

    def db_save_msg(self, ip, port, msg, isServer=False, curr_time=0):
        if curr_time == 0:
            curr_time = int(time.time())
        self.tmp = (ip, port, curr_time, msg, isServer)
        self.db_curs.execute(self._DB_INSERT_MESSAGES, self.tmp)
        self.db_conn.commit()

    def db_get_hsaltPass(self, username):
        self.db_curs.execute(self._DB_SELECT_USER_HSALTPASS, (username,))
        rows = self.db_curs.fetchall()
        if len(rows) != 1:
            return 0
        res = rows[0]
        return res

    def db_close(self):
        self.db_conn.close()

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

    def get_hsaltpass(password, noise):
        key = hashlib.sha256((password+noise).encode()).hexdigest()
        return key


def random_string(lenght):
    dic = string.ascii_letters + string.digits
    return ''.join(random.choice(dic) for i in range(lenght))

# ------------
# --- Main ---
# ------------
def main():
    db = database('v1.3_database.db')
    # Création du socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

    # Liaison du socket à notre configuration d'@
    try:
        server.bind((_HOST, _PORT))
    except socket.error:
        print("La liaison au socket a échouée...\nFin du programme.")
        sys.exit()

    print("Serveur connecté.")
    print("Attente de client...")

    # Attente de clients
    while True:
        server.listen(2)
        conn, adr = server.accept()
        print("Demande de connection : adresse IP %s, port %s" % (adr[0], adr[1]))
        print("Authentification...")

        username = conn.recv(1024).decode("utf-8")
        hsaltpass = db.db_get_hsaltPass(username)
        if hsaltpass == 0:
            conn.send(_WRONG_USER_SERV.encode("utf-8"))
            print("Identifiants incorrects !")
            choice = input("<C>lient suivant -- <T>erminer ?")
            if choice.upper() == "T":
                break
            conn.close()
            continue
        else:
            hsaltpass = hsaltpass[0]
        rnd = random_string(16)
        conn.send(rnd.encode("utf-8"))
        cmp_client = conn.recv(1024).decode("utf-8")
        challenge = security.get_hsaltpass(hsaltpass, rnd)

        if challenge != cmp_client:
            print("Mauvais mot de passe !")
            conn.send("Who cares ?".encode("utf-8"))
        else:
            sc = security(challenge[:32].encode("utf-8"))
            conn.send(sc.encrypt(_MSG_CONN.encode('utf-8')))
            print("Client connecté !")
            
            while True:
                msgClient = conn.recv(1024).decode("utf-8")
                db.db_save_msg(adr[0], adr[1], msgClient)
                msgClientDecrypted = sc.decrypt(msgClient)
                if msgClientDecrypted[1] == 0:
                    print("Mauvais mot de passe...")
                    break
                else:
                    msgClientDecrypted = msgClientDecrypted[0]

                if msgClientDecrypted.upper() in _EXIT_STRINGS:
                    print("Signal d'extinction envoyé par le client : %s" % msgClientDecrypted)
                    break

                print("Client >> ", msgClientDecrypted)
                msgServer = input("Server >> ")
                msgServerEncrypted = sc.encrypt(msgServer.encode("utf-8"))
                db.db_save_msg(adr[0], adr[1], msgServerEncrypted, True)
                conn.send(msgServerEncrypted)

            # On est sorti de la boucle, on ferme la connexion du client
            conn.send(sc.encrypt("Extinction de la connexion.".encode("utf-8")))
            print("Connexion interrompue.")
            conn.close()

        choice = input("<C>lient suivant -- <T>erminer ?")
        if choice.upper() == "T":
            break

    server.shutdown(socket.SHUT_RDWR)
    server.close()
    print("Extinction du serveur...")
    db.db_close()

if __name__ == '__main__':
    status = main()
    sys.exit(status)