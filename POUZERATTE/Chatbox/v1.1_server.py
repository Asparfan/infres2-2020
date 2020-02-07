#!/usr/bin/env python3

"""
@author Alexis Pouzeratte - INFRES11
@version 1.1
1. Client/Serveur monothread
~. Stockage des messages en DB 
"""

import socket
import sys
import sqlite3
import time

_PORT = 8888
_HOST = socket.gethostbyname('localhost')
_MSG_CONN = "Vous êtes connecté au serveur chatbox.Bienvenue (/*_*)/"
_EXIT_STRINGS = ["QUIT", "EXIT", "FIN", "TERMINE", "TERMINER", ""]

# Liaison avec la base de données SQLite3
class database:
    _DB_INSERT_MESSAGES = "INSERT INTO messages (ip, port, `time`, message, isServer) \
                            VALUES (?, ?, ?, ?, ?)"

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

    def db_close(self):
        self.db_conn.close()
        
# ------------
# --- Main ---
# ------------
def main():
    db = database('v1.1_database.db')
    # Création du socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

    # Liaison du socket à notre configuration d'@
    try:
        server.bind((_HOST, _PORT))
    except socket.error:
        print("La liaison au socket a échouée...\nFin du programme.")
        sys.exit()

    print("Serveur connecté : attente de client...")

    # Attente de clients
    while True:
        server.listen(2)

        conn, adr = server.accept()

        print("Client connecté, adresse IP %s, port %s" % (adr[0], adr[1]))

        conn.send(_MSG_CONN.encode("utf-8"))
        
        while True:
            msgClient = conn.recv(1024).decode("utf-8")
            db.db_save_msg(adr[0], adr[1], msgClient)

            if msgClient.upper() in _EXIT_STRINGS:
                print("Signal d'extinction envoyé par le client.")
                break

            print("Client >> ", msgClient)
            msgServer = input("Server >> ")
            db.db_save_msg(adr[0], adr[1], msgServer, True)
            conn.send(msgServer.encode("utf-8"))

        # On est sorti de la boucle, on ferme la connexion du client
        conn.send("Extinction de la connexion.".encode("utf-8"))
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