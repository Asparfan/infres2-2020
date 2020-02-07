#!/usr/bin/env python3

"""
@author Alexis Pouzeratte - INFRES11
@version 1.1
1. Client/Serveur monothread
~. Stockage des messages en DB 
"""

import socket
import sys

_PORT = 8888
_HOST = socket.gethostbyname('localhost')
_EXIT_STRINGS = "Extinction de la connexion."

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

    msgServer = client.recv(1024).decode("utf-8")

    while 1:
        if msgServer.upper() == _EXIT_STRINGS.upper():
            break
        print("Server >>", msgServer)
        msgClient = input("Client >> ")
        client.send(msgClient.encode("utf-8"))
        msgServer = client.recv(1024).decode("utf-8")
     
    # Fermeture de la connexion
    print("Connexion interrompue.")
    client.close()

if __name__ == '__main__':
    status = main()
    sys.exit(status)