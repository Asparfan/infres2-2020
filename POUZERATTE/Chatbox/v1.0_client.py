#!/usr/bin/python2.7
# -*-coding:utf-8 -*

# @author Alexis Pouzeratte - INFRES11
# @version 1.0
# 1. Client/Serveur monothread

import socket
import sys

_PORT = 8888
_HOST = socket.gethostbyname('localhost')
_EXIT_STRINGS = "Extinction de la connexion."


# Création du socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# Liaison du socket à notre configuration d'@
try:
	client.connect((_HOST, _PORT))
except socket.error, exc:
	print("La liaison au server a échoué...\nFin du programme.")
	sys.exit()
print("Connexion au serveur établie.")

msgServer = client.recv(1024)

while 1:
	if msgServer.upper() in _EXIT_STRINGS.upper():
		break	
	print("Server >>", msgServer)
	msgClient = raw_input("Client >> ")
	client.send(msgClient)
	msgServer = client.recv(1024)
 
# Fermeture de la connexion
print("Connexion interrompue.")
client.close()