#!/usr/bin/python2.7
# -*-coding:utf-8 -*

# @author Alexis Pouzeratte - INFRES11
# @version 1.0
# 1. Client/Serveur monothread

import socket
import sys

_PORT = 8888
_HOST = socket.gethostbyname('localhost')
_ACTIVE_CONN = 0
_MSG_CONN = "Vous êtes connecté au serveur chatbox."
_EXIT_STRINGS = ["QUIT", "EXIT", "FIN", "TERMINE", "TERMINER", ""]

# Création du socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# Liaison du socket à notre configuration d'@
try:
	server.bind((_HOST, _PORT))
except socket.error:
	print("La liaison au socket a échoué...\nFin du programme.")
	sys.exit()

print("Serveur connecté : attente de client...")

# Attente de clients
while True:
	server.listen(2)

	conn, adr = server.accept()
	_ACTIVE_CONN += 1

 	print("Client connecté, adresse IP %s, port %s" % (adr[0], adr[1]))

 	conn.send(_MSG_CONN)
 	msgClient = conn.recv(1024)

 	while True:
 		print("Client >> ", msgClient)
 		if msgClient.upper() in _EXIT_STRINGS:
			break
		msgServer = raw_input("Server >> ")
		conn.send(msgServer)
		msgClient = conn.recv(1024)

	# On est sorti de la boucle, on ferme la connexion du client
	conn.send("Extinction de la connexion.")
	print("Connexion interrompue.")
	conn.close()

	choice = raw_input("<C>lient suivant -- <T>erminer ?")
	if choice.upper() == "T":
		break

server.close()
print("Extinction du serveur...")
sys.exit()