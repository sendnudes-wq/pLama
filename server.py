
host = '127.0.0.1'
port = 25519

import socket #socketserver ? :o
import sys
import threading

## Chaque Thread sera une instance de cet objet
## On créera un Thread par client/connexion
class ThreadClient(threading.Thread):
  '''dérivation d'un objet thread pour gérer la connexion avec un client'''
  def __init__(self, conn,client):
      threading.Thread.__init__(self)
      self.connexion = conn
      self.client_addr = client[0]
      self.client_port = client[1]
  
   
  def run(self):
      print("Nouveau client %s:%d"%(self.client_addr,self.client_port))
      self.connexion.send(("Vive la Savoie !").encode("Utf8"))
      while True:
          ## Attends de recevoir des données
          data = self.connexion.recv(1024).decode("Utf8")
          print("%s:%d ->> %s"%(self.client_addr,self.client_port,data))
          ## Le cas chaîne vide ou LAMA est une rupture de connexion
          if data.upper() == "LAMA":
              break
          ## On formule la réponse à envoyer
          answer = input("Server->> ")
          self.connexion.send(answer.encode("Utf8"))
      self.connexion.send((data).encode("Utf8"))
      self.connexion.close()
    
############    Initialisation    ############
### On réserve un port pour notre programme
#still_alive = int(input("Combien de connexion avant de déco ?"))     
port_app = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ## TCP/IP
try:
  port_app.bind((host, port))
except socket.error:
  print("La connexion a échoué.")
  sys.exit()
print("Serveur en écoute en %s:%d" % (host,port))
## Ouvre le port jusquà avoir accepté 2 connexion
port_app.listen(2)
############    Initialisation    ############

############    Corps    ############
while True:
    # Bloque le programme tant qu'il n'a pas reçu de demande de connexion
    connexion,client = port_app.accept()
    th = ThreadClient(connexion,client)
    th.start()	  # identifiant du thread
############    Corps    ############

############    Fin    ############
port_app.close()
############    Fin    ############