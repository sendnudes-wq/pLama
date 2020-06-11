
host = '127.0.0.1'
port = 25519
 
import socket, sys, threading
 
class ThreadRec(threading.Thread):
  """objet thread gérant la réception des messages"""
  def __init__(self, conn):
      threading.Thread.__init__(self)
      self.connexion = conn	     # réf. du socket de connexion
    
  def run(self):
      while True:
          data = self.connexion.recv(1024).decode("Utf8")
          if data == "" or data.upper() == "LAMA":
              break
############    Initialisation    ############
# On essaye de se connecter
target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
  target.connect((host, port))
except socket.error:
  print("La connexion a échoué.")
  sys.exit()
print("Connexion établie avec le serveur %s:%d"%(host,port))
############    Initialisation    ############

############    Corps    ############
#th = ThreadRec(target)
#th.start()
while True:
          ## Attends de recevoir des données
          data = target.recv(1024).decode("Utf8")
          print("%s:%d ->> %s"%(host,port,data))
          ## Le cas chaîne vide ou LAMA est une rupture de connexion
          if data.upper() == "LAMA":
              break
          ## On formule la réponse à envoyer
          answer = input("Client ->> ")
          target.send(answer.encode("Utf8"))
############    Corps    ############

############    Fin    ############
#th.join(None)
target.close()
############    Fin    ############