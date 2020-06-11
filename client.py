
host = '127.0.0.1'
port = 25519
 
import socket, sys, threading
 
class ThreadRec(threading.Thread):
  """objet thread gérant la réception des messages"""
  def __init__(self, conn):
      threading.Thread.__init__(self)
      self.connexion = conn	     # réf. du socket de connexion
    
  def run(self):
      answer = "Lama"
      self.connexion.send(answer.encode("Utf8"))

############    Initialisation    ############
# On essaye de se connecter
target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
  target.connect((host, port))
except socket.error:
  print("La connexion a échoué.")
  sys.exit()
print("Connexion établie avec le serveur. (%s:%d)"%(host,port))
############    Initialisation    ############

############    Corps    ############
th = ThreadRec(target)
th.start()
############    Corps    ############

############    Fin    ############
th.join()
target.close()
############    Fin    ############