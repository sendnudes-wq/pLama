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
          ## Le cas LAMA est une rupture de connexion
          if data.upper() == "LAMA":
              break
          ## On formule la réponse à envoyer
          answer = input("Server->> ")
          self.connexion.send(answer.encode("Utf8"))
      self.connexion.send((data).encode("Utf8"))
      self.connexion.close()
    
def config():
    file = open("config.lama","r")

    #Default Values
    host = "127.0.0.1"
    port = 25519
    max_co = -1
    time_out = None

    data = file.readline()
    while data != '':
        if data[0] != "#" and data[0] != '\n':
            len_carac = 0
            for letter in data:
                if letter == " ":
                    break
                else:
                    len_carac += 1
            carac = data[:len_carac]
            value = data[len_carac+1:-1]
            if carac.upper() == "MAXTOTALCONNEXION":
                if value.upper() != "INFINITY":
                    max_co = int(value)
            elif carac.upper() == "HOST":
                host = value
            elif carac.upper() == "PORT":
                port = int(value)
            elif carac.upper() == "TIMEOUT":
                if value.upper() != "NONE":
                    time_out = float(value)
        data = file.readline()

    file.close()
    return (host,port,max_co,time_out)
############    Initialisation    ############
### On réserve un port pour notre programme
host,port,max_connexion,timeout = config() 
port_app = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ## TCP/IP

try:
  port_app.bind((host, port))
except socket.error:
  print("La connexion a échoué.")
  sys.exit()
print("Serveur en écoute en %s:%d" % (host,port))
## Ouvre le port jusquà avoir accepté 2 connexion
port_app.listen(2)
connexion_alive = 0
############    Initialisation    ############

############    Corps    ############
while max_connexion != connexion_alive:
    # Bloque le programme tant qu'il n'a pas reçu de demande de connexion
    connexion,client = port_app.accept()
    connexion.settimeout(timeout)
    th = ThreadClient(connexion,client)
    th.start()	  # identifiant du thread
    connexion_alive += 1
############    Corps    ############

############    Fin    ############
port_app.close()
############    Fin    ############