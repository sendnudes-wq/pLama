import socket, sys, threading , time
 
class ThreadRec(threading.Thread):
  """objet thread gérant la réception des messages"""
  def __init__(self, conn,msg):
      threading.Thread.__init__(self)
      self.connexion = conn	     # réf. du socket de connexion
      self.data = msg
    
  def run(self):
      while True:
          ## Attends de recevoir des données
          self.data = self.connexion.recv(1024).decode("Utf8")
          print("%s:%d ->> %s"%(host,port,self.data))
          ## Le cas LAMA est une rupture de connexion
          if self.data.upper() == "LAMA":
              break
      

class ThreadEmi(threading.Thread):
  """objet thread gérant la réception des messages"""
  def __init__(self, conn,msg):
      threading.Thread.__init__(self)
      self.connexion = conn	     # réf. du socket de connexion
      self.answer = msg
  def run(self):
      while True:
          ## On formule la réponse à envoyer
          self.answer = input("Client ->> ")
          self.connexion.send(self.answer.encode("Utf8"))
          if self.answer.upper() == "LAMA":
              break
          

def config():
    file = open("client.lama","r")

    #Default Values
    host = "127.0.0.1"
    port = 25519
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

            if carac.upper() == "HOST":
                host = value
            elif carac.upper() == "PORT":
                port = int(value)
            elif carac.upper() == "TIMEOUT":
                if value.upper() != "NONE":
                    time_out = float(value)
        data = file.readline()

    file.close()
    return (host,port,time_out)    
############    Initialisation    ############
host,port,timeout = config() 
target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
  target.connect((host, port))
  target.settimeout(timeout)
except socket.error:
  print("La connexion a échoué.")
  sys.exit()
print("Connexion établie avec le serveur %s:%d"%(host,port))
data = []
answer = []
############    Initialisation    ############

############    Corps    ############
th_r = ThreadRec(target,data)
th_e = ThreadEmi(target,answer)
th_r.start()
th_e.start()
'''while True:
          ## Attends de recevoir des données
          data = target.recv(1024).decode("Utf8")
          print("%s:%d ->> %s"%(host,port,data))
          ## Le cas chaîne vide ou LAMA est une rupture de connexion
          if data.upper() == "LAMA":
              break
          ## On formule la réponse à envoyer
          answer = input("Client ->> ")
          target.send(answer.encode("Utf8"))
          if answer.upper() == "LAMA":
              break'''
############    Corps    ############

############    Fin    ############
th_r.join(None)
#target.send(("Lama").encode("Utf8"))
print("Fin de la communication")
target.close()
############    Fin    ############