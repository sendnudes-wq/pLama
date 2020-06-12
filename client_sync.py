 
import socket, sys

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
# On essaye de se connecter
host,port,timeout = config() 
target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
  target.connect((host, port))
  target.settimeout(timeout)
except socket.error:
  print("La connexion a échoué.")
  sys.exit()
print("Connexion établie avec le serveur %s:%d"%(host,port))
############    Initialisation    ############

############    Corps    ############
while True:
    try:
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
              break
    except socket.timeout:
          self.connexion.send(("Lama").encode("Utf8"))
############    Corps    ############

############    Fin    ############
target.close()
############    Fin    ############