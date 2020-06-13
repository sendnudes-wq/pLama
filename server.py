import socket #socketserver ? :o
import sys
import threading
from cryptography.hazmat.backends import default_backend as backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding , PublicFormat

###############################################################################
                          #Fonctions#
###############################################################################
def get_size(x,base):
        size = 1
        if type(x) == bytes:
            x = int.from_bytes(x,byteorder=sys.byteorder)
        while x >= base:
            x = x / base
            size += 1
        return size        

def xor(a,b):
    if type(a) == bytes:
        xa = int.from_bytes(a,byteorder=sys.byteorder)
    else:
        xa = a
    if type(b) == bytes:
        xb = int.from_bytes(b,byteorder=sys.byteorder)
    else:
        xb = b
    x = xa ^ xb
    return x.to_bytes(len(a),sys.byteorder)
    
def config():
    file = open("server.lama","r")

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

###############################################################################
                          #Objets#
###############################################################################
class keychain():
    """ Objet utilise pour l'EECDH.Genere une paire de cle dans le domaine 'curve' , par defaut SECP256K1 ,
        et permet la derivation du secret (hash par defaut sha256) ainsi que le chiffrement/dechiffrement symetrique de donnees
        (le secret devrais etre ephemere)
    """
    def __init__(self,curve=ec.SECP256K1(),hash_for_derivation=hashes.SHA256()):
        self.curve = curve
        self.hash = hash_for_derivation
        self.pr_key = ec.generate_private_key(self.curve,backend())
        # Du type cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey
        self.pu_key = self.pr_key.public_key()
        # Au format x962 compressé -> b'0x04.....'
        self.pu_key_compressed = self.pu_key.public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
           
    def trade(self,peer_key):
        # On ne garde que la forme non compressé -> cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey
        if type(peer_key == bytes):
            peer_key = ec.EllipticCurvePublicKey.from_encoded_point(self.curve,peer_key)
        self.peer_key = peer_key
        self.raw_secret = self.pr_key.exchange(ec.ECDH(),peer_key)
        self.secret = HKDF(algorithm=self.hash,length=len(self.raw_secret),salt=None,info=b"Je suis le roi des Chameaux",backend=backend()).derive(self.raw_secret)
    
    def derivate(self):
        """ On presuppose qu'il y'a deja eu un appel de self.trade"""
        self.raw_secret = self.secret
        self.secret = HKDF(algorithm=hashes.SHA256(),length=len(self.raw_secret),salt=None,info=b"Je suis le roi des Chameaux",backend=backend()).derive(self.raw_secret)
     
    def decrypt(self,data):
        """ On presuppose qu'il y'a deja eu un appel de self.trade"""
        return xor(self.secret,data)
    
    def encrypt(self,data):
        """ On presuppose qu'il y'a deja eu un appel de self.trade"""
        return xor(self.secret,data)
        
    def show(self):
        print("Couple (k,kP):\n%d\n\n[%d ;\n%d]"%(self.pr_key.private_numbers().private_value,(self.pu_key.public_numbers()).x,(self.pu_key.public_numbers()).y))
 
## Chaque Thread sera une instance de cet objet
## On créera un Thread par client/connexion
class ThreadClient(threading.Thread):
  '''dérivation d'un objet thread pour gérer la connexion avec un client'''
  def __init__(self, conn,client):
      threading.Thread.__init__(self)
      self.connexion = conn
      self.key = keychain()
      self.client_addr = client[0]
      self.client_port = client[1]
  
  def receive(self):
      ''' Attends de recevoir des données et les décrypte'''
      self.data = self.key.decrypt(self.connexion.recv(1024))
      print("%s:%d ->> %s"%(self.client_addr,self.client_port,self.data))

  def emit(self):
      ''' On formule la réponse à envoyer '''
      self.answer = self.data
      self.connexion.send(self.key.encrypt(self.answer))
    
  def run(self):
      try:
          print("Nouveau client %s:%d"%(self.client_addr,self.client_port))
          # On fait l'échange de clés
          self.client_key = self.connexion.recv(74)
          self.connexion.send(self.key.pu_key_compressed)
          self.key.trade(self.client_key)
          while True:
              ## Attends de recevoir des données
              self.receive()
              ## Le cas LAMA est une rupture de connexion
              if self.data.upper() == "LAMA":
                  break
              self.emit()
              if self.answer.upper() == "LAMA":
                  break
          self.connexion.send(self.key.encrypt(self.data))
      except socket.timeout:
          self.connexion.send(self.key.encrypt(b"Lama"))
      print("Fin de la communication avec %s:%d"%(self.client_addr,self.client_port))
      self.connexion.close()



###############################################################################
                          #Programme#
###############################################################################

############    Initialisation    ############
### On réserve un port pour notre programme
host,port,max_connexion,timeout = config() 
port_app = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ## TCP/IP

try:
  port_app.bind((socket.gethostbyname(host), port))
except socket.error:
  print("La connexion a échoué.")
  sys.exit()
print("Serveur en écoute en %s:%d" % (host,port))
## Ouvre le port
port_app.listen()
## Compte le nombre de connexions qui ont été accepté depuis le début.
connexion_alive = 0
## On retient la référence aux threads que l'on a crée
th_list = {}
dict_entry = []
############    Initialisation    ############

############    Corps    ############
while max_connexion != connexion_alive:
    # Bloque le programme tant qu'il n'a pas reçu de demande de connexion
    connexion,client = port_app.accept()
    # On définit un timeout en fonction du fichier de configuration
    connexion.settimeout(timeout)
    # On crée un nouveau thread pour la connexion
    th = ThreadClient(connexion,client)
    # Désormais c'est th qui gère le client
    th.start()
    
    # On garde une liste des id et un dictionnaire des thread
    th_id = th.getName()	  # identifiant du thread
    dict_entry.append(th_id)
    th_list[th_id] = connexion
    connexion_alive += 1

############    Corps    ############

############    Fin    ############
port_app.close()
############    Fin    ############