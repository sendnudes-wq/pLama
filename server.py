import socket #socketserver ? :o
import sys
import threading
from cryptography.hazmat.backends import default_backend as backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding , PublicFormat

HEADER_SIZE = 9
DATA_SIZE = 63
COMPLETION_SIZE = 1
PAQUET_SIZE = HEADER_SIZE+DATA_SIZE+COMPLETION_SIZE
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
    size = min(len(a),len(b))
    xa = int.from_bytes(a[:size],'little')
    xb = int.from_bytes(b[:size],'little')
    x = xa ^ xb
    return x.to_bytes(size,'little')
    
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

def complete(s):
    l = len(s)
    comp = (DATA_SIZE - l)
    return comp.to_bytes(1,'little')+s+comp*b"~"

def shortcut(s):
    l = (DATA_SIZE-s[0])+1
    return s[1:l]


###############################################################################
                          #Objets#
###############################################################################
class keychain():
    """ Objet utilise pour l'EECDH.Genere une paire de cle dans le domaine 'curve' , par defaut SECP256K1 ,
        et permet la derivation du secret (hash par defaut shea512) ainsi que le chiffrement/dechiffrement symetrique de donnees
        (le secret devrais etre ephemere)
    """
    def __init__(self,curve=ec.SECP256K1(),hash_for_derivation=hashes.SHA512()):
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
        self.secret = HKDF(algorithm=hashes.SHA512(),length=len(self.raw_secret),salt=None,info=b"Je suis le roi des Chameaux",backend=backend()).derive(self.raw_secret)
     
    def decrypt(self,data):
        """ On presuppose qu'il y'a deja eu un appel de self.trade"""
        return shortcut(xor(self.secret,data))
    
    def encrypt(self,data):
        """ On presuppose qu'il y'a deja eu un appel de self.trade"""
        return xor(self.secret,complete(data))
        
    def show(self):
        print("Couple (k,kP):\n%d\n\n[%d ;\n%d]"%(self.pr_key.private_numbers().private_value,(self.pu_key.public_numbers()).x,(self.pu_key.public_numbers()).y))
 
class hat():
    class RMP(Exception):
        '''Rien a signaler'''
        pass
    
    class AH(Exception):
        '''Probleme dans le header'''
        pass
    
    class Banana(Exception):
        '''Pacquet refuse'''
        pass
    
    class Fromage(Exception):
        '''Format du pacquet non support'''
        pass
           
    
    def __init__(self,SRC,DST,CRYPT=1,FST=0,LST=0,ACK=0,MODE=0,Err=0,ID=0):
        self.src = SRC % 2**16
        self.dst = DST % 2**16
        self.crypt = CRYPT % 2
        self.fst = FST % 2
        self.lst = LST % 2
        self.ack = ACK % 2
        self.mode = MODE % 4
        self.max_ID = 2**(8+8*self.mode)-1
        self.err = Err % 4
        self.id = ID % self.max_ID
    
    def toBytes(self):
        self.flags = (8*self.crypt + 4*self.fst + 2*self.lst + self.ack)
        self.mod_n_err = (4*self.mode + self.err)
        self.port_part = self.src.to_bytes(2,'big') + self.dst.to_bytes(2,'big')
        self.info_part = (16*self.flags + self.mod_n_err).to_bytes(1,'big')
        self.id_part = (self.id).to_bytes(4,'big')
        return self.port_part+self.info_part+self.id_part
    
    @classmethod    
    def fromBytes(cls,head):
        SRC = 256*head[0]+head[1]
        DST = 256*head[2]+head[3]
        CRYPT = (head[4] >> 7 ) % 2
        FST = (head[4] >> 6) % 2
        LST = (head[4] >> 5) % 2
        ACK = (head[4] >> 4) % 2
        MODE = (head[4] >> 2) % 4
        Err = head[4]%4
        ID = int.from_bytes(head[5:9],'big')
        return hat(SRC,DST,CRYPT,FST,LST,ACK,MODE,Err,ID)

    def forBreakConn(self):
        SRC = self.src
        DST = self.dst
        CRYPT = self.crypt
        MODE = self.mode
        ID = self.id
        return (hat(SRC,DST,CRYPT=CRYPT,LST=1,ACK=1,MODE=MODE,ID=ID))

    def yes(self):
        plop = self.src
        self.src = self.dst
        self.dst = plop
        self.ack = (self.ack + 1)%2
    
    def idPlus(self):
        if self.id == 0 and self.lst == 1:
            raise self.Banana("La connexion ne peut pas gerer plus de donnees (retentez avec un autre mode)")
        elif self.id == self.max_ID:
            self.lst = 1
        self.id = (self.id+1) % (self.max_ID+1)
        
    def show(self):
        print(self.src,self.dst,self.crypt,self.fst,self.lst,self.ack,self.mode,self.err,self.id)
   
## Chaque Thread sera une instance de cet objet
## On créera un Thread par client/connexion
class ThreadClient(threading.Thread):
  '''dérivation d'un objet thread pour gérer la connexion avec un client'''
  def __init__(self, conn,client):
      threading.Thread.__init__(self)
      self.connexion = conn
      self.key = keychain(curve=ec.BrainpoolP512R1())
      self.client_addr = client[0]
      self.client_port = client[1]
      self.header = hat(port,self.client_port)

  def get_filename(self):
      self.raw_data = self.connexion.recv(PAQUET_SIZE)
      self.header = hat.fromBytes(self.raw_data[:HEADER_SIZE])
      self.filename = self.key.decrypt(self.raw_data[HEADER_SIZE:])  
      self.key.derivate()
      self.header.yes()
      self.connexion.send(self.header.toBytes()+self.key.encrypt(self.filename))

  def receive_chat(self):
      ''' Attends de recevoir des données et les décrypte'''
      self.raw_data = self.connexion.recv(PAQUET_SIZE)
      self.raw_header = hat.fromBytes(self.raw_data[:HEADER_SIZE])
      self.data = self.key.decrypt(self.raw_data[HEADER_SIZE:])
      self.script.write(b"Client >>"+self.data+b"\n")
      self.key.derivate()
      print("%s:%d ->> %s"%(self.client_addr,self.client_port,self.data))
      
  def receive_data(self):
      ''' Attends de recevoir des données et les décrypte'''
      self.raw_data = self.connexion.recv(PAQUET_SIZE)
      self.raw_header = hat.fromBytes(self.raw_data[:HEADER_SIZE])
      self.data = self.key.decrypt(self.raw_data[HEADER_SIZE:])
      self.script.write(self.data)
      self.key.derivate()
      print("%s:%d ->> %s"%(self.client_addr,self.client_port,self.data))

  def emit_chat(self):
      ''' On formule la réponse à envoyer '''
      self.answer = self.data
      self.header = self.raw_header
      self.header.yes()
      self.script.write(b"Serveur >>"+self.answer+b"\n")
      self.connexion.send(self.header.toBytes()+self.key.encrypt(self.answer))
      self.key.derivate()

  def emit_data(self):
      ''' On formule la réponse à envoyer '''
      self.answer = self.data
      self.header = self.raw_header
      self.header.yes()
      self.connexion.send(self.header.toBytes()+self.key.encrypt(self.answer))
      self.key.derivate()
  
  
  def run(self):
      try:
          print("Nouveau client %s:%d"%(self.client_addr,self.client_port))
          # On fait l'échange de clés , le point compressé fait 65octets
          self.raw_data = self.connexion.recv(PAQUET_SIZE+1)
          self.raw_header = hat.fromBytes(self.raw_data[:HEADER_SIZE])
          self.header = self.raw_header
          self.header.yes()
          self.client_key = self.raw_data[HEADER_SIZE:]
          self.connexion.send(self.header.toBytes()+self.key.pu_key_compressed)
          self.key.trade(self.client_key)
          ##### N'est pas inclus dans le protocole pLama
          self.get_filename()
          if self.filename == b"chat.lama":
              self.emit = self.emit_chat
              self.receive = self.receive_chat
          else:
              self.emit = self.emit_data
              self.receive = self.receive_data
          self.script = open(self.filename.decode(),"wb")       
          #####
          while True:
              ## Attends de recevoir des données           
              self.receive()   
              ## Le cas LAMA est une rupture de connexion            
              if self.data.upper() == b"LAMA" or self.data == b"":
                  break
              self.emit()
              if self.answer.upper() == b"LAMA":
                  break
          self.script.close()
          self.connexion.send(self.header.forBreakConn().toBytes()+self.key.encrypt(self.data))
      except socket.timeout:
          self.connexion.send(self.header.forBreakConn().toBytes()+self.key.encrypt(b"Lama"))
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