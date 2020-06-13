import socket, sys
from cryptography.hazmat.backends import default_backend as backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding , PublicFormat

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

def receive(connexion,key):
    ## Attends de recevoir des données
    data = key.decrypt(connexion.recv(1024))
    print("%s:%d ->> %s"%(host,port,data))
    return data

def emit(connexion,key):
    ## On formule la réponse à envoyer
    answer = input("Client ->> ")
    connexion.send(key.encrypt(answer.encode()))
    return answer

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

############    Initialisation    ############
# On essaye de se connecter
host,port,timeout = config()
target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
  key = keychain() 
  target.connect((host, port))
  target.settimeout(timeout)
except socket.error:
  print("La connexion a échoué.")
  sys.exit()
############    Initialisation    ############

############    Corps    ############
try:
    print("Connexion établie avec le serveur %s:%d"%(host,port))
    # Echange de clés
    target.send(key.pu_key_compressed)
    server_key = target.recv(74)
    # Calcul du secret
    key.trade(server_key)
    while True:
          answer = emit(target,key)
          if answer.upper() == "LAMA":
              break
          data = receive(target,key)
          ## Le cas chaîne vide ou LAMA est une rupture de connexion
          if data.upper() == "LAMA":
              break

except socket.timeout:
    # En cas de timeout côté client on romp la connexion
    target.send(key.encrypt("Lama".encode()))
############    Corps    ############

############    Fin    ############
target.close()
############    Fin    ############