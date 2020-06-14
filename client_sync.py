import socket, sys
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
def get_file_size(name):
    for_size = open(name,"rb")
    char = 1
    c = for_size.read(1)
    while c != b"":
        char += 1
        c = for_size.read(1)
    for_size.close()
    return char

def xor(a,b):
    size = min(len(a),len(b))
    xa = int.from_bytes(a[:size],byteorder=sys.byteorder)
    xb = int.from_bytes(b[:size],byteorder=sys.byteorder)
    x = xa ^ xb
    return x.to_bytes(size,sys.byteorder)
    
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

def emit_chat(connexion,key,d_size):
    ## On formule la réponse à envoyer
    answer = input("Client ->> ")
    connexion.send(key.encrypt(answer.encode()))
    return (answer,d_size)

def emit_data(connexion,key,d_size):
    ## On formule la réponse à envoyer
    answer = file.read(32)
    connexion.send(key.encrypt(answer))
    d_size -= 32
    return (answer,d_size)

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

###############################################################################
                          #Programme#
###############################################################################
############    Initialisation    ############
## Défini si le client souhaite s'en servir pour échanger des messages ou des fichiers
choice = "" ## A ne pas supprimer !!!!!
while choice != "C" and choice != "F":
    choice = (input("<C>hat ou transfert de <F>ichier ou <Q>uitter ?")).upper()
    if choice == "C":
        emit = emit_chat
        data_size = 2
        new_name = "chat.lama"
    elif choice == "F":
        emit = emit_data
        filename = input("Le nom du fichier a envoyer : ")
        try: 
            data_size = get_file_size(filename)
            file = open(filename,"rb")
            new_name = input("(Optionnel) Quel nom sur le serveur ?")
            if new_name == "":
                new_name = "default.lama"
        except FileNotFoundError:
            print("File not found")
            choice = ""    
    elif choice == "Q":
        print("A bientôt :D")
        sys.exit()
    else:
        print("Choix non reconnu.")    
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
    server_key = target.recv(74) ## La taille finale des "paquets" seront de 10+32+32octets
    # Calcul du secret
    key.trade(server_key)
    ##### N'est pas inclus dans le protocole pLama
    target.send(key.encrypt(new_name.encode())) # Dans le cadre du chat , le fichier s'appel chat.lama
    key.derivate()
    target.recv(74)
    #####
    while data_size > 1:
          (answer,data_size) = emit(target,key,data_size)
          #if answer.upper() == "LAMA":
          #    break
          key.derivate()
          data = receive(target,key)
          ## Le cas chaîne vide ou LAMA est une rupture de connexion
          if data.upper() == b"LAMA":
              break
    target.send(key.encrypt("Lama".encode())) ## La rupture finale sera indiqué par la gestion des flags
except socket.timeout:
    # En cas de timeout côté client on romp la connexion
    target.send(key.encrypt("Lama".encode()))
############    Corps    ############

############    Fin    ############
if choice == "F":
    file.close()
target.close()
############    Fin    ############