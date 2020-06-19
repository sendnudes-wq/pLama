import socket, sys
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
    xa = int.from_bytes(a[:size],'little')
    xb = int.from_bytes(b[:size],'little')
    x = xa ^ xb
    return x.to_bytes(size,'little')
 
def complete(s):
    l = len(s)
    comp = (DATA_SIZE - l)
    return comp.to_bytes(1,'little')+s+comp*b"~"

def shortcut(s):
    l = (DATA_SIZE-s[0])+1
    return s[1:l]

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
    raw_data = connexion.recv(PAQUET_SIZE)
    raw_head = hat.fromBytes(raw_data[:HEADER_SIZE])
    data = key.decrypt(raw_data[HEADER_SIZE:])
    key.derivate()
    print("%s:%d ->> %s"%(host,port,data))
    return (raw_head,data)

def emit_chat(connexion,key,d_size):
    ## On formule la réponse à envoyer
    answer = input("Client:%d ->> "%(my_port))
    head.idPlus()
    head.yes()
    head.show()
    connexion.send(head.toBytes()+key.encrypt(answer.encode()))
    key.derivate()
    return (answer,d_size)

def emit_data(connexion,key,d_size):
    ## On formule la réponse à envoyer
    answer = file.read(DATA_SIZE)
    head.idPlus()
    head.yes()
    head.show()
    connexion.send(head.toBytes()+key.encrypt(answer))
    key.derivate()
    d_size -= len(answer)
    return (answer,d_size)

###############################################################################
                          #Objets#
###############################################################################
class keychain():
    """ Objet utilise pour l'EECDH.Genere une paire de cle dans le domaine 'curve' , par defaut SECP256K1 ,
        et permet la derivation du secret (hash par defaut sha512) ainsi que le chiffrement/dechiffrement symetrique de donnees
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
        '''Format du pacquet non supporte'''
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
        return cls(SRC,DST,CRYPT,FST,LST,ACK,MODE,Err,ID)

    def forKeyExch(self):
        SRC = self.src
        DST = self.dst
        CRYPT = self.crypt
        MODE = self.mode
        return hat(SRC,DST,CRYPT=CRYPT,FST=1,MODE=MODE)
           
    def forBreakConn(self):
        SRC = self.src
        DST = self.dst
        CRYPT = self.crypt
        MODE = self.mode
        ID = self.id
        return (hat(SRC,DST,CRYPT=CRYPT,LST=1,MODE=MODE,ID=ID))

    def forDataExch(self):
        SRC = self.src
        DST = self.dst
        CRYPT = self.crypt
        MODE = self.mode
        return hat(SRC,DST,CRYPT=CRYPT,MODE=MODE)

    def yes(self):
        plop = self.src
        self.src = self.dst
        self.dst = plop
        self.ack = (self.ack + 1) % 2
           
    def idPlus(self):
        if self.id == 0 and self.lst == 1:
            raise self.Banana("La connexion ne peut pas gerer plus de donnees (retentez avec un autre mode)")
        elif self.id == self.max_ID:
            self.lst = 1
        self.id = (self.id+1) % (self.max_ID+1)
        
    def show(self):
        print(self.src,self.dst,self.crypt,self.fst,self.lst,self.ack,self.mode,self.err,self.id)
     
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
#On crée l'objet qui gère la cryptographie
key = keychain(curve=ec.BrainpoolP512R1()) 
try:
  #On initie la connexion
  target.connect((host, port))
  target.settimeout(timeout)
  my_ip,my_port = target.getsockname()
  head = hat(my_port,port)
except socket.error:
  print("La connexion a échoué.")
  sys.exit()
############    Initialisation    ############

############    Corps    ############
try:
    print("Connexion établie avec le serveur %s:%d"%(host,port))
    head = head.forKeyExch()
    # Echange de clés
    target.send(head.toBytes()+key.pu_key_compressed)
    server_key = target.recv(PAQUET_SIZE+1)
    raw_head = hat.fromBytes(server_key[:HEADER_SIZE])
    head = head.forDataExch()
    server_key = server_key[HEADER_SIZE:]
    # Calcul du secret
    key.trade(server_key)
    ##### N'est pas inclus dans le protocole pLama
    target.send(head.toBytes()+key.encrypt(new_name.encode())) # Dans le cadre du chat , le fichier s'appel chat.lama
    key.derivate()
    target.recv(PAQUET_SIZE)
    head.yes()
    #####
    while data_size > 1:
          (answer,data_size) = emit(target,key,data_size)
          #if answer.upper() == "LAMA":
          #    break
          (head,data) = receive(target,key)
          ## Le cas chaîne vide ou LAMA est une rupture de connexion
          if data.upper() == b"LAMA":
              break
    target.send(head.forBreakConn().toBytes()+key.encrypt("Lama".encode())) ## La rupture finale sera indiqué par la gestion des flags
except socket.timeout:
    # En cas de timeout côté client on romp la connexion
    try:
        target.send(head.forBreakConn().toBytes()+key.encrypt("Lama".encode()))
    except AttributeError:
        print("Key Exchange failed before timeout")
except IndexError:
    target.send(head.forBreakConn().toBytes()+key.encrypt("Lama".encode()))
    print("Paquet impossible a traiter , secret desynchronise")
############    Corps    ############

############    Fin    ############
if choice == "F":
    file.close()
target.close()
############    Fin    ############