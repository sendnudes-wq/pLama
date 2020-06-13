#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curve-key-exchange-algorithm

from cryptography.hazmat.backends import default_backend as backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding , PublicFormat
import sys

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
    xa = int.from_bytes(a[:size],byteorder=sys.byteorder)
    xb = int.from_bytes(b[:size],byteorder=sys.byteorder)
    x = xa ^ xb
    return x.to_bytes(size,sys.byteorder)
    
server = keychain()
client = keychain()

client.trade(server.pu_key_compressed)
server.trade(client.pu_key_compressed)
'''
for i in range(5):
    print(client.secret,"\n")
    client.derivate()

'''
s = "Lama"
crypt = server.encrypt(s.encode())
dcrypt = client.decrypt(crypt)
print("%s\n\n%s\n\n%s"%(s,crypt,dcrypt))
print("%s\n\n%s\n\n%s"%(len(s),len(crypt),len(dcrypt)))
