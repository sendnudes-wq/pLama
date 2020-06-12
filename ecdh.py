#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curve-key-exchange-algorithm

from cryptography.hazmat.backends import default_backend as backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class keychain():
    def __init__(self,size):
        self.curve = ec.SECP256K1
        self.pr_key = ec.generate_private_key(self.curve,backend())
        self.pu_key = self.pr_key.public_key()
           
    def trade(self,peer_key):
        self.peer_key = peer_key
        self.raw_secret = self.pr_key.exchange(ec.ECDH(),peer_key)
        self.secret = HKDF(algorithm=hashes.SHA256(),length=len(self.raw_secret),salt=None,info=b"Je suis le roi des Chameaux",backend=backend()).derive(self.raw_secret)
    
    def derivate(self):
        self.raw_secret = self.secret
        self.secret = HKDF(algorithm=hashes.SHA256(),length=len(self.raw_secret),salt=None,info=b"Je suis le roi des Chameaux",backend=backend()).derive(self.raw_secret)
        
'''        
server = keychain()
client = keychain()

client.trade(server.pu_key)
server.trade(client.pu_key)

for i in range(5):
    print(client.secret,"\n")
    client.derivate()
'''