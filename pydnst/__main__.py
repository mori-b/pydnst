import sys
import logging
import pydnst

logger = logging.getLogger('dnst_main')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
logger.addHandler(handler)

    
HELP = '''
pydnst supported commands :
    -python -m pydnst config : generate pydnst.toml config file, necessary for client and server
    -python -m pydnst create_certificates : create server_private.pem (for server) and server_public.pem (for client)
    -python -m pydnst server run : run the server
    -python -m pydnst client run : run the client
    -python -m pydnst server c2 : send and receives commands to clients
    -python -m pydnst shared_key : generate default shared key shared by client and server (used as a fallback, or when not using certificates)    

'''

def generate_config():
    from cryptography.fernet import Fernet    
    shared_key = Fernet.generate_key()
    config_path = 'pydnst.toml'
    config = f'''
[general]
DNST_SERVER_NAME = "dn1dn1.site"
DEFAULT_SHARED_KEY = "{shared_key.decode()}"

[client]
USE_DEFAULT_DNS_SERVER = false
MAIN_INTERFACE = "wlp1s0"    #if USE_DEFAULT_DNS_SERVER is true
DNS_SERVER_ADDRESS_FALLBACK = "1.1.1.1"   #if USE_DEFAULT_DNS_SERVER is true
DNS_SERVER_ADDRESS = "1.1.1.1"   #if USE_DEFAULT_DNS_SERVER is false
DNS_SERVER_PORT = 53
KEEP_ALIVE_PERIOD = 30
DNST_CLIENT_ID_PATH = "dnst_client_id.txt"
SERVER_PUBLIC_PEM_PATH = "server_public.pem"

[server]
LISTENING_INTERFACE = "eth0"   #"lo"
LISTENING_PORT = 53
SERVER_PRIVATE_PEM_PATH = "server_private.pem"
MESSAGES_JSON = "/var/tmp/pydnst_messages.json"
UDS_PATH_COMMANDER = "/var/tmp/pydnst.uds"    
'''
    with open(config_path,'w') as fd:
        fd.write(config)
    print(f'Config file was generated at {config_path}')

def create_default_shared_key():
    from cryptography.fernet import Fernet
    
    SHARED_KEY = Fernet.generate_key()
    print('Set the following shared_key value in your config file (both client and server)')
    print(SHARED_KEY.decode())

def create_certificates():
    #generate server keys in advance : then provide server_private.pem to server and server_public.pem to client
    
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    
    serial_private = private_key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    with open('server_private.pem', 'wb') as fd:
        fd.write(serial_private)
    print('server_private.pem was generated')
        
    # public key
    serial_pub = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('server_public.pem', 'wb') as fd:
        fd.write(serial_pub)
    print('server_public.pem was generated')
    

if len(sys.argv) > 2:
    if sys.argv[2] == 'run':
        if sys.argv[1] == 'server':
            server = pydnst.server.DnstServer()
            server.run()
        elif sys.argv[1] == 'client':
            client = pydnst.client.DnstClient()
            client.run()
        else:
            print('Unknown argument : '+str(sys.argv[1]))
    elif sys.argv[1] == 'server' and sys.argv[2] == 'c2':
        c2 = pydnst.commander.Commander()
        c2.run()
    else:
        print('Unknown command : '+str(sys.argv[2]))
elif sys.argv[1] == 'create_certificates':
    create_certificates()
elif sys.argv[1] == 'shared_key':
    create_default_shared_key()
elif sys.argv[1] == 'config':    
    generate_config()
elif sys.argv[1] == '--help':
    print(HELP)
else:
    print(HELP)    
    
        
