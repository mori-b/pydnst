from cryptography.fernet import Fernet
from zlib import crc32
import  base64
import struct
import time
from datetime import datetime


HEADER_STRUCT = struct.Struct('BBBB')
HEADER_LENGTH = HEADER_STRUCT.size
HEADER_LENGTH_ENCODED = 16 #(base32 of header (4 bytes) and crc32 (4 bytes))
#A query field max size is 250 (experimental) - 4 (max label lengths) - 16 (header) - (len(dns_server_name)+1) = 230 - 12 = 218
#A query field label max size is 35 : 63 - 16 (header) - (len(dns_server_name)+1) = 35

FRAGMENTS_EXPIRATION_TIME = 30*60
MAX_COMMAND_LENGTH = 1000
KA_COMMAND_ID = '0'
RSA_COMMAND_ID = '1'
ACK_COMMAND_ID = '2'
COMMANDS_WITHOUT_ENCRYPTION = (KA_COMMAND_ID, RSA_COMMAND_ID, ACK_COMMAND_ID)


class MessageBuilder:
    def __init__(self, logger, dnst, dns_server_name, DEFAULT_SHARED_KEY):
        self.logger = logger.getChild('MessageBuilder')
        self.dnst, self.dns_server_name = dnst, dns_server_name
        self.max_fragment_payload_sizes = {'request': {'A': 63-16-len(dns_server_name)-1, 'TXT':63-16-len(dns_server_name)-1, 
                                      'NULL': 63-16-len(dns_server_name)-1},
                          'response': {'TXT':234-16-len(dns_server_name)-1}}
    
        #experimentally, the base32+encryption bloat the data by a factor of slightly less than 2.2    
        self.max_data_length = {'request': int(254*(63-16-len(dns_server_name)-1) // 2.2),
                                'response': int(254*(234-16-len(dns_server_name)-1) // 2.2)}        
        self.encryptors = {}
        self.default_encryptor = Fernet(DEFAULT_SHARED_KEY)
    
    
    def use_shared_key_for_client(self, client_id, shared_key):
        self.encryptors[client_id] = Fernet(shared_key)
        
    def b32encode(self, data):
        #avoid '=' not allowed in A record, use instead '8' which is absent from base32
        res = base64.b32encode(data)
        res = res.replace(b'=', b'8')
        return res

    def b32decode(self, data):
        #avoid '=' not allowed in A record, use instead '8' which is absent from base32
        data = data.replace(b'8', b'=')        
        res = base64.b32decode(data)
        return res
        
    def encode_payload(self, data, client_id, without_encryption=False):
        if without_encryption:
            encrypted_data = data
        else:
            #encrypt the data
            encryptor = self.encryptors.get(client_id, self.default_encryptor)
            encrypted_data = encryptor.encrypt(data)
        #prepend crc32 (4 bytes) for data integrity
        crc = crc32(encrypted_data).to_bytes(4, byteorder='big')
        #base32 encode
        payload = self.b32encode(crc + encrypted_data)
        #return b'\x55'*len(payload)
        return payload
    
    def decode_payload(self, payload, client_id, without_encryption=False):
        #base32 decode
        payload_b32decoded = self.b32decode(payload)
        #check crc
        crc = int.from_bytes(payload_b32decoded[:4], byteorder='big')
        crc_calc = crc32(payload_b32decoded[4:])
        if crc != crc_calc:
            self.logger.warning('Received packet payload with wrong crc, discarding it')
            return False
        
        if without_encryption:
            #circumvent the encryption for keep-alive
            data = payload_b32decoded[4:]
        else:
            #decrypt the data
            encryptor = self.encryptors.get(client_id, self.default_encryptor)
            data = encryptor.decrypt(payload_b32decoded[4:])
        return data    
    
    def fragment_payload(self, payload, rtype, is_dns_response):
        #fragments the payload into a list of fragments, each of which should fit in a separate dns packet
        fragments = []
        read_index = 0
        fragment_length = self.max_fragment_payload_sizes['response' if is_dns_response else 'request'][rtype]
        number_of_fragments_except_last, last_fragment_length = divmod(len(payload), fragment_length)
        for el in range(number_of_fragments_except_last):
            fragments.append(payload[read_index : read_index + fragment_length])
            read_index += fragment_length
        if last_fragment_length:
            fragments.append(payload[-last_fragment_length:])
                
        #removed because the first labels are not forwarded by dns server to authoritative server (only last labels are)
        #so we cannot leverage that by adding more labels of 63 length
        if False: #not self.dnst.is_server:
            #client sends qname with dots
            #add the length byte before each label as expected by RFC-1035
            #it will add up to 3 bytes to each fragment, which will make the fragment reach up to 243 bytes, which is still under the limit
            LABEL_MAX_LENGTH = 63
            new_fragments = []
            for fragment in fragments:
                new_fragment = bytearray()
                read_index = 0
                number_of_labels_except_last, last_label_length = divmod(len(fragment), LABEL_MAX_LENGTH)
                for el in range(number_of_labels_except_last):
                    new_fragment += (b'.' + fragment[read_index : (read_index + LABEL_MAX_LENGTH)])
                if last_label_length:
                    new_fragment += (b'.' + fragment[-last_label_length:])
                new_fragments.append(new_fragment)
            fragments = new_fragments
            
        if not (self.dnst.is_server and (rtype != 'A')):
            #append the dns server name at the end of each fragment
            #-always for client (since it sends it query inside the qd.qname field which uses dots)
            #-for server : based on an.type : if the response is of TXT type, dots were not added, so don't remove them at reception
            for index in range(len(fragments)):
                fragments[index] += (b'.'+self.dns_server_name)
        return fragments
        
    def build_packet_header(self, command_id, fragment_id, number_of_fragments):
        #packet header is 4 bytes, with 4 crc32 bytes, all base32 encoded : overall header length is 16 bytes
        #client_id (1 byte) - command_id (1 byte) - fragment_id (1 byte) (starts 1) - number of fragments (1 byte)
        #command_id = 0 for keep-alive
        header = HEADER_STRUCT.pack(int(self.dnst.dnst_id), int(command_id), fragment_id, number_of_fragments) #4 bytes
        crc = crc32(header).to_bytes(4, byteorder='big')
        header_packet = self.b32encode(crc + header)
        return header_packet
    
    def fragmenter(self, data, rtype, client_id, command_id, is_dns_response=False, without_encryption=False):
        self.logger.info(f'Generating fragments for command_id {command_id}')
        fragments = self.fragment_payload(self.encode_payload(data, client_id, without_encryption=without_encryption), rtype, is_dns_response)
        #truncate the number of fragments if over 255, since our header has only 1 byte for this field
        number_of_fragments = min(len(fragments), 255)
        index = 1
        #the fragments numerotation starts from 1 (not 0), easier to compare with number_of_fragments
        result = []
        for fragment in fragments:
            dns_value = self.build_packet_header(command_id, index, number_of_fragments) + fragment
            result.append(dns_value)
            index += 1
        self.logger.info(f'{number_of_fragments} fragments were generated for command_id {command_id}')            
        return result
            
    def reassemble_fragment(self, fragment):
        self.logger.info('Starting reassemble_fragment')
        try:
            if self.dnst.is_server:
                #server receives from client qname with dots, we exclude the site name
                fragment = fragment.split(b'.')[0] #b''.join(fragment.split(b'.')[:-2])
            header_packet = self.b32decode(fragment[:HEADER_LENGTH_ENCODED])
            crc = header_packet[:4]
            header = header_packet[4:]
            crc_calc = crc32(header).to_bytes(4, byteorder='big')
            if crc != crc_calc:
                self.logger.warning('Received packet header with wrong crc, discarding it')
                return False
            client_id, command_id, fragment_id, number_of_fragments = HEADER_STRUCT.unpack(header)
            client_id = str(client_id)
            command_id = str(command_id)
            self.logger.info(f'Reassembling fragment {fragment_id} out of {number_of_fragments} for client {client_id} and command {command_id}')
            if client_id not in self.dnst.received_fragments:
                self.dnst.received_fragments[client_id] = {}
            received_fragments = self.dnst.received_fragments[client_id]
            new_command_id_entry = False
            if command_id not in received_fragments:
                new_command_id_entry = True
            else:
                if (time.time() - received_fragments[command_id]['date']) > FRAGMENTS_EXPIRATION_TIME:
                    #we don't accept fragments from expired command_id (30 minutes) : we therefore relate to this random command_id as a new one
                    self.logger.info(f'Replacing expired fragments for command_id : {command_id}')
                    received_fragments.pop(command_id, None)
                    new_command_id_entry = True
            if new_command_id_entry:
                #prepare list of fragments for this command_id
                received_fragments[command_id] = {'date':time.time(), 'list_of_fragments': [False]*number_of_fragments}
            received_fragments[command_id]['list_of_fragments'][fragment_id-1] = fragment[HEADER_LENGTH_ENCODED:]
                
            if all(received_fragments[command_id]['list_of_fragments']):
                self.logger.info(f'Fragments received from client_id : {client_id} with command_id : {command_id} are reassembled')
                data = self.decode_payload(b''.join(received_fragments[command_id]['list_of_fragments']), client_id,
                                           without_encryption=(command_id in COMMANDS_WITHOUT_ENCRYPTION))
                if data:
                    self.logger.info(f'Reassembled received valid message from client_id : {client_id} with command_id : {command_id} and content : {data}')
                    if command_id in (RSA_COMMAND_ID, ACK_COMMAND_ID):
                        #store binary data as is in shared_keys to be read when leaving the function by datagram_received
                        self.dnst.tunnel_mng_messages[command_id][client_id] = data
                    else:
                        if client_id not in self.dnst.tunnel_messages:
                            #should happen only for keep-alive
                            self.dnst.tunnel_messages[client_id] = {}
    
                        if command_id not in self.dnst.tunnel_messages[client_id]:
                            if self.dnst.is_server and command_id != KA_COMMAND_ID:
                                self.logger.info(f'Server received response id {command_id} without prior request in tunnel_messages : Ignoring ...')
                                return False
                            else:
                                self.dnst.tunnel_messages[client_id][command_id] = {}                            
                        self.dnst.tunnel_messages[client_id][command_id]['date'] = datetime.fromtimestamp(received_fragments[command_id]['date']).strftime(r'%Y-%m-%d--%H:%M:%S')
                        self.dnst.tunnel_messages[client_id][command_id]['response'] = data.decode().strip()
                        self.logger.info(f'Updated tunnel_messages : {self.dnst.tunnel_messages}')
                        if self.dnst.is_server:
                            #storing it with this new message in json, ordering according to most recent per client                    
                            self.dnst.store_ordered_tunnel_messages(self.dnst.tunnel_messages)
                    #removing the fragments of this command_id since we finished to process them
                    received_fragments.pop(command_id, None)
                    return client_id, command_id, fragment_id, number_of_fragments, True    # reassembled fragment is ready
            return client_id, command_id, fragment_id, number_of_fragments, False    # reassembled fragment is not ready yet
        except Exception:
            self.logger.exception('reassemble_fragment')
            return False
            
