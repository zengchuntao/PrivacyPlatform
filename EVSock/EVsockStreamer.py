import argparse
import json
import math
import secrets
import socket
import sys
import uuid
import random

class EVsockStreamer:
    """Client
        message format:
        ----------------------------------------------------
        |       header (76bytes)         |        payload   |
        ----------------------------------------------------
        |                               \
        |                                   \
        |                                       \
        |                                           \
        -----------------------------------------------
        | m_type(8) | d_len(4) | s_id(32) | nouce(32) |
        -----------------------------------------------

        m_type: message type
            - "CONNINIT": indicate the first message from client to the server,
                when sending a coninit message, client will generate a session id and a nouce
                and add it to the message header
            - "DATATRAN": the encrypted data message from client to server
            - "ATTESDOC": attestation document message, the payload should be a AD
        d_len: data length, maxmum data length is 2**32 bytes
        s_id: session id
        nouce: nouce number from client to server and vice versa

    """

    def __init__(self, conn_tmo=100):
        self.conn_tmo = conn_tmo
        self.session_id = ""
        self.nouce = ""
        self.send_fun_dict = {
            "CONNINIT": self._send_coninit_msg_handler,
            "DATATRAN": self._send_dat_msg_handler,
            "DATAFINN": self._send_dat_finish_handler
        }
        self.recv_fun_dict = {
            "ATTESDOC": self._recv_attes_doc_msg_handler,
            "RESULTCL": self._recv_result_handler,
            "CONFIRME": self._recv_confirm_handler
        }


    def connect(self, endpoint):
        """Connect to the remote endpoint"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) 
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)


    def send_data(self, message_type: str, bytes_data: bytes):
        """Send data to a remote endpoint."""
        if type(bytes_data)!=bytes:
            raise TypeError("bytes data required!")
        if message_type not in self.send_fun_dict.keys():
            raise TypeError("No such message type!")    
        deal_func = self.send_fun_dict[message_type]  # find the mapping function
        data = deal_func(bytes_data)
        print("client start to send data...")
        print(".          message type:" + message_type)
        print(".          message length:" + str(len(data)))
        self.sock.sendall(data) # for debug
        print("#########client sent complete#########")



    def recv_data(self):
        """Receive data from a remote endpoint"""
        bytes_message = bytearray()
        # only receive the header first
        try:
            data = self.sock.recv(76)
            bytes_message.extend(data)
        except socket.error:
            print(socket.error)
            
        payload_len = int.from_bytes(bytes_message[8:12], 'little')  
        
        loop_time = math.ceil(payload_len / 1024)  # 71 is the header length
        while len(bytes_message)-76 < payload_len:
            last_size = payload_len-(len(bytes_message)-76)
            try:
                data = self.sock.recv(min(last_size,4024*1024))
                bytes_message.extend(data)
                if not data:
                    break
            except socket.error:
                print(traceback.format_exc())
            #bytes_message += data
        bytes_message = bytes(bytes_message)
        message_type = bytes_message[:8].decode()
        
        # call the corresponed deal function
        deal_func = self.recv_fun_dict[message_type] 
        data = deal_func(bytes_message)

        print("client received: ")
        print("         message type: " + message_type)
        print("         message len: " + str(len(data))) 
        return data
        
    def disconnect(self):
        """Close the client socket"""
        self.sock.close()


    def _send_coninit_msg_handler(self,data_bytes):
        """construct the sending bytes when the message type is "CONNINIT" """
        nouce_bytes = self.nouce.encode()  # for connect init message, data_bytes are used as nouce
        self.session_id = create_nouce()
        print("session_id: " + str(self.session_id))
        print("nouce: " + nouce_bytes.decode())
        set_bytes = "CONNINIT".encode()
        data_len_bytes = len(data_bytes).to_bytes(4, 'little')  # data length is 0
        s_id_bytes = str(self.session_id).encode()
        return set_bytes + data_len_bytes + s_id_bytes + nouce_bytes + data_bytes


    def _send_dat_msg_handler(self,data_bytes):
        set_bytes = "DATATRAN".encode()
        data_len_bytes = len(data_bytes).to_bytes(4, 'little')
        s_id_bytes = self.session_id.encode()
        nouce_bytes = self.nouce.encode()
        return set_bytes + data_len_bytes + s_id_bytes + nouce_bytes + data_bytes

    def _recv_attes_doc_msg_handler(self,bytes_data):
        """Verify the session_id and nouce"""
        session_id = get_session_id(bytes_data)
        nouce = get_nouce(bytes_data)
        print("session_id from server: "+session_id)
        print("nouce from server: "+ nouce)
        return bytes_data[76:]
    
    def _recv_result_handler(self,bytes_data):
        session_id = get_session_id(bytes_data)
        nouce = get_nouce(bytes_data)
        print("session_id from server: "+session_id)
        print("nouce from server: "+ nouce)
        return bytes_data[76:]
    
    def _send_dat_finish_handler(self,bytes_data):
        set_bytes = "DATAFINN".encode()
        data_len_bytes = len(bytes_data).to_bytes(4, 'little')
        s_id_bytes = self.session_id.encode()
        nouce_bytes = self.nouce.encode()
        return set_bytes + data_len_bytes + s_id_bytes + nouce_bytes + bytes_data
    
    def _recv_confirm_handler(self,bytes_data):
        session_id = get_session_id(bytes_data)
        nouce = get_nouce(bytes_data)
        print("session_id from server: "+session_id)
        print("nouce from server: "+ nouce)
        return bytes_data[76:]
        
        
    def register_recv_msg_handler(self, msg_type, msg_handler):
        self.recv_func_dict[msg_type] = msg_handler


    def register_send_msg_handler(self, msg_type, msg_handler):
        self.send_fun_dict[msg_type] = msg_handler
        
    def parse_nouce(self,nouce):
        self.nouce = nouce
        
def create_nouce(num=6):
        """generate a unique random string"""
        return secrets.token_hex(16)
    
    
def get_session_id(bytes_data):
    """return the session id from any bytes message"""
    return bytes_data[12:44].decode()


def get_nouce(byte_data):
    """return the nouce from any bytes message"""
    return byte_data[44:76].decode()