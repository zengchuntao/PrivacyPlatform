#!/usr/local/bin/env python3

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import math
import secrets
import socket
import sys
import uuid
import base64
import random
sys.path.append("/app")
import pyattestation as pya


class EVsockListener:
    """Server"""


    def __init__(self, conn_backlog=128):
        self.conn_backlog = conn_backlog
        """
            The connection_info dict has a format like
            {
                session_id: [nouce,sock]
                ....
            }
        """
        self.connection_info = {}
        self.receive_fun_dict = {
            "CONNINIT": self._rev_coninit_msg_handler,
            "DATATRAN": self._rev_encrypted_data_msg_handler,
            "DATAFINN": self._rev_data_finn_msg_handler
        }
        self.send_fun_dict = {
            "ATTESDOC": self._send_attes_doc_msg_handler,
            "RESULTCL": self._send_result_handler,
            "CONFIRME": self._send_confirm_handler   # enclave confirm a message
        }
        self.nouce = ""
        self.a = pya.attestation()


    def bind(self, port):
        """Bind and listen for connections on the specified port"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.conn_backlog)
        
        print("server listening on port:" + str(port) + "...")


    def wait_for_conn(self):
        print("Wait for new connection...")
        (from_client, (remote_cid, remote_port)) = self.sock.accept()
        print("Connection detect!")
        return from_client


    def recv_data(self,from_client):
        """Receive data from a remote endpoint"""
        bytes_message = bytearray()
        print("")
        
        try:
            bytes_message.extend(from_client.recv(76))
        except socket.error:
            pass
            
        payload_len = int.from_bytes(bytes_message[8:12], 'little')  # extract payload length

        while len(bytes_message)-76 < payload_len:
            last_size = payload_len-(len(bytes_message)-76)
            try:
                data = from_client.recv(min(last_size,4024*1024))
                bytes_message.extend(data)
                if not data:
                    break
            except :
                print(traceback.format_exc())
                
        message_type = bytes_message[:8].decode()
        if message_type=="":
            raise TypeError("bad message")
        print(message_type)
        
        print("search for deal_fun")
        deal_fun = self.receive_fun_dict[message_type]
        print("deal fun found")
        data = deal_fun(bytes_message, from_client)
        print("server received: ")
        print("         message type: "+message_type)
        print("         message len: "+str(len(bytes_message[76:].decode())))
        
        return bytes_message,get_session_id(bytes_message)
        #还没有关闭socket

    

    def send_data(self, message_type: str, session_id, bytes_data="".encode()):
        """Send data to a remote endpoint."""
        if message_type not in self.send_fun_dict.keys():
            raise TypeError("No such message type!")
        deal_func = self.send_fun_dict[message_type]  # find the mapping function
        if session_id not in self.connection_info.keys():
            raise TypeError("Session id wrong!")
        data = deal_func(session_id,bytes_data)
        
        sock = self.connection_info[session_id][1]     # find the corresponded client socket
        sock.sendall(data)
        print("server sent:")
        print("         message type: "+message_type)
        print("         message length: "+str(len(data)))


    def _rev_coninit_msg_handler(self,byte_message,socks):
        """construct the received bytes when the message type is "CONNINIT"
           save the client information to the connection_info dict
        """
        session_id = get_session_id(byte_message)
        nouce = get_nouce(byte_message)
        print("Saved client information:")
        print("session_id: " + session_id)
        print("nouce: " + nouce)
        # record a new session
        msg = get_msg(byte_message)
        print("write to connect info message:"  + msg)
        self.connection_info[session_id] = [nouce, socks, get_msg(byte_message)]        
        return msg

    def _rev_encrypted_data_msg_handler(self, bytes_message, socks):
        # TODO: 处理加密消息
        return ""

    def _rev_data_finn_msg_handler(self, bytes_message, socks):
        session_id = get_session_id(bytes_message)
        nouce = get_nouce(bytes_message)
        self.connection_info[session_id] = [nouce, socks, get_msg(bytes_message)] 
        return ""

    def _send_attes_doc_msg_handler(self,session_id,bytes_data):
        """construct the message to send"""
        print("parse the doc")
        print(self.connection_info)
        
        nouce = self.connection_info[session_id][0]
        client_msg = self.connection_info[session_id][2]
        print("client message needs to be in doc" + client_msg)
        att_bytes = self._get_attestation_doc(client_msg,nouce)
        print("attes doc load successful")
        payload_len = len(att_bytes)
        payload_len_bytes = payload_len.to_bytes(4, 'little')

        bytes_message = "ATTESDOC".encode()+ payload_len_bytes + \
                        session_id.encode() + nouce.encode() + att_bytes
        return bytes_message
        
        
    def _send_result_handler(self,session_id,bytes_data):
        nouce = self.connection_info[session_id][0]
        payload_len = len(bytes_data)
        payload_len = len(bytes_data)
        payload_len_bytes = payload_len.to_bytes(4, 'little')
        bytes_message = "RESULTCL".encode()+ payload_len_bytes + \
                        session_id.encode() + nouce.encode() + bytes_data
        return bytes_message
        
        
    def _get_attestation_doc(self,client_msg,nouce):
        print("begin to get attestation")
        
        print("begin to genreate the key")
        isKey = self.a.init_key_pair()
        print("begin to get attestation doc")
        att_doc = self.a.request_attestation_doc(client_msg,nouce)
        att_json = json.loads(att_doc)
        att_content = att_json["AttestationDocument"]
        att_bytes = base64.b64decode(att_content)
        return att_bytes
        
    def _send_confirm_handler(self,session_id,bytes_data):
        nouce = self.connection_info[session_id][0]
        payload_len = len(bytes_data)
        payload_len = len(bytes_data)
        payload_len_bytes = payload_len.to_bytes(4, 'little')
        bytes_message = "CONFIRME".encode()+ payload_len_bytes + \
                        session_id.encode() + nouce.encode() + bytes_data
        return bytes_message
        
    
    def register_recv_msg_handler(self, msg_type, msg_handler):
        self.recv_func_dict[msg_type] = msg_handler


    def register_send_msg_handler(self, msg_type, msg_handler):
        self.send_fun_dict[msg_type] = msg_handler

    def get_msg_type(self,bytes_data):
        return bytes_data[:8].decode()
        
def get_session_id(bytes_data):
    """return the session id from any bytes message"""
    return bytes_data[12:44].decode()


def get_nouce(byte_data):
    """return the nouce from any bytes message"""
    return byte_data[44:76].decode()

def get_msg(bytes_data):
    return bytes_data[76:].decode()

    
