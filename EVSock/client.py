
from __future__ import print_function
from EVsockStreamer import EVsockStreamer
import logging
import grpc
import pickle
import sys
import os
import socket
import sys
import traceback
import base64
import secrets
import json
import yaml
from verify_tools import*

sys.path.append(os.path.abspath("."))
sys.path.append(os.path.abspath("../../protos_py/"))

import DPServer_pb2
import DPServer_pb2_grpc
import traceback

def readyaml(file):
    """read a yaml file"""
    if os.path.isfile(file):
        fr = open(file, 'r')

        yaml_info = yaml.load(fr, Loader=yaml.FullLoader)
        fr.close()
        return yaml_info
    return None
    
    
def character_engineer(gas_secure_check_data, access_control_data):
    return list(access_control_data.SWIPE_TIME)[0] + list(gas_secure_check_data.check_time)[0]


def task_start(yaml_file,port_enclave,cid):
    
    MAX_MESSAGE_LENGTH = 1024 * 1024 * 1024
    client = EVsockStreamer(100)
    endpoint = (32, 5005)
    root_cert_path = "."
    
# The following operation is for each grpc server

# ------------------------------------------------------------
#    phase 1 : connect the grpc server request for chanllenge
# ------------------------------------------------------------
    for server_info in yaml_file:
        ip = server_info['ip']
        port = server_info['port']
        with grpc.insecure_channel(ip + ':' + port,options=[
                                ('grpc.max_send_message_length', MAX_MESSAGE_LENGTH),
                                ('grpc.max_receive_message_length', MAX_MESSAGE_LENGTH),
                                ]) as channel:
            stub = DPServer_pb2_grpc.SPServiceStub(channel)
            # get data
            print("Try to connect to grpc server ...")
            req_data = DPServer_pb2.RequestMessage()
            req_data.msg_type = "GetData"
            req_data.id = 1234
            try:
                print("------------------------ connected to data provider----------------------")
                print(f"connection info:\n ip:{ip}\n port: {port} \n")
                response = stub.SendRequest(req_data)
                
                print("----------grpc: receive nouce and user data-------------")
                
                print("user data: "+ response.user_data.decode() + "\n" + "nouce: " + response.user_nonce.decode())
                print("client received: " + response.response_msg)
                # get AttestationMessage
            except:
                traceback.print_exc()
                session_id = DPServer_pb2.SessionID(id=req_data.id)
                close_r = stub.CloseSession(session_id)
                print("Something went wrong!")
                return    
# -----------------------------------------------------------------------------
#     phase 2 : connect to the encalve
# -----------------------------------------------------------------------------
            try:
                client.connect(endpoint)
            except:
                print("connection error")
                exit(0)
# -------------------------------------------------------------------------------
#      phase 3 : init with enclave and receive doc 
# -------------------------------------------------------------------------------
            print("------------enclave: send nouce to enclave-----------------")
            nouce = response.user_nonce
            user_data = response.user_data
            client.parse_nouce(nouce.decode())
            client.send_data("CONNINIT", user_data)
            bytes_data = client.recv_data()  # receive attdoc message
            print("------------enclave: received doc from enclave--------------")
# -------------------------------------------------------------------------------
#      phase 4 : send back the attestation doc to the grpc server and get result
# -------------------------------------------------------------------------------
            atmsg = DPServer_pb2.AttestationMessage()
            atmsg.attestation_doc = bytes_data
            atmsg.id = req_data.id
            resp_at = stub.SendAttestationDocument(atmsg)
            print("------------grpc: receiving enc data ... --------------")
            if resp_at.att_result == 0:
                print("verify success!")
            else:
                print("verify faile!")
                close_r = stub.CloseSession(session_id)
                client.close()
            

            if resp_at.att_result != 0:
                print("Attestation Failed!!!")
                client.disconnect()
                session_id = DPServer_pb2.SessionID(id=req_data.id)
                close_r = stub.CloseSession(session_id)
            
            session_id = DPServer_pb2.SessionID(id=req_data.id)
            close_r = stub.CloseSession(session_id)

# ---------------------------------------------------------------------
#      phase 4 : send encrypted data to enclave
# ---------------------------------------------------------------------
            cipher_dict = {
                "enc_data": base64.b64encode(resp_at.encrypted_data).decode(),
                "key": resp_at.encrypted_data_key.decode("utf-8"),
                "iv": base64.b64encode(resp_at.encrypted_data_iv).decode(),
                "mac": base64.b64encode(resp_at.encrypted_data_mac).decode(),
                "aes_mode": resp_at.aes_cipher_mode
            }
            json_cipher_dict = json.dumps(cipher_dict)
            enc_aes_key = base64.b64decode(cipher_dict['key'])
            print("------------enclave: send enc data to enclave--------------")
            client.send_data("DATATRAN", json_cipher_dict.encode())
            client.recv_data()
            print("enclave received the encrypte message")
            
            client.disconnect()
# --------------------------------------------------------------------
#              send finish signal and receive the result
# --------------------------------------------------------------------     
    try:
        client.connect(endpoint)
    except:
        print("connection error")
        exit(0)
    client.send_data("DATAFINN", "".encode())
    bytes_data = client.recv_data()
    print("------------------------ get final result from enclave----------------------")
    print(pickle.loads(bytes_data))
    print("Communication Complete!")
    
                


if __name__ == "__main__":

    yaml_file = readyaml("servers.yaml")
    task_start(yaml_file,5005,32)
 
    
