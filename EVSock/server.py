from EVSockListner import EVsockListener
import EVSockListner as ev
import sys
import time
import json
import traceback
import base64
import pickle
import pandas as pd
import io
import datetime
from sys import getsizeof as getsize
import numpy as np


import chinese_calendar
# import datetime
# import numpy as np
# import hyperopt
# import lightgbm as lgb
# from hyperopt import STATUS_OK, Trials, hp, space_eval, tpe
# from sklearn.model_selection import train_test_split

# counter = 1
# while True:
#     time.sleep(1)
#     print("......")
#     counter = counter + 1
#     if counter > 10:
#         break
    
sys.path.append("app/")
import SymmetricEncryption
import RSAEncryption


def character_engineer(gas_secure_check, access_control):
    try:
        access_control['workday_access'] = access_control['workday_morning'] * 8 + access_control['workday_noon'] * 4
        + access_control['workday_afternoon'] * 2 + access_control['workday_night']

        access_control['holiday_access'] = access_control['holiday_morning'] * 8 + access_control['holiday_noon'] * 4
        + access_control['holiday_afternoon'] * 2 + access_control['holiday_night']

        df = pd.merge(gas_secure_check, access_control, how='left')
        df.fillna(0, inplace=True)
        day_list = list(gas_secure_check.columns)
        day_list.remove("id")
        access_workday_list = list(df['workday_access'])
        access_holiday_list = list(df['holiday_access'])

        for day in day_list:
            is_holiday = chinese_calendar.is_holiday(datetime.datetime.strptime(day, "%Y-%m-%d"))
            if is_holiday:
                df[day] = np.multiply(list((df[day] == 0).astype(int)), access_holiday_list) + list(df[day])
            else:
                df[day] = np.multiply(list((df[day] == 0).astype(int)), access_workday_list) + list(df[day])
            df[day] = df[day].astype(int)
        day_list.insert(0, "id")
        df = df[day_list]
        return pickle.dumps(df)

    except:
        return pickle.dumps(traceback.format_exc())

        
if __name__ == "__main__":
    server = EVsockListener()
    server.bind(int(sys.argv[1]))
    result = []

    while True:
        from_client = server.wait_for_conn()
        from_client.settimeout(50)
        while True:
            try:
                byte_msg,session_id = server.recv_data(from_client)         # received the conninit message
            except:
                print("connection initialize message error")
                break
            print("最新 message type:" + server.get_msg_type(byte_msg))
            if server.get_msg_type(byte_msg) == "CONNINIT":
                """ 
                    server receive a conn init message, it do:
                    1. send the attestation doc to client
                    2. receive the encrypted message from client
                    3. decrypte the message and save it to
                """
                try:
                    server.send_data("ATTESDOC",session_id,"".encode())
                except:
                    print("send error!")
                    break
                try:
                    byte_msg, session_id = server.recv_data(from_client)
                    #print("encrypted message from client:"+ byte_msg)
                    
                    # --------------------------------------
                    #           get plain aes key  
                    # --------------------------------------
                    cipher_dict = json.loads(byte_msg[76:].decode())
                    rsa_private_key = server.a.get_private_key()
                    rsa = RSAEncryption.RSASimaple()
                    rsa.set_private_key(rsa_private_key)
                    plain_aes_key = rsa.decrypt(cipher_dict['key'])
                    
                    # --------------------------------------
                    #           decrypted the message  
                    # --------------------------------------            
                    aes = SymmetricEncryption.AESSimple(length = 128)
                    
                    cipher =base64.b64decode(cipher_dict['enc_data'].encode())
                    nonce = base64.b64decode(cipher_dict['iv'].encode())
                    mac = base64.b64decode(cipher_dict['mac'].encode())
                    
                    aes.set_key(plain_aes_key)
                    plain_text = pickle.loads(aes.decrypt(cipher,nonce,mac))
                    server.send_data("CONFIRME",session_id,"".encode())
                    result.append(plain_text)
                    break
                except:
                    traceback.print_exc()
                    print("message error!")
                    break
            # --------------------------------------
            #           data processing. sum a list
            # --------------------------------------       
            elif server.get_msg_type(byte_msg) == "DATAFINN":
                print(len(result[0]))
                print(len(result[1]))
                f1 = open("a.csv","w+")
                f1.write(result[1].decode("utf-8").replace("\r", ""))
                f1.close()
                
                f0 = open("b.csv","w+")
                f0.write(result[0].decode("utf-8").replace("\r", ""))
                f0.close()
                df1 = pd.read_csv(io.StringIO(result[0].decode("utf-8").replace("\r", "")), lineterminator='\n',low_memory=False,memory_map=True)
                df2 = pd.read_csv("a.csv")
                
                
                print("access_control: ", df2.head(5))
                print("gas_secure_check: ", df1.head(5))
                data = character_engineer(df1,df2)
                # send back to client
                server.send_data("RESULTCL",session_id,data)
                print("Operation Complete! ")
                break
            
    