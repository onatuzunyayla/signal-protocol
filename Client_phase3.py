import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://10.92.52.175:5000/'

stuID = 23813  ## Change this to your ID number

E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator
curve = E

#my public private key generation
random.seed(68)
secretkey = random.randint(0, E.order-2)
Qa = secretkey*P # my public key
print("Q on curve?", E.is_on_curve(Qa))

# signature generation for my ID
random.seed(37)
k = random.randint(0, E.order-3)
R = k*P
lower_r = (R.x) % n
msg = stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big')
hashdata = lower_r.to_bytes((lower_r.bit_length()+7)//8, byteorder='big') + msg
h_object = SHA3_256.new()
h_object.update(data=hashdata)

h = (int.from_bytes(h_object.digest(), byteorder='big'))% n
s = (k - (secretkey*int.from_bytes(h_object.digest(), byteorder='big'))) % n

ikpubx = Qa.x
ikpuby = Qa.y

#server's Identitiy public key
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    print(response.json())

def PseudoSendMsgPH3(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json = mes)		
    print(response.json())

def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]
    
def SendMsg(idA, idB, otkid, msgid, msg, ekx, eky):
    mes = {"IDA":idA, "IDB":idB, "OTKID": int(otkid), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json = mes)
    print(response.json())    
        
def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json = OTK_request_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']      
    else:
        return -1, 0, 0

def Status(stuID, h, s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)	
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']	

def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)     
    print(response.json())


PseudoSendMsgPH3(h, s)
key_dict = [None] * 10
message_box = [None] * 5

for i in range(0, 10):

    random.seed(200 + i)
    otk_secret = random.randint(0, E.order-2) 
    otk_pub = otk_secret*P
    otk_pub_x = otk_pub.x
    otk_pub_y = otk_pub.y
    key_dict[i] = {'otk_secret': otk_secret, 'otk_pub_x': otk_pub_x, 'otk_pub_x': otk_pub_x}


for y in range(5):  
    ID_b, OTK_id, MSG_id, MSG, EK_x, EK_y = ReqMsg(h, s)
    print("MSGID: ", MSG_id)

    

    #KDF CHAIN
    if(y == 0):
        #session key generation
        EK_PUB = Point(EK_x ,EK_y, curve)
        OTKA = key_dict[OTK_id]['otk_secret']
        
        #print("OTKA: ", OTKA, "\n")
        T = OTKA*EK_PUB
        T_x = T.x
        T_y = T.y
        U = T_x.to_bytes((T_x.bit_length()+7)//8, byteorder='big') + T_y.to_bytes((T_y.bit_length()+7)//8, byteorder='big') + b'MadMadWorld'
        k_session = SHA3_256.new()
        k_session.update(data=U)
        #encrpytion key, hmac generation
        k_enc = SHA3_256.new()
        u_data = k_session.digest() + b'LeaveMeAlone'
        k_enc.update(data=u_data)
        #print("K_ENC DIGEST: ", k_enc.digest(), "\n", "K_ENC DIGEST TYPE:", type(k_enc.digest()))
        #print("U DATA: ", u_data, "\n", "U DATA TYPE: ", type(u_data))
        int_key = int.from_bytes(k_enc.digest(), byteorder='big')  #int version of session key
        k_hmac = SHA3_256.new()
        u_data = k_enc.digest() + b'GlovesAndSteeringWheel'
        k_hmac.update(data=u_data)
        kdf_next = SHA3_256.new()
        u_data = k_hmac.digest() + b'YouWillNotHaveTheDrink'
        kdf_next.update(data=u_data)

        # starting to decrypt messages

        array_msg = MSG.to_bytes((MSG.bit_length()+7)//8, byteorder='big')
        hmac_message = array_msg[-32:]
        message_data = array_msg[8:-32]
        verify_hmac = HMAC.new(key=k_hmac.digest(), digestmod=SHA256)
        verify_hmac.update(msg=message_data)
        try:
            verify_hmac.verify(hmac_message)
            print("The message is authentic")
            authentic = True


        except ValueError:
            print("Hmac couldn't be verified")
            authentic = False


        s_cipher = AES.new(int_key.to_bytes((int_key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR, nonce=array_msg[0:8])
        plaintext = s_cipher.decrypt(array_msg[8:-32])
        print("plaintext: ", plaintext)
        print("decoded plaintext: ", str(plaintext.decode(encoding='UTF-8',errors='strict'))) #https://www.youtube.com/watch?v=mJXUNMexT1c
        if(authentic):
            Checker(stuID, ID_b, MSG_id, str(plaintext.decode(encoding='UTF-8',errors='strict')))
            message_box[y] = str(plaintext.decode(encoding='UTF-8',errors='strict'))
        else:
            Checker(stuID, ID_b, MSG_id, "INVALIDHMAC")
            message_box[y] = "INVALIDHMAC"


    else:
        k_enc = SHA3_256.new()
        u_data = kdf_next.digest() + b'LeaveMeAlone'
        k_enc.update(data=u_data)
        #print("K_ENC DIGEST: ", k_enc.digest(), "\n", "K_ENC DIGEST TYPE:", type(k_enc.digest()))
        #print("U DATA: ", u_data, "\n", "U DATA TYPE: ", type(u_data))
        int_key = int.from_bytes(k_enc.digest(), byteorder='big')  #int version of session key
        k_hmac = SHA3_256.new()
        u_data = k_enc.digest() + b'GlovesAndSteeringWheel'
        k_hmac.update(data=u_data)
        kdf_next = SHA3_256.new()
        u_data = k_hmac.digest() + b'YouWillNotHaveTheDrink'
        kdf_next.update(data=u_data)
        # starting to decrypt messages

        array_msg = MSG.to_bytes((MSG.bit_length()+7)//8, byteorder='big')
        hmac_message = array_msg[-32:]
        message_data = array_msg[8:-32]
        verify_hmac = HMAC.new(key=k_hmac.digest(), digestmod=SHA256)
        verify_hmac.update(msg=message_data)
        try:
            verify_hmac.verify(hmac_message)
            print("The message is authentic")
            authentic = True


        except ValueError:
            print("Hmac couldn't be verified")
            authentic = False

        s_cipher = AES.new(int_key.to_bytes((int_key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR, nonce=array_msg[0:8])
        plaintext = s_cipher.decrypt(array_msg[8:-32])
        print("plaintext: ", plaintext)
        print("decoded plaintext: ", str(plaintext.decode(encoding='UTF-8',errors='strict'))) #https://www.youtube.com/watch?v=mJXUNMexT1c
        if(authentic):
            Checker(stuID, ID_b, MSG_id, str(plaintext.decode(encoding='UTF-8',errors='strict')))
            message_box[y] = str(plaintext.decode(encoding='UTF-8',errors='strict'))
        else:
            Checker(stuID, ID_b, MSG_id, "INVALIDHMAC")
            message_box[y] = "INVALIDHMAC"


#PHASE 3 STARTS
random.seed(37)
k = random.randint(0, E.order-3)
R = k*P
lower_r = (R.x) % n
stuid_b = 18007
stuid_b = stuid_b.to_bytes((stuid_b.bit_length()+7)//8, byteorder='big')
hashdata = lower_r.to_bytes((lower_r.bit_length()+7)//8, byteorder='big') + stuid_b
h_object = SHA3_256.new()
h_object.update(data=hashdata)

h_send = (int.from_bytes(h_object.digest(), byteorder='big'))% n
s_send = (k - (secretkey*int.from_bytes(h_object.digest(), byteorder='big'))) % n
rec_keyid, rec_otkx, rec_otky = reqOTKB(stuID, 18007, h_send, s_send)
print("KEYID: ", rec_keyid)
print("OTK X: ", rec_otkx)
print("OTK Y: ", rec_otky)
#KDF CHAIN
for m in range(5):
    if(m == 0):
        #session key generation
        random.seed(78)
        e_secret = random.randint(0, E.order-2) #Sa
        Q_ephemeral = e_secret*P
        ekeyx = Q_ephemeral.x
        ekeyy = Q_ephemeral.y
        REC_OTK_PUB = Point(rec_otkx, rec_otky, curve)
        T = e_secret*EK_PUB
        T_x = T.x
        T_y = T.y
        U = T_x.to_bytes((T_x.bit_length()+7)//8, byteorder='big') + T_y.to_bytes((T_y.bit_length()+7)//8, byteorder='big') + b'MadMadWorld'
        k_session = SHA3_256.new()
        k_session.update(data=U)
        #encrpytion key, hmac generation
        k_enc = SHA3_256.new()
        u_data = k_session.digest() + b'LeaveMeAlone'
        k_enc.update(data=u_data)
        #print("K_ENC DIGEST: ", k_enc.digest(), "\n", "K_ENC DIGEST TYPE:", type(k_enc.digest()))
        #print("U DATA: ", u_data, "\n", "U DATA TYPE: ", type(u_data))
        int_key = int.from_bytes(k_enc.digest(), byteorder='big')  #int version of session key
        k_hmac = SHA3_256.new()
        u_data = k_enc.digest() + b'GlovesAndSteeringWheel'
        k_hmac.update(data=u_data)
        kdf_next = SHA3_256.new()
        u_data = k_hmac.digest() + b'YouWillNotHaveTheDrink'
        kdf_next.update(data=u_data)

        # sending msg

        sending_msg = message_box[0].encode()
        generate_hmac = HMAC.new(key=k_hmac.digest(), digestmod=SHA256)
        generate_hmac.update(msg=message_data)
        
        en_cipher = AES.new(int_key.to_bytes((int_key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR)
        ciphertext = en_cipher.encrypt(sending_msg)
        temp_array = en_cipher.nonce
        sent_array = temp_array + ciphertext + generate_hmac.digest()
        final_msg = int.from_bytes(sent_array, byteorder='big')
        SendMsg(stuID, 18007, rec_keyid, m+1, final_msg, ekeyx, ekeyy)
        


    else:
        k_enc = SHA3_256.new()
        u_data = kdf_next.digest() + b'LeaveMeAlone'
        k_enc.update(data=u_data)
        #print("K_ENC DIGEST: ", k_enc.digest(), "\n", "K_ENC DIGEST TYPE:", type(k_enc.digest()))
        #print("U DATA: ", u_data, "\n", "U DATA TYPE: ", type(u_data))
        int_key = int.from_bytes(k_enc.digest(), byteorder='big')  #int version of session key
        k_hmac = SHA3_256.new()
        u_data = k_enc.digest() + b'GlovesAndSteeringWheel'
        k_hmac.update(data=u_data)
        kdf_next = SHA3_256.new()
        u_data = k_hmac.digest() + b'YouWillNotHaveTheDrink'
        kdf_next.update(data=u_data)
        # encryption 

        sending_msg = message_box[0].encode()
        generate_hmac = HMAC.new(key=k_hmac.digest(), digestmod=SHA256)
        generate_hmac.update(msg=message_data)
        
        en_cipher = AES.new(int_key.to_bytes((int_key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR)
        ciphertext = en_cipher.encrypt(sending_msg)
        temp_array = en_cipher.nonce
        sent_array = temp_array + ciphertext + generate_hmac.digest()
        final_msg = int.from_bytes(sent_array, byteorder='big')
        SendMsg(stuID, 18007, rec_keyid, m+1, final_msg, ekeyx, ekeyy)


Status(stuID, h, s)


