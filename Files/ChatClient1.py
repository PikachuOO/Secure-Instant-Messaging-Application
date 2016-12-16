import sys
import socket
import select
import hashlib
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from Crypto import Random
import traceback
import time
import datetime
import ast
import os
import pickle
import threading
from random import randint


client_c2_ticket_recv = []
client_c1_ticket_recv = []
client_c1_DHparams = []
client_c2_DHparams = []
global talking_list_c1
talking_list_c1 = []
global talking_list_c2
talking_list_c2 = []

def H(*args):  # a one-way hash function
	a = ':'.join(str(a) for a in args)
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(a)
	hash_of_message = digest.finalize()
	return int(hash_of_message.encode('hex'), 16)
		
	

def H_bytes(*args):  # a one-way hash function
    
	a = ':'.join(str(a) for a in args)
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(a)
	hash_of_message = digest.finalize()
	return hash_of_message
    
	
def H_key(*args):
	try:
		a = ':'.join(str(a) for a in args)
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(a)
		hash_of_message = digest.finalize()
		return hash_of_message

	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	


def cryptrand(n=2048):
    return random.SystemRandom().getrandbits(n) % N

N = '''00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
       4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
       c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
       97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
       c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
       c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
       16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
       9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:
       d0:d4:ca:3c:50:0b:88:5f:e3'''
N = int(''.join(N.split()).replace(':', ''), 16)
g = 2       
global username
global password
global a_new_int
global A_new_int

flags = ["11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "00"]

port_new = randint(5555, 9999)

session_key = ""

try:
	random_gen = Random.new().read


	private_key_client = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
			backend=default_backend()
			)
	public_key_client = private_key_client.public_key()

	public_key_client_serialized = public_key_client.public_bytes(encoding = serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)



	with open("server_public_key.pem", "rb") as key_file:
						server_public_key = serialization.load_pem_public_key(
							key_file.read(),
							backend = default_backend()
						)
except:
	f1 = open("error_log_client.txt", "a+")
	exc_type, exc_value, exc_traceback = sys.exc_info()
	traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
	f1.close()	

def verifySignature(key,signature,message):
	try:
		verifier = key.verifier(
				signature,
				padding.PSS(
					mgf = padding.MGF1(hashes.SHA256()),
					salt_length = padding.PSS.MAX_LENGTH
				),
				hashes.SHA256()
			)
		verifier.update(message)
		verifier.verify()
		return True

	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	

def hashm(message):
	try:
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(message)
		hash_of_message = digest.finalize()
		return hash_of_message
	
	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	
	
def sign_message(key, message):

	signer = key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
	signer.update(message)
	signature = signer.finalize()
	return signature
	


def rsa_enc(key, message):
    try:
		ciphertext = key.encrypt(
			message,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA1()),
				algorithm=hashes.SHA1(),
				label=None))
		return ciphertext
    
    except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	
    
def rsa_dec(key, message):
	try:
		decryptedMsg = key.decrypt(
				message,
				padding.OAEP(
						mgf=padding.MGF1(algorithm=hashes.SHA1()),
						algorithm=hashes.SHA1(),
						label=None))
		return decryptedMsg
	
	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	
	
client_identifier = os.urandom(16)
tag_str = b"tapansingh"
nonce_c1 = os.urandom(32)
time_stamp_11 = datetime.datetime.now()

def gcm_encrypt(key, plaintext, associated_data):
	try:
		iv = os.urandom(12)
		encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
		encryptor.authenticate_additional_data(associated_data)
		ciphertext = encryptor.update(plaintext) + encryptor.finalize()

		return (iv, ciphertext, encryptor.tag)

	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	

def gcm_decrypt(key, associated_data, iv, ciphertext, tag):
	try:
		decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
		decryptor.authenticate_additional_data(associated_data)
		return decryptor.update(ciphertext) + decryptor.finalize()
		
	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	


def p2p_listen_thread(listen_socket):
	try:
		while True:
			accept_socket, address_socket = listen_socket.accept()
			t1 = threading.Thread( target=p2p_listen_sub_thread, args=(accept_socket,address_socket, ))
			t1.start()		
	
	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	
				
def p2p_listen_sub_thread(accept_socket,address_socket):
	try:
		while True:
			global talking_list_c1
			global talking_list_c2
			auth_req_recv = accept_socket.recv(10000)
			
			msgcode, msgg = auth_req_recv.split("##########")
			
			if(msgcode == flags[12]):
				time_stamp_12_str, username_c1_encrypt, client_identifier_c2_encrypt, A_new_str, nonce_c1_recv, auth_req_hash_sign = msgg.split("**********")
				
				time_stamp_12 = datetime.datetime.strptime(time_stamp_12_str, "%Y-%m-%d %H:%M:%S.%f")
				if(time_stamp_12>time_stamp_11):
					
					username_c1 = rsa_dec(private_key_client, username_c1_encrypt)
					client_identifier_c2 = rsa_dec(private_key_client, client_identifier_c2_encrypt)
					
					for client_data in client_c2_ticket_recv:
						if(client_data[0] == username_c1):
							username_c1 = client_data[0]
							client_identifier_c1 = client_data[1]
							public_key_client_c1_serialized = client_data[2]
							client_c1_addr = client_data[3]
							port_new_client_c1 = client_data[4]
							break
						else:
							print "client not requested to connect"	
							
					public_key_client_c1 = load_pem_public_key(public_key_client_c1_serialized, backend=default_backend())
					
					
							
					auth_temp = msgcode + "##########" + time_stamp_12_str + "**********" + username_c1_encrypt + "**********" + client_identifier_c2_encrypt +"**********"+A_new_str+"**********"+nonce_c1_recv
					auth_temp_hash = hashm(auth_temp)
					
					
					if verifySignature(public_key_client_c1, auth_req_hash_sign, auth_temp_hash):
						if(client_identifier_c2 == client_identifier):
							
							username_c2_encrypt =  rsa_enc(public_key_client_c1, username)
							
							client_identifier_c1_encrypt = rsa_enc(public_key_client_c1, client_identifier_c1)
							
							
							b_int = cryptrand()
							B_int = pow(g, b_int, N)
							B_int_str = str(B_int)
							
							c = (username_c1, B_int, b_int)
							client_c2_DHparams.append(c)
							time_stamp_13 = datetime.datetime.now()
							time_stamp_13_str = str(time_stamp_13)
							nonce_c2 = os.urandom(32)
							auth2 = flags[13] + "##########" + time_stamp_13_str + "**********" + username_c2_encrypt + "**********" + client_identifier_c1_encrypt + "**********" + B_int_str + "**********" + nonce_c2 + "**********" + nonce_c1_recv
							
							auth2_hash = hashm(auth2)
							
							
							auth2_hash_sign = sign_message(private_key_client, auth2_hash)
							auth2_send = auth2 +"**********"+ auth2_hash_sign
							
							accept_socket.send(auth2_send)
							
							A_int = int(A_new_str)
							
							S_c2_key_int = pow(A_int, b_int, N)
							K_c2_key = H_bytes(S_c2_key_int)
							session_key1 = H_bytes(str(K_c2_key))
							
							session_key_c2 = session_key1[0:32]
							
							
							
						else:
							os._exit()
					else:
						os._exit()
				
			elif(msgcode == flags[14]):
				
				time_stamp_14_str, iv4, tag_str, tag_encrypted, auth3_encrypted = msgg.split("**********") 
				
				time_stamp_14 = datetime.datetime.strptime(time_stamp_14_str, "%Y-%m-%d %H:%M:%S.%f")
				
				if(time_stamp_14>time_stamp_13):
					msg_temp = msgcode + "##########" + time_stamp_14_str +"**********"+ iv4 +"**********"+ tag_str +"**********"+ tag_encrypted +"**********"+ auth3_encrypted 
					
					auth3_decrypt = gcm_decrypt(session_key_c2, tag_str, iv4, auth3_encrypted, tag_encrypted)
					if(auth3_decrypt == nonce_c2):
						
						c = (username, username_c1, session_key_c2, accept_socket)
						talking_list_c1.append(c)
												
					else:
						os._exit()
							
				else:
					os._exit()
					
			elif(msgcode == flags[15]):
				iv1, tag_str, tag_enc, msg_enc = msgg.split("**********")
				
				
				msg_recv = gcm_decrypt(session_key_c2, tag_str, iv1, msg_enc, tag_enc)
				
				
				time_stamp_15_str, uname_sender, msg = msg_recv.split("**********")
				time_stamp_15 = datetime.datetime.strptime(time_stamp_15_str, "%Y-%m-%d %H:%M:%S.%f")
				if(time_stamp_15 > time_stamp_14):
					sys.stdout.write("\n" + "< - " + uname_sender + " - > " + msg); sys.stdout.flush()
					
				else:
					os._exit()
			
			elif(msgcode == flags[17]):
				iv1, tag_str, tag_enc, msg_enc = msgg.split("**********")
				msg_dec = gcm_decrypt(session_key_c2, tag_str, iv1, msg_enc, tag_enc)
				
				time_stamp_19_str, user_logout, msg = msg_dec.split("**********")
				time_stamp_19 = datetime.datetime.strptime(time_stamp_14_str, "%Y-%m-%d %H:%M:%S.%f")
				if(msg == "LOGOUT"):
					for client in talking_list_c1:
						if(client[1] == user_logout):
							sock1 = client[3]
							talking_list_c1.remove(client)
							sock1.shutdown(socket.SHUT_RDWR)
							sock1.close()
							
	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()		
			
			
		
	
	
	
A_new_str = ""	
time_stamp_11
def client_to_client(c12_socket, username_c2, client_identifier_c2, public_key_client_c2_serialized):
	try:
		public_key_client_c2 = load_pem_public_key(public_key_client_c2_serialized, backend=default_backend())
		
		while True:
			global talking_list_c1
			global talking_list_c2
			message1 = c12_socket.recv(10000)
			
			msgcode, message = message1.split("##########")
			
			if(msgcode == flags[13]):
				time_stamp_13_str, username_c2_encrypt, client_identifier_c1_encrypt, B_int_str, nonce_c2_recv, nonce_c1_recv, auth2_recv_hash_sign = message.split("**********")
				
				time_stamp_13 = datetime.datetime.strptime(time_stamp_13_str, "%Y-%m-%d %H:%M:%S.%f")
				
				if(time_stamp_13>time_stamp_11):
					if(nonce_c1 == nonce_c1_recv):
						
						username_c2_recv = rsa_dec(private_key_client, username_c2_encrypt)
						client_identifier_c1_decrypt = rsa_dec(private_key_client, client_identifier_c1_encrypt)
						if(username_c2_recv == username_c2 and client_identifier == client_identifier_c1_decrypt ):
							auth2_recv = msgcode + "##########" + time_stamp_13_str + "**********" + username_c2_encrypt + "**********" + client_identifier_c1_encrypt + "**********" + B_int_str + "**********" + nonce_c2_recv + "**********" + nonce_c1_recv
							auth2_recv_hash = hashm(auth2_recv)
							
							
					
							if verifySignature(public_key_client_c2, auth2_recv_hash_sign, auth2_recv_hash):
								
								B_int = int(B_int_str)
								for c in client_c1_DHparams:
									if(c[0] == username_c2):
										a_int = c[2]
										break
								
								S_c1_key = pow(B_int, a_int, N)
								
								K_c1_key = H_bytes(S_c1_key)
								session_key1 = H_bytes(str(K_c1_key))
								
								session_key_c1 = session_key1[0:32]
								
								
								
								time_stamp_14 = datetime.datetime.now()
								time_stamp_14_str = str(time_stamp_14)
								tag_str = os.urandom(16)
								auth3 = nonce_c2_recv
								iv4, auth3_encrypt, tag_encrypted = gcm_encrypt(session_key_c1, auth3, tag_str)
								
								auth3_msg = flags[14] + "##########" + time_stamp_14_str +"**********"+ iv4 +"**********"+ tag_str +"**********"+ tag_encrypted +"**********"+ auth3_encrypt
								
								
								c = (username, username_c2, session_key_c1, c12_socket)
								talking_list_c1.append(c)
								
								c12_socket.send(auth3_msg)
								
								print "\n" + username_c2 + " authenticated" + "\n"
								
							else:
								os._exit()
							
						else:
							os._exit()
					else:
						os._exit
				else:
					os._exit	
					
						
			elif(msgcode == flags[15]):
				iv1, tag_str, tag_enc, msg_enc = message.split("**********")
				
				msg_recv = gcm_decrypt(session_key_c1, tag_str, iv1, msg_enc, tag_enc)
				
				time_stamp_15_str, uname_sender, msg = msg_recv.split("**********")
				time_stamp_15 = datetime.datetime.strptime(time_stamp_15_str, "%Y-%m-%d %H:%M:%S.%f")
				if(time_stamp_15 > time_stamp_14):
					sys.stdout.write("\n" + "< - " + uname_sender + " - > " + msg); sys.stdout.flush()
					
				else:
					os._exit()
					
		
	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()			
		
	
	
	
	
time_stamp_6 = datetime.datetime.now() 
def receive_thread(s1,):
	try:
		while True:
			global talking_list_c1
			global talking_list_c2
			message77 = s1.recv(10000)
			msgcode, message777 = message77.split("##########")
			
		
			if(msgcode == flags[7]):
				iv2, tag_server_str, tag_encrypted, message7777_encrypted = message777.split("**********")
				message7777_decrypted = gcm_decrypt(session_key, tag_server_str, iv2, message7777_encrypted, tag_encrypted)
		
				time_stamp_7_str, active_list = message7777_decrypted.split("**********")
		
				time_stamp_7 = datetime.datetime.strptime(time_stamp_7_str, "%Y-%m-%d %H:%M:%S.%f")

				if(time_stamp_7>time_stamp_6):
		
					sys.stdout.write("\nACTIVE LIST\n" + active_list + "\n"); sys.stdout.flush()
													
				else:
					sys.exit()
		
			elif(msgcode == flags[8]):
				iv3, tag_server_str, tag_encrypted, message88_encrypted = message777.split("**********")
				message88 = gcm_decrypt(session_key, tag_server_str, iv3, message88_encrypted, tag_encrypted)
			
				time_stamp_8_str, message888 = message88.split("**********")
		
				time_stamp_8 = datetime.datetime.strptime(time_stamp_8_str, "%Y-%m-%d %H:%M:%S.%f")
				
				if(time_stamp_8>time_stamp_6):
					sys.stdout.write(message888); sys.stdout.flush()
				else:
					sys.exit()
		
			elif(msgcode == flags[10]):
				
				iv3, tag_server_str, tag_encrypted, message99_encrypted = message777.split("**********")
				message99 = gcm_decrypt(session_key, tag_server_str, iv3, message99_encrypted, tag_encrypted)
				time_stamp_9_str, username_c1, client_identifier_c1, public_key_client_c1_serialized, client_c1_addr, port_new_client_c1 = message99.split("**********")
				
				time_stamp_9 = datetime.datetime.strptime(time_stamp_9_str, "%Y-%m-%d %H:%M:%S.%f")
			
				if(time_stamp_9>time_stamp_6):
					c = (username_c1, client_identifier_c1, public_key_client_c1_serialized, client_c1_addr, port_new_client_c1)
					client_c2_ticket_recv.append(c)
				
			elif(msgcode == flags[11]):
				
				iv3, tag_server_str, tag_encrypted, message99_encrypted = message777.split("**********")
				message99 = gcm_decrypt(session_key, tag_server_str, iv3, message99_encrypted, tag_encrypted)
				time_stamp_9_str, username_c2, client_identifier_c2, public_key_client_c2_serialized, client_c2_addr, port_new_client_c2 = message99.split("**********")
				c = (username_c2, client_identifier_c2, public_key_client_c2_serialized, client_c2_addr, port_new_client_c2)
				client_c1_ticket_recv.append(c)
				time_stamp_9 = datetime.datetime.strptime(time_stamp_9_str, "%Y-%m-%d %H:%M:%S.%f")
					
				if(time_stamp_9>time_stamp_6):
					c12_socket = socket.socket()
					c12_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
					c12_socket.connect((client_c2_addr, int(port_new_client_c2)))
					t2 = threading.Thread( target=client_to_client, args=(c12_socket, username_c2, client_identifier_c2, public_key_client_c2_serialized, ))
					t2.start()
					
					public_key_client_c2 = load_pem_public_key(public_key_client_c2_serialized, backend=default_backend())
					
					username_c1_encrypt = rsa_enc(public_key_client_c2, username)
					
					client_identifier_c2_encrypt = rsa_enc(public_key_client_c2, client_identifier_c2)
					
					time_stamp_11 = datetime.datetime.now()
					time_stamp_11_str = str(time_stamp_11)
					a_new_int = cryptrand()
					A_new_int = pow(g, a_new_int, N)
					A_new_str = str(A_new_int)
					c = (username_c2, A_new_int, a_new_int)
					client_c1_DHparams.append(c)
					auth_req = flags[12] + "##########" + time_stamp_11_str + "**********" + username_c1_encrypt + "**********" + client_identifier_c2_encrypt +"**********"+A_new_str+"**********"+nonce_c1
					auth_req_hash = hashm(auth_req)
					
					auth_req_hash_sign = sign_message(private_key_client, auth_req_hash)
					auth_req_signed = auth_req + "**********" + auth_req_hash_sign
					
					c12_socket.send(auth_req_signed)
					
				else:
					sys.exit()
													
			elif(msgcode == flags[18]):
				iv3, tag_server_str, tag_encrypted, message99_encrypted = message777.split("**********")
				message99 = gcm_decrypt(session_key, tag_server_str, iv3, message99_encrypted, tag_encrypted)
				time_stamp_10_str, username_c2, msg = message99.split("**********")
				time_stamp_10 = datetime.datetime.strptime(time_stamp_10_str, "%Y-%m-%d %H:%M:%S.%f")
				if(time_stamp_10>time_stamp_6):
					if(msg == "LOGOUT"):
						for client in talking_list_c1:
							if(username_c2 == client[1]):
								socket11 = client[3]
								talking_list_c1.remove(client)
								break
						
						c12_socket.shutdown(socket.SHUT_RDWR)
						c12_socket.close()
						
						socket11.shutdown(socket.SHUT_RDWR)		
						socket11.close()
			

	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	






	
if __name__ == "__main__":
	try:
		host = sys.argv[1]
		port = int(sys.argv[2])
		s = socket.socket()         
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.connect((host, port))
		
		p2p_listen_socket = socket.socket()         
		p2p_listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		host = 'localhost'
		port = port_new 
		p2p_listen_address = (host, port)
		p2p_listen_socket.bind((host, port))
		p2p_listen_socket.listen(10)
		p2psocketdetails=p2p_listen_socket.getsockname()
		
		sys.stdout.write("Username: "); sys.stdout.flush()
		username1 = sys.stdin.readline()
		sys.stdout.write("\n"); sys.stdout.flush()
		sys.stdout.write("Password: "); sys.stdout.flush()
		password1 = sys.stdin.readline() 
		
		username = username1.rstrip()
		password = password1.rstrip()
		a_int = cryptrand()
		A_int = pow(g, a_int, N)
		time_stamp_1 = datetime.datetime.now()
		time_stamp_1_str = str(time_stamp_1)
		
		message1 = flags[0] + "##########" + time_stamp_1_str +"**********" + username + "**********" + str(A_int)
		message1_hash = H_bytes(message1)
			
		
		message = message1 + "**********" + message1_hash
		s.send(message)
		
		data1 = s.recv(10000)
		
				
			
		if(data1 == "User_Not_Found"):
			print "\nUsername Not Found\n"
			os._exit()
		msgcode, message2 = data1.split("##########")
		
		if(msgcode == flags[1]):
			time_stamp_2_str, s_str, B_str, message2_hash_sign = message2.split("**********")
			time_stamp_2 = datetime.datetime.strptime(time_stamp_2_str, "%Y-%m-%d %H:%M:%S.%f")
			if(time_stamp_2>time_stamp_1):
				message22 = flags[1] + "##########" + time_stamp_2_str +"**********"+ s_str +"**********"+ B_str
				message22_hash = H_bytes(message22)
				
				if verifySignature(server_public_key, message2_hash_sign, message22_hash):

					B_int = int(B_str)
					
					u_int = H(A_int, B_int)
					u_str = str(u_int)
					x_int = H(int(s_str), username, password)
					x_str = str(x_int)
						
					k_int = H(N, g)	
					S_c_int = pow(B_int - k_int * pow(g, x_int, N), a_int + u_int * x_int, N)
					K_c_int = H(S_c_int)
						
					M_c_int = H(H(N) ^ H(g), H(username), int(s_str), A_int, B_int, K_c_int)
					M_c_str = str(M_c_int)
					time_stamp_3 = datetime.datetime.now()
					time_stamp_3_str = str(time_stamp_3)
						
					message33 = flags[2] + "##########" + time_stamp_3_str +"**********" + M_c_str
					message33_hash = H_bytes(message33)
					message333 = message33 + "**********" +message33_hash
						
					s.send(message333)
			
					message3 = s.recv(10000)

					if(message3 == "wrong_password"):
						print message3 + "\n"
						sys.exit()
					
					msgcode, message44 = message3.split("##########")	
					if(msgcode == flags[3]):
						time_stamp_4_str, M_s_str, message4_hash = message44.split("**********")
						time_stamp_4 = datetime.datetime.strptime(time_stamp_4_str, "%Y-%m-%d %H:%M:%S.%f")
			
						if(time_stamp_4>time_stamp_3):
							message444 = msgcode +"##########"+ time_stamp_4_str +"**********"+ M_s_str
							message444_hash = H_bytes(message444)
								
							if(message444_hash == message4_hash):
		
								M_s_int = int(M_s_str)
						
								M_s_int_verify = H(A_int, M_c_int, K_c_int)
							
								if(M_s_int_verify == M_s_int):
									
									session_key1 = H_bytes(str(K_c_int)) 								
									
									session_key += session_key1[0:32]
									
									time_stamp_5 = datetime.datetime.now()
									time_stamp_5_str = str(time_stamp_5)
										
									message5 = time_stamp_5_str + "**********" + client_identifier + "**********" + public_key_client_serialized+"**********"+str(port_new)
									
										

									
									iv, message5_cipher, tag_encrypted = gcm_encrypt(session_key, message5, tag_str)
										
		
									message55 = iv + "**********" +tag_str+"**********"+tag_encrypted+"**********"+ message5_cipher
										
									message555 = flags[4] + "##########" + message55
										
									s.send(message555)
										
																		 
					
								else:
									sys.exit()
								
							else:
								sys.exit()
						else:
							sys.exit()
					else:
						sys.exit()
				else:
					sys.exit()
			else:
				sys.exit()
		else:
			sys.exit()

		t = threading.Thread(target=receive_thread, args=(s,))
		t.start()
		t1 = threading.Thread(target=p2p_listen_thread, args=(p2p_listen_socket,))
		t1.start()
		sys.stdout.write("\nLogged In!!!\n"); sys.stdout.flush()
		while True:
			
			command1 = sys.stdin.readline()
			flag11 = 0
			flag22 = 0
			
			if(command1 == "list\n"):
				command = command1.rstrip()
				time_stamp_6 = datetime.datetime.now()
				time_stamp_6_str = str(time_stamp_6)
		
				message6 = time_stamp_6_str +"**********"+ command
				iv1, message6_encrypted, tag_encrypted = gcm_encrypt(session_key, message6, tag_str)
							
				message66 = flags[6] + "##########" + username+"**********"+iv1 +"**********"+tag_str+"**********"+ tag_encrypted +"**********"+message6_encrypted
		
				s.send(message66)   
			elif(command1 == "connect\n"):
				command = command1.rstrip()
				username_c22 = sys.stdin.readline()
				username_c2 = username_c22.rstrip()
				
				time_stamp_7 = datetime.datetime.now()
				time_stamp_7_str = str(time_stamp_7)
		
				message7 = time_stamp_7_str +"**********"+ command
				iv1, message6_encrypted, tag_encrypted = gcm_encrypt(session_key, message7, tag_str)
							
				message77 = flags[6] + "##########" + username+"**********"+iv1 +"**********"+tag_str+"**********"+ tag_encrypted +"**********"+message6_encrypted
		
				s.send(message77)
				
				time_stamp_8 = datetime.datetime.now()
				time_stamp_8_str = str(time_stamp_8)
		
				message8 = time_stamp_8_str +"**********"+ username_c2
				iv1, message8_encrypted, tag_encrypted = gcm_encrypt(session_key, message8, tag_str)
							
				message88 = flags[9] + "##########" + username+"**********"+iv1 +"**********"+tag_str+"**********"+ tag_encrypted +"**********"+message8_encrypted
				s.send(message88)
				
				
			elif(command1 == "send\n"):
				
				username_c2 = sys.stdin.readline()
				username_c2_id = username_c2.rstrip()
				
				
				for user in talking_list_c1:
					if(username_c2_id == user[1]):
						username_c2_id = user[1]
						session_key_c12 = user[2]
						socket_msg = user[3]
						flag22 = 1
						
						break
					else:
						flag22 = 2
					
				if(flag22 == 2):
					print "\n\nUser Not connected\n\n"
					
				
				elif(flag22 == 1):	
					msg1 = sys.stdin.readline()
					
					time_stamp_14 = datetime.datetime.now()
					time_stamp_14_str = str(time_stamp_14)
					msg = time_stamp_14_str +"**********"+ username +"**********"+  msg1
					iv1, msg_enc, tag_enc = gcm_encrypt(session_key_c12, msg, tag_str)
					
					msg_send = flags[15] + "##########" + iv1 + "**********" + tag_str + "**********" + tag_enc + "**********" + msg_enc
					
					socket_msg.send(msg_send)
					
				else:
					print "\n\nUSER NOT CONNECTED\n\n"	
					
			elif(command1 == "exitchat\n"):
				flag22 = 0
				uname1 = sys.stdin.readline()
				uname = uname1.rstrip()
				for user in talking_list_c1:
					if(uname == user[1]):
						username_c2_id = user[1]
						session_key_c12 = user[2]
						socket_msg = user[3]
						flag22 = 1
						break
					else:
						flag22 = 0
				
				if(flag22 == 0):
					print "\n\nNOT CONNECTED WITH " + uname + "\n"
				
				else:
					msg1 = "EXIT_CHAT"
					time_stamp_15 = datetime.datetime.now()
					time_stamp_15_str = str(time_stamp_15)
					msg = time_stamp_15_str +"**********"+ username +"**********"+  msg1
					iv1, msg_enc, tag_enc = gcm_encrypt(session_key_c12, msg, tag_str)
					
					msg_send = flags[16] + "##########" + iv1 + "**********" + tag_str + "**********" + tag_enc + "**********" + msg_enc
					
					socket_msg.send(msg_send)
					
					socket_msg.shutdown(socket.SHUT_RDWR)
					socket_msg.close()
					for user in talking_list_c1:
						if(uname == user[1]):
							talking_list_c1.remove(user)
					
				
					
			elif(command1 == "logout\n"):
				msg1 = "LOGOUT"
				
				time_stamp_17 = datetime.datetime.now()
				time_stamp_17_str = str(time_stamp_17)
				msg = time_stamp_17_str + "**********" + msg1
				
				iv2, msg_enc2, tag_enc2 = gcm_encrypt(session_key, msg, tag_str)
				
				msg_send_s = flags[6] + "##########" +username+ "**********" + iv2 + "**********" + tag_str + "**********" + tag_enc2 + "**********" + msg_enc2
				s.send(msg_send_s)
				
				
				for user2 in talking_list_c1:
					uname3 = user2[1]
					session_key_c12 = user2[2]
					socket_msg = user2[3]
					msg2 = time_stamp_17_str + "**********"+username+"**********" + msg1
					iv1, msg_enc, tag_enc = gcm_encrypt(session_key_c12, msg2, tag_str)
					msg_send_c = flags[17] + "##########"  +iv1 + "**********" + tag_str + "**********" + tag_enc + "**********" + msg_enc
					socket_msg.send(msg_send_c)
					talking_list_c1.remove(user2)
					
				
				
				s.shutdown(socket.SHUT_RDWR)
				s.close()
						
				os._exit()
				
				
			else:
				print "INVALID COMMAND"
	
	except:
		f1 = open("error_log_client.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()		
			


