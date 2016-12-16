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
import os
import sys
import traceback
import time
import datetime
import ast
import os
import threading
import pickle

host = ''
SOCKET_LIST = []
ACTIVE_LIST = []
RECV_BUFFER = 10000

try:
	with open("server_private_key.pem", "rb") as key_file:
		server_private_key = serialization.load_pem_private_key(
								key_file.read(),
								password = None,
								backend = default_backend()
							)

	server_public_key = server_private_key.public_key()

	server_public_key_serialized = server_public_key.public_bytes(encoding = serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

except:
	f1 = open("error_log_server.txt", "a+")
	exc_type, exc_value, exc_traceback = sys.exc_info()
	traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
	f1.close()	



flags = ["11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "00"]

err_msg = "msgcode mismatch"

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

def H(*args):  # a one-way hash function
	try:
		a = ':'.join(str(a) for a in args)
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(a)
		hash_of_message = digest.finalize()
		return int(hash_of_message.encode('hex'), 16)

	except:
		f1 = open("error_log_server.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	

def H_bytes(*args):  # a one-way hash function
	try:
		a = ':'.join(str(a) for a in args)
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(a)
		hash_of_message = digest.finalize()
		return hash_of_message
	except:
		f1 = open("error_log_server.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	

def H_key(*args):
	try:
		a = ':'.join(str(a) for a in args)
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(a)
		hash_of_message = digest.finalize()
		return hash_of_message
		
	except:
		f1 = open("error_log_server.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	

def cryptrand():
	try:
		return random.SystemRandom().getrandbits(2048) % N
	except:
		f1 = open("error_log_server.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	

tag_server_str = os.urandom(32)

def gcm_encrypt(key, plaintext, associated_data):
	try:
		iv = os.urandom(12)
		encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
		encryptor.authenticate_additional_data(associated_data)
		ciphertext = encryptor.update(plaintext) + encryptor.finalize()

		return (iv, ciphertext, encryptor.tag)
	
	except:
		f1 = open("error_log_server.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	

def gcm_decrypt(key, associated_data, iv, ciphertext, tag):
	try:
		decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
		decryptor.authenticate_additional_data(associated_data)
		return decryptor.update(ciphertext) + decryptor.finalize()
		
	except:
		f1 = open("error_log_server.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	

def sign_message(key, message):
	try:
		
		signer = key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
		signer.update(message)
		signature = signer.finalize()
		return signature
	
	except:
		f1 = open("error_log_server.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	


def client_thread(sockfd,addr):
	try:
	
		data = sockfd.recv(RECV_BUFFER)
				
		if data:
			msgcode, message = data.split("##########")
			
			if(msgcode == flags[0]):
				time_stamp_str_1, username, A_str, message_hash = message.split("**********")
				
				
				message_recv = msgcode+"##########"+time_stamp_str_1+"**********"+username+"**********"+A_str
				
					
								
									
				message_recv_hash = H_bytes(message_recv)
				
					
						
						
				if (message_hash == message_recv_hash):
					
					time_stamp_1 = datetime.datetime.strptime(time_stamp_str_1, "%Y-%m-%d %H:%M:%S.%f")
						
				else:
					
					sockfd.send(err_msg +"**********"+ "dfd")
					exc_type, exc_value, exc_traceback = sys.exc_info()
					traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = sys.stdout); sys.stdout.flush()
					sockfd.shutdown(socket.SHUT_RDWR)
					sockfd.close()
					SOCKET_LIST.remove(sockfd)
					sys.exit()
							
						
								
				
				A_int = int(A_str)
				flag = 0
				f1 = open("client_list_server.txt", 'r')
				while(flag == 0):
					buf = f1.readline()
					if not buf:
						break
					username1, s_str, v_str, k_str, N_str, g_str = buf.split("**********")
					
					if(username == username1):
						flag = 1
						break

				if(flag == 0):
					
					sockfd.send("User_Not_Found")
					sockfd.shutdown(socket.SHUT_RDWR)
					sockfd.close()
					SOCKET_LIST.remove(sockfd)
					f1.close()
					
					

				elif(flag == 1):
					
					

					b_int = random.SystemRandom().getrandbits(2048) % int(N_str)
					B_int = (int(k_str) * int(v_str) + pow(int(g_str), b_int, int(N_str))) % int(N_str)
					
					time_stamp_2 = datetime.datetime.now()
					time_stamp_2_str = str(time_stamp_2)
					message = flags[1] + "##########" + time_stamp_2_str + "**********" + s_str + "**********" + str(B_int)
					message_hash = H_bytes(message)
					
					message_hash_sign = sign_message(server_private_key, message_hash)
					message1 = message + "**********" +message_hash_sign

					sockfd.send(message1)

					u_int = H(A_int, B_int)
					u_str = str(u_int)

					S_s_int = pow(A_int * pow(int(v_str), u_int, int(N_str)), b_int, int(N_str))

					K_s_int = H(S_s_int)	

					message1 = sockfd.recv(RECV_BUFFER)
					msgcode, message11 = message1.split("##########")
					if(msgcode == flags[2]):
						time_stamp_3_str, M_c_str, message11_hash = message11.split("**********")
						time_stamp_3 = datetime.datetime.strptime(time_stamp_3_str, "%Y-%m-%d %H:%M:%S.%f")
						if(time_stamp_3> time_stamp_2):
							message111 =msgcode +"##########"+ time_stamp_3_str +"**********"+ M_c_str
							message111_hash = H_bytes(message111)
				
							if(message111_hash == message11_hash):
		
								M_c_int = int(M_c_str)
							
								M_c_int_verify = H(H(int(N_str)) ^ H(int(g_str)), H(username1), int(s_str), A_int, B_int, K_s_int)	
									
								if(M_c_int_verify == M_c_int):
									M_s_int = H(A_int, M_c_int, K_s_int)
									M_s_str = str(M_s_int)
									time_stamp_4 = datetime.datetime.now()
									time_stamp_4_str = str(time_stamp_4)
									
									message4 = flags[3] + "##########" + time_stamp_4_str + "**********" +M_s_str
						
									message4_hash = H_bytes(message4)
				
									message44 = message4 + "**********" +message4_hash			
			
									sockfd.send(message44)
									status = "online"
										
										
									session_key1 = H_bytes(str(K_s_int))
									
									session_key = session_key1[0:32]

									message5 = sockfd.recv(RECV_BUFFER)
		
									msgcode, message55 = message5.split("##########")
										
									if (msgcode == flags[4]):
										iv, tag_str, tag_encrypted, message55_cipher = message55.split("**********") 
											
									
										message_decrypted = gcm_decrypt(session_key, tag_str, iv, message55_cipher, tag_encrypted)
										
										time_stamp_str_5, client_identifier, public_key_client_serialized, port_new_client = message_decrypted.split("**********")	
										time_stamp_5 = datetime.datetime.strptime(time_stamp_str_5, "%Y-%m-%d %H:%M:%S.%f")
										if(time_stamp_5>time_stamp_4):
											
											public_key_client = load_pem_public_key(public_key_client_serialized, backend=default_backend())
											client_addr = sockfd.getpeername()
											
											client_data = (username, client_identifier, session_key, public_key_client_serialized, client_addr[0], port_new_client, sockfd)
											ACTIVE_LIST.append(client_data)
											
		
											while True:
												message6 = sockfd.recv(RECV_BUFFER)
												
									
												msgcode, message66 = message6.split("##########")
			
												if(msgcode == flags[6]):
													username2, iv1, tag_str, tag_encrypted, message66_encrypted = message66.split("**********")	
													for client_data in ACTIVE_LIST:
														
														if(client_data[0] == username2):
															session_key_client = client_data[2]	
															break

													message66_decrypt = gcm_decrypt(session_key_client, tag_str, iv1, message66_encrypted, tag_encrypted)
					
													time_stamp_6_str, command = message66_decrypt.split("**********")
													
													time_stamp_6 = datetime.datetime.strptime(time_stamp_6_str, "%Y-%m-%d %H:%M:%S.%f")


													if(time_stamp_6>time_stamp_5):
														
														if(command == "list"):
															if(len(ACTIVE_LIST) == 1):
																str3 = "NO ACTIVE USERS"
																time_stamp_8 = datetime.datetime.now()
									
																time_stamp_8_str = str(time_stamp_8)

																message8 = time_stamp_8_str + "**********" + str3
		
																iv3, message8_encrypted, tag_encrypted = gcm_encrypt(session_key_client, message8, tag_server_str)

																message88 = flags[8] +"##########"+ iv3 +"**********"+ tag_server_str+"**********"+tag_encrypted+"**********"+message8_encrypted

																sockfd.send(message88) 
															else:
																active_list = ""
																for client_data in ACTIVE_LIST:
																	if(username2 == str(client_data[0])):
																		continue
																	active_list += str(client_data[0]) + "\n"
			
																time_stamp_7 = datetime.datetime.now()
												
																time_stamp_7_str = str(time_stamp_7)
															
																message7 = time_stamp_7_str + "**********" +active_list		
																iv2, message7_encrypted, tag_encrypted = gcm_encrypt(session_key_client, message7, tag_server_str)	
			
															
																message77 = flags[7] +"##########"+ iv2 +"**********"+ tag_server_str+"**********"+tag_encrypted+"**********"+message7_encrypted
		
		
																sockfd.send(message77)
			
														if(command == "connect"):
															message8 = sockfd.recv(RECV_BUFFER)
															msgcode, message88 = message8.split("##########")
															if(msgcode==flags[9]):
																username2, iv1, tag_str, tag_encrypted, message88_encrypted = message88.split("**********")	
																for client_data in ACTIVE_LIST:
														
																	if(client_data[0] == username2):
																		session_key_client = client_data[2]	
																		break
																	
																message88_decrypt = gcm_decrypt(session_key_client, tag_str, iv1, message88_encrypted, tag_encrypted)
					
																time_stamp_8_str, username_c2 = message88_decrypt.split("**********")
													
																time_stamp_8 = datetime.datetime.strptime(time_stamp_8_str, "%Y-%m-%d %H:%M:%S.%f")
																
																if(time_stamp_8>time_stamp_6):
																	for client_data in ACTIVE_LIST:
																		if(username_c2 == client_data[0]):
																			username_c2 = client_data[0] 
																			client_identifier_c2 = client_data[1]
																			session_key_c2 = client_data[2]
																			public_key_client_c2_serialized = client_data[3]
																			client_c2_addr = client_data[4]
																			port_new_client_c2 = str(client_data[5])
																			client_c2_socket = client_data[6]
																			break
																	
																	
																	
																	for client_data in ACTIVE_LIST:
																		if(username2 == client_data[0]):
																			username_c1 = client_data[0] 
																			client_identifier_c1 = client_data[1]
																			session_key_c1 = client_data[2]
																			public_key_client_c1_serialized = client_data[3]
																			client_c1_addr = client_data[4]
																			port_new_client_c1 =  str(client_data[5])
																			client_c1_socket = client_data[6]
																			break
																	time_stamp_8 = datetime.datetime.now()
									
																	time_stamp_8_str = str(time_stamp_8)
																	
																	message_c2 = time_stamp_8_str +"**********"+username_c1 +"**********"+ client_identifier_c1 +"**********"+ public_key_client_c1_serialized +"**********"+ client_c1_addr  + "**********" + port_new_client_c1
																	iv, message_c2_encrypted, tag_encrypted = gcm_encrypt(session_key_c2, message_c2, tag_server_str) 
																	
																	message_c2_send = flags[10] + "##########" + iv + "**********" + tag_server_str + "**********" + tag_encrypted + "**********" + message_c2_encrypted
																	client_c2_socket.send(message_c2_send)
																	
																	
																	
																	message_c1 = time_stamp_8_str +"**********"+username_c2 + "**********" + client_identifier_c2 + "**********" + public_key_client_c2_serialized  + "**********" + client_c2_addr + "**********" + port_new_client_c2	
																	iv, message_c1_encrypted, tag_encrypted = gcm_encrypt(session_key_c1, message_c1, tag_server_str) 
																	
																	message_c1_send = flags[11] + "##########" + iv + "**********" + tag_server_str + "**********" + tag_encrypted + "**********" + message_c1_encrypted
																	sockfd.send(message_c1_send)
																	
																else:
																	sockfd.shutdown(socket.SHUT_RDWR)
																	SOCKET_LIST.remove(sockfd)
																	sockfd.close()
																	sys.exit()
																	
															else:
																sockfd.shutdown(socket.SHUT_RDWR)
																SOCKET_LIST.remove(sockfd)
																sockfd.close()
																sys.exit()
															
														if(command == "LOGOUT"):
															
															for client in ACTIVE_LIST:
																if(username2 == client[0]):
																	
																	ACTIVE_LIST.remove(client)
																	sockfd.shutdown(socket.SHUT_RDWR)
																	sockfd.close()
															
															
															
															
															

														
													else:
														sockfd.shutdown(socket.SHUT_RDWR)
														
														sockfd.close()
														sys.exit()

												
											
												

										else:
											sockfd.shutdown(socket.SHUT_RDWR)
											
											sockfd.close()

											
									else:
										sockfd.shutdown(socket.SHUT_RDWR)
										
										sockfd.close()
										
				
								else:
									
									sockfd.send("wrong_password")
									
									sockfd.close()
							else:
								sockfd.shutdown(socket.SHUT_RDWR)
								sockfd.close()
								
						else:
							sockfd.shutdown(socket.SHUT_RDWR)
							sockfd.close()
							
					else:
						sockfd.shutdown(socket.SHUT_RDWR)
						sockfd.close()
						
				else:
					sockfd.shutdown(socket.SHUT_RDWR)
					sockfd.close()
					
			else:
				sockfd.shutdown(socket.SHUT_RDWR)
				sockfd.close()
				

		else:
			sockfd.shutdown(socket.SHUT_RDWR)
			sockfd.close()
			
	except:
		f1 = open("error_log_server.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()							
			
             
            






if __name__ == "__main__":
	
	try:
		server_socket = socket.socket()         # Create a socket object
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		 # Get local machine name
		host = sys.argv[1]
		port = int(sys.argv[2])        # Reserve a port for your service.
		server_address = (host, port)
		server_socket.bind((host, port))        # Bind to the port
		

		server_socket.listen(20)               # Now wait for client connection.
		
		while True:
			sockfd, addr = server_socket.accept()     # Establish connection with client.
			t = threading.Thread( target=client_thread, args=(sockfd, addr, ))
			t.start()
	   #server_socket.close()
	  
	except:
		f1 = open("error_log_server.txt", "a+")
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback, limit=None, file = f1)
		f1.close()	

