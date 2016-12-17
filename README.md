# Secure-Instant-Messaging-Application
Python

Try following commands if you face dependance errors:

$ sudo apt-get install build-essential libssl-dev libffi-dev python-dev
 
$ sudo pip install cryptography
 
$ sudo pip install pycrypto




For Testing, please use the following credentials:
1.	Username: tapan
Password: tapan311291

2.	Username: paras
Password: paras12345

3.	Username: tushar
Password: tushar12345

If the above credentials don’t work or if you want to add additional users, please execute the “create_users.py” as:
“python create_users.py [username] [password]”

Note: if login fails for any user, please delete the “client_list_server.txt” file and execute the above said command to create new users. 
Then try to login to the server.


To execute Server:
"python ChatServer1.py [IP] [PORT]"

To execute Client
"Python ChatClient.py [IP] [PORT]"

WORKING

Step 1: python ChatClient1.py IP Port No.
Step 2: python ChatServer1.py IP Port No.
Step3: Enter: Username
Step4: Enter: Password
Step5: Enter: list
Step5: select user who is online
Step6: Enter: connect
Step7: Enter: username_selected_in_step5
Step8: Enter: send
Step9: Enter: username_selected_in_step5
Step10: Enter: Message
