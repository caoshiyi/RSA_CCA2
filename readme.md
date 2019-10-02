# CCA2 Implementation for Textbook RSA
## Files
1. RSA.py - A simple implementation of RSA encryption.

2. OAEP.py - Adding OAEP padding module to the RSA encryption.

3. ServerClient.py - The server-client-cracker communication simulation model. 

## Environment
Windows10, py3.5

## Running
To start, run ```python ServerClient.py server [port] rsa``` in one terminal to setup the server.

For RSA algorithm testing, run ```python ServerClient.py client [port] rsa``` in another terminal to setup the client.  After varifying the wup request, the client and server can communicate with the shared session key.
   
For CCA2 attack, run ```python ServerClient.py cracker [port] rsa``` in another terminal (make sure no other crackers or clients that are   running) to setup the cracker. The cracker will try to crack a pre-generated AES session key with CCA2 method. If the session key is successfully cracked, the cracker and the server can then communicate with the shared session key

## TBD 
Add OAEP in the choices of algorithms.
