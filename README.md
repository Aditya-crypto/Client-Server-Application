## Client-Server Application
 Encrypted Files are Downloaded from server and Decrypted accodingly.
 for communication between client and server Socket programming is used and,
 Deffie-Hellman Key Exchange is used for key generation which in turn used in 3DES algorithm for secure communication.

## Language Used:
Python3
## OS:
Linux

## Features:
1. All types of files can be downloaded from server.
2. Files are transferred Chunk-wise
2. Encrypted Files are transferred and decrypted accordingly on the clientside.
3. Socket Programming for communication between server and client is used.
4  3DES Encrytion is used for secure Transmission

## How To Run Program:

1. create a folder named files that contains all the files need to be shared to client.
2. create a folder named client which contains all files which are Downloaded from server.
3  Run pip3 install sympy
4. Run pip3 install Crypto
4. Program is written in python Script, make sure you run this script in python3.
5. To run program,
   - open terminal and write python3 myserver.py
   - open in onother terminal and write python3 client.py
      - enter filename that you need to Download from Server.
