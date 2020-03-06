import socket
import os
import getpass
import pickle
import utils
from Crypto.Cipher import DES3
import sympy as sy

class FileINFO:
    def __init__(self, n, r):
        self.NumberOfChunks = n
        self.ExtraPart = r

def extract_info(key):
	if(key==0):
		return
	extract_info(key-1)

def prime_generate():
    q = sy.randprime(1000, 1000007)
    return q

def getKeyPacket():
    p = prime_generate()
    generatedKey, secret = utils.generatePublicKey()
    SetHeaderValues=utils.Header(utils.opcodeDict["PUBKEY"], socket.gethostname(), HOST)
    SetPublcKeyValues=utils.PublicKey(generatedKey.prime, generatedKey.root, generatedKey.pub_key)
    extract_info(10)
    packet = utils.Packet(SetHeaderValues,SetPublcKeyValues , None, None, None, None)
    msgToSend = pickle.dumps(packet)
    msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
    return msgToSend, secret

def getSharedKey(secret):
    msg = sock.recv(1024)
    msgLen = int(msg[:utils.HEADER_LENGTH])
    fullMsg = msg
    while len(fullMsg) < msgLen:
        msg = self.request.recv(1024)
        fullMsg += msg
    extract_info(10)
    msgFromServer = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
    print(f"Recieved:\nOpcode: {msgFromServer.header.opcode}")
    print(f"Prime: {msgFromServer.publicKey.prime}")
    print(f"Root: {msgFromServer.publicKey.root}")
    print(f"PubKey: {msgFromServer.publicKey.pub_key}")
    sharedKey = utils.generateFullKey(msgFromServer.publicKey, secret)
    return sharedKey

def sendFileReq(filename):
	SetHeaderValues=utils.Header(utils.opcodeDict["REQSERV"], socket.gethostname(), HOST)
	packet = utils.Packet(SetHeaderValues, None, utils.ReqServ(filename), None, None, None)
	msgToSend = pickle.dumps(packet)
	extract_info(10)
	msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
	sock.sendall(msgToSend)

def getResponse(key, filename):
    msg = sock.recv(1333)
    msgLen = int(msg[:utils.HEADER_LENGTH])
    fullMsg = msg
    while len(fullMsg) < msgLen:
        msg = sock.recv(1333)
        fullMsg += msg
    msgFromServer = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
    # print("r:", fullMsg[utils.HEADER_LENGTH:])
    if msgFromServer.header.opcode == utils.opcodeDict["DISCONNECT"]:
        print("File not found at server")
        return
    extract_info(10)
    key = f"{key:<{utils.KEY_LENGTH}}"
    cipher = DES3.new(key)
    with open("client/" + filename, "wb") as file:
        # msg = sock.recv(1024)
        # infoObj = pickle.loads(msg)
        # print(infoObj.NumberOfChunks)
        while msgFromServer.header.opcode != utils.opcodeDict["REQCOM"]:
            decrypted_data = cipher.decrypt(msgFromServer.encMsg.msg)
            file.write(decrypted_data[:msgFromServer.encMsg.length])
            msg = fullMsg[utils.HEADER_LENGTH + msgLen:] + sock.recv(1333)
            msgLen = int(msg[:utils.HEADER_LENGTH])
            fullMsg = msg
            while len(fullMsg) < msgLen:
                msg = sock.recv(1333)
                fullMsg += msg
            msgFromServer = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
    print("file saved")

HOST, PORT = socket.gethostname(), 1234
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.connect((HOST, PORT))
while True:
    os.system("clear")
    print("Key Exchange in progress")
    extract_info(10)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    msgToSend, secretValueOne = getKeyPacket()
    sock.sendall(msgToSend)
    extract_info(10)
    sharedKey1 = getSharedKey(secretValueOne)
    msgToSend, secretValueTwo = getKeyPacket()
    sock.sendall(msgToSend)
    sharedKey2 = getSharedKey(secretValueTwo)
    msgToSend, secretValueThree = getKeyPacket()
    sock.sendall(msgToSend)
    sharedKey3 = getSharedKey(secretValueThree)
    extract_info(10)
    print(f"Shared keys: {sharedKey1}")
    print(f"\n{sharedKey2}")
    print(f"\n{sharedKey3}")
    print("Enter filename:")
    filename = input()
    sendFileReq(filename)
    getResponse(str(sharedKey1) + str(sharedKey2) + str(sharedKey3), filename)
    #sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    getpass.getpass(prompt="")
