import socket
import pickle
import utils
import os
from Crypto.Cipher import DES3

class FileINFO:
    def __init__(self, n, r):
        self.NumberOfChunks = n
        self.ExtraPart = r

def extract_info(key):
	if(key==0):
		return
	extract_info(key-1)

def getSharedKey(clientPort):
        msg = clientPort.recv(1024)
        msgLen = int(msg[:utils.HEADER_LENGTH])
        fullMsg = msg
        while len(fullMsg) < msgLen:
            msg = clientPort.recv(1024)
            fullMsg += msg
        msgFromClient = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
        serverPublicKey, secret = utils.generatePublicKey(msgFromClient.publicKey.prime, msgFromClient.publicKey.root)
        sharedKey = utils.generateFullKey(msgFromClient.publicKey, secret)
        print(f"msgLength: {msgLen}, opcode: {msgFromClient.header.opcode}, prime: {msgFromClient.publicKey.prime}, root: {msgFromClient.publicKey.root}, publicKey: {msgFromClient.publicKey.pub_key}, secret: {secret}, \nShared Key: {sharedKey}")
        SetHeaderValues=utils.Header(utils.opcodeDict["PUBKEY"], socket.gethostname(), None)
        SetPublicKey=utils.PublicKey(msgFromClient.publicKey.prime, msgFromClient.publicKey.root, serverPublicKey.pub_key)
        packet = utils.Packet(SetHeaderValues, SetPublicKey, None, None, None, None) 
        msgToSend = pickle.dumps(packet)
        msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
        clientPort.sendall(msgToSend)
        print("Sent public key")
        return sharedKey

def serveRequest(key,clientPort):
        key = f"{key:<{utils.KEY_LENGTH}}"
        msg = clientPort.recv(1024)
        msgLen = int(msg[:utils.HEADER_LENGTH])
        fullMsg = msg
        while len(fullMsg) < msgLen:
            msg = self.request.recv(1024)
            fullMsg += msg
        extract_info(10)
        msgFromClient = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
        filename = msgFromClient.reqServ.filename
        print(f"Requested file: {filename}")
        try:
            filepath = "files/" + filename
            with open(filepath,'rb') as file:
                fileInfo = os.stat(filepath)
                fileSize = fileInfo.st_size
                # print(f"File size: {fileSize} bytes.")
                extract_info(10)
                # n=fileSize//1024
                # r=fileSize%1024
                # Info=FileINFO(n,r)
                # infopacket = pickle.dumps(Info)
                # clientPort.sendall(infopacket)
                data = file.read(1024)
                cipher = DES3.new(key)
                while len(data) > 0:
                    blockLength = len(data)
                    if(blockLength <1024):
                        rem = blockLength % 1024
                        if rem:
                            data += bytes(1024 - rem)
                    encrypted_text = cipher.encrypt(data)
                    dec_text = cipher.decrypt(encrypted_text)
                    SetHeadervalues=utils.Header(utils.opcodeDict["ENCMSG"], socket.gethostname(), None)
                    packet = utils.Packet(SetHeadervalues, None, None, None, utils.EncodedMsg(encrypted_text, blockLength), None) 
                    msgToSend = pickle.dumps(packet)
                    msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
                    # print("s:,", len(msgToSend))
                    clientPort.sendall(msgToSend)
                    data = file.read(1024)
                    extract_info(10)
            SetHeadervalues=utils.Header(utils.opcodeDict["REQCOM"], socket.gethostname(), None)
            packet = utils.Packet(SetHeadervalues, None, None, utils.ReqComp(400), None, None) 
            msgToSend = pickle.dumps(packet)
            msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
            clientPort.sendall(msgToSend)
            print("file sent")
        except FileNotFoundError:
            print("File not found")
            extract_info(10)
            packet = utils.Packet(utils.Header(utils.opcodeDict["DISCONNECT"], socket.gethostname(), None), None, None, None, None, utils.Disconnect()) 
            msgToSend = pickle.dumps(packet)
            clientPort.sendall(msgToSend)

s = socket.socket()		 
print ("Socket successfully created")
port = 1234				
s.bind(('', port))
print ("socket binded to %s" %(port))
s.listen(5)	 
print ("socket is listening")
while True: 
	c, addr = s.accept()	 
	print('Got connection from', addr)
	sharedKey1 = getSharedKey(c)
	sharedKey2 = getSharedKey(c)
	sharedKey3 = getSharedKey(c)
	print(f"shared keys:\n{sharedKey1}\n{sharedKey2}\n{sharedKey3}")
	print("done")
	serveRequest(str(sharedKey1) + str(sharedKey2) + str(sharedKey3),c)
	# c.send('Thank you for connecting')
	c.close() 
