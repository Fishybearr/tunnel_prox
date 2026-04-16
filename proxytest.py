import socket
import threading
import sys

#key derivation libraries from pycryptodome
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct


#TODO: 
    # - need to ecrypt the CONNECT request that is initially sent so that no one 
    #   can see where you are going
    
    # - should also implement diffie-hellman (Should be able to do this with ECC)
    #   Can use the client as a CA to validate of anyone is trying to Man in the Middle us

    # - should also use some kind of morphing/randomization to obfuscate packet structure

#curl command for testing: curl -v -x http://127.0.0.1:8888 https://www.weatherbuddy.org:443

#So the idea is that this is a local proxy that intercepts data from my machine, and then sends data to the remote server proxy

#the client proxy is considered trusted because the HTTPS data is never decrypted.
# So all the client is doing is obscuring the destination and already encrypted data of the request
# then the server sends that forwarded request to the actual website it wants to go to.
# then the server gets the data back and sends it ecrypted back to the client who then returns that data back to the browser
#

#We use 3 socket connections
    #1) browser (or curl) to local proxy
    #2) local proxy to remote 'proxy' server
    #3) remote 'proxy' server to website

#TODO: Test this between both linux laptops
#      with the Windows laptop as a router
# Also may need to deal with firewall rules on both
# systems so don't forget that


def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return b'' # Connection closed
        data += packet
    return data


def forward_traffic(source, dest, mode,key):
    iv = None
    data = None
    header = None

    try:
        if mode == "enc":
            while True:
                data = source.recv(4096)
                if not data: break

                #generate an iv for AES
                iv = get_random_bytes(16) #this works with AES128
                ctr = Counter.new(128,initial_value=int.from_bytes(iv,byteorder='big'))
                cipher = AES.new(key,AES.MODE_CTR,counter=ctr)
                ciphertext = cipher.encrypt(data)

                #now pack data into serialized form [data size (int 4 bytes) | iv (byte array 16 bytes) | data (byte array data size)]
                data_size = len(ciphertext)
                packet_header = struct.pack('!I',data_size)
                
                dest.sendall(packet_header + iv + ciphertext)

        elif mode == "dec":
            while True:
                #data = source.recv(4096)
                #if not data: break

                # need to read header from stream first
                #read first 4 bytes of from stream
                header = recv_all(source, 4)

                #try to unpack our data
                try:
                    data_len = struct.unpack('!I',header)[0]
                except: break
                
                # try to get 16 bytes for our iv
                iv = recv_all(source, 16)
                if not iv or len(iv) < 16: break

                #try to read our data
                data = recv_all(source, data_len)
                if not data or len(data) < data_len: break

                #create ctr object
                ctr = Counter.new(128,initial_value=int.from_bytes(iv,byteorder='big'))
                cipher = AES.new(key,AES.MODE_CTR, counter=ctr)
                plaintext = cipher.decrypt(data)

                dest.sendall(plaintext)
    except Exception as e:
        print(f"Remote setup error: {e}")
        source.close()
    finally:
        #try to close socket if it's not already closed
        try:
            source.shutdown(socket.SHUT_RDWR)
            source.close()
        except:
            pass
        try:
            dest.shutdown(socket.SHUT_RDWR)
            dest.close()
        except:
            pass


def start_remote_proxy(passKey):


    #generate a salted key from our password
    #salt = get_random_bytes(16)
    shared_salt = b'\x12\x34\x56\x78\x90\xab\xcd\xef\x11\x22\x33\x44\x55\x66\x77\x88'
    key = PBKDF2(passKey,shared_salt,dkLen=32,count=1000000)
    

    remote_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #FIXME TEMPORARILY BINDING TO LOCALHOST ON ANOTHER PORT FOR TESTING 
    # SHOULD BE ABLE TO USE 0.0.0.0:9999 for local testing as it'll accept
    # any incoming traffic as long as port is correct
    remote_server.bind(('127.0.0.1',9999)) #on the remote server this is set to 0.0.0.0:9999
    remote_server.listen(5)
    print("listening on remote server")

    while True:
        client_sock, addr = remote_server.accept()

        request = client_sock.recv(4096).decode('utf-8')
        request_first_line = request.split('\n')[0]
        if "CONNECT" not in request_first_line:
            print("Not a connect request! REJECT")
        else:
            site_addr,site_port = (request_first_line.split(' ')[1]).split(':')
            print(site_addr,site_port)

            #Connection to the website from our server
            remote_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_connection.connect((site_addr,int(site_port)))

            
            #This needs to be encrypted like a normal message before sending
            # since the client expects the other form
            #tell client, which tells the browser we're ready to stream data now
            client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")


            #We now send data between client and server
            t1 = threading.Thread(target=forward_traffic, args=(client_sock,remote_connection,"dec",key))
            t2 = threading.Thread(target=forward_traffic, args=(remote_connection,client_sock,"enc",key))

            t1.start()
            t2.start()
            # start data transfer between client and server


def start_client_proxy(passKey):

    #generate a salted key from our password
    #salt = get_random_bytes(16)
    shared_salt = b'\x12\x34\x56\x78\x90\xab\xcd\xef\x11\x22\x33\x44\x55\x66\x77\x88'
    key = PBKDF2(passKey,shared_salt,dkLen=32,count=1000000)
    



    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server.bind(('127.0.0.1',8888))
    local_server.listen(5)
    print("listening on localhost:8888")

    while True:
        client_sock, addr = local_server.accept()
        #this could cause a crash down the line if we
        # don't read just the raw bytes before the
        # decode
        request = client_sock.recv(4096).decode('utf-8')
        request_first_line = request.split('\n')[0]
        if "CONNECT" not in request_first_line:
            print("Not a connect request! REJECT")
        else:
            site_addr,site_port = (request_first_line.split(' ')[1]).split(':')
            print(site_addr,site_port)

            #would connect to our server here with a socket
            #FIXME TEMP CONNECT DIRECTLY TO REMOTE PROXY HARDCODED
            remote_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #remote_connection.connect(('127.0.0.1',9999))
            #connecting to other laptop for now
            remote_connection.connect(('192.168.137.25',9999)) #set this back to 127.0.0.1 for local testing

            #send the initial request from the browser to the remote server
            remote_connection.sendall(request.encode('utf-8'))

            
            #Wait for the remote server to send this instead
            #client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            #accounts for partial data received
            

            #start the data transfer between browser and local proxy
                #encrypt local traffic here before sending
            

            #this actually forwards traffic between client
            # and the website we want
            #need to do this on threads so the data transfer actual
            # completes


            #read the OK response before starting the threads
            #response = remote_connection.recv(4096)
            #if b"200 Connection Established" in response:
                # Pass the 200 OK back to the browser so IT knows we are ready
             #   client_sock.sendall(response)
            #else:
             #   print("Remote server failed to establish connection")
              #  return

            #getting OK message back before anything else
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = remote_connection.recv(1) # Read 1 byte at a time to be safe
                if not chunk: break
                response += chunk

            if b"200" in response:
                client_sock.sendall(response)
            else:
                print("Handshake failed")
                return
            
            #each of these threads would either have an encrypt or decrypt mode set in their args
            # this would make sure traffic flowing is always in the right state for whoever gets it
            # Also need to make sure to get encrypted traffic sizes working so we don't read the
            # wrong amount of data
            t1 = threading.Thread(target=forward_traffic, args=(client_sock,remote_connection,"enc",key))
            t2 = threading.Thread(target=forward_traffic, args=(remote_connection,client_sock,"dec",key))

            t1.start()
            t2.start()
            # start data transfer between client and server


#need some more logic to prevent incorrect usage
if sys.argv[2] == '-p':
    passkey = sys.argv[3]

    if sys.argv[1] == 'client':
        start_client_proxy(passkey)

    else:
        start_remote_proxy(passkey)


else:
    print("-p password required")
    

#TODO: should implement a helper function for reading and writing encrypted traffic
# so we don't crash or get out of sync if we read a wrong amount of data somehow
