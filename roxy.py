import socket
import threading
import sys

#encryption libraries from pycryptodome
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import ECC

import struct

#TODO: import Diffie Hellman from Crypto
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA256

#curl command for testing: curl -v -x http://127.0.0.1:8888 https://www.weatherbuddy.org:443


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


#transmits the original CONNECT request between client and remote proxy server
def transmit_handshake_client(client_server, remote_server, key):

    try:
        

  
        #encrypt our initial packet
        #then transmit it

        request = client_server.recv(4096).decode('utf-8')
        if "CONNECT" not in request:
            return False

        else:
            #encode our request into utf-8
            request = request.encode('utf-8')

            #encrypt request
            iv = get_random_bytes(16) #this works with AES128
            ctr = Counter.new(128,initial_value=int.from_bytes(iv,byteorder='big'))
            cipher = AES.new(key,AES.MODE_CTR,counter=ctr)
            ciphertext = cipher.encrypt(request)

            #now pack data into serialized form [data size (int 4 bytes) | iv (byte array 16 bytes) | data (byte array data size)]
            data_size = len(ciphertext)
            packet_header = struct.pack('!I',data_size)
        
            #send this request to the server
            remote_server.sendall(packet_header + iv + ciphertext)

           
        #decrypt packet and assert that the response is a Connection OK message

        #read header from server
        resp_header = recv_all(remote_server, 4)
        if len(resp_header) < 4: return False

        #unpack header
        resp_data_len = struct.unpack('!I',resp_header)[0]

        # try to get 16 bytes for our iv
        resp_iv = recv_all(remote_server, 16)

        #try to read our data
        resp_data = recv_all(remote_server, resp_data_len)

        #create ctr object
        resp_ctr = Counter.new(128,initial_value=int.from_bytes(resp_iv,byteorder='big'))
        resp_cipher = AES.new(key,AES.MODE_CTR, counter=resp_ctr)
        resp_plaintext = resp_cipher.decrypt(resp_data)

        if b"200" in resp_plaintext:
            client_server.sendall(resp_plaintext)
            return True
        
        print("Handshake failed")
        return False


    except Exception as e:
        print(f"Remote setup error: {e}")
        return False



#transmits the initial connect request response back to the client
def transmit_handshake_server(remote_server, client_sock, key):
    try:
        header = recv_all(client_sock,4)
        if len(header) < 4: return None

        data_len = struct.unpack('!I',header)[0]

        iv = recv_all(client_sock, 16)

        data = recv_all(client_sock, data_len)

        resp_ctr = Counter.new(128,initial_value=int.from_bytes(iv,byteorder='big'))
        resp_cipher = AES.new(key,AES.MODE_CTR, counter=resp_ctr)
        plaintext = resp_cipher.decrypt(data)

        #now get the addr and port from this plaintext
        request = plaintext.decode('utf-8')
        request_first_line = request.split('\n')[0].strip()
        if "CONNECT" not in request_first_line:
            print("Not a connect request! REJECT")
            return None
        else:
            site_addr,site_port = (request_first_line.split(' ')[1]).split(':')
            print(site_addr,site_port)
            
            # would add the request info to the return here
            # if it's valid

        
        #now encrypt message and send it back to the client server
        raw_message = b"HTTP/1.1 200 Connection Established\r\n\r\n"
        
        iv = get_random_bytes(16) #this works with AES128
        ctr = Counter.new(128,initial_value=int.from_bytes(iv,byteorder='big'))
        cipher = AES.new(key,AES.MODE_CTR,counter=ctr)
        ciphertext = cipher.encrypt(raw_message)

        #now pack data into serialized form [data size (int 4 bytes) | iv (byte array 16 bytes) | data (byte array data size)]
        data_size = len(ciphertext)
        packet_header = struct.pack('!I',data_size)

        client_sock.sendall(packet_header + iv + ciphertext)
        return (site_addr,site_port) #would also return addr and port here


    

    except Exception as e:
        print(f"Remote setup error: {e}")
        return None

def ECC_Handshake(dest_sock,source_pub_key, is_client=True):
    try:
      
        #This ensures that both don't send their data
        # at the exact same time
        if is_client:
            dest_sock.sendall(source_pub_key)
            dest_pub_key = recv_all(dest_sock,len(source_pub_key))

        else:
            dest_pub_key = recv_all(dest_sock,len(source_pub_key))
            dest_sock.sendall(source_pub_key)
        

        if not dest_pub_key:
            return None

        #return the actual rebuilt key
        return ECC.import_key(dest_pub_key)


    except Exception as e:
        print(f"Remote setup error: {e}")
        return None




def start_remote_proxy(passKey="testPass", remote_host_broadcast_addr='127.0.0.1',enc_mode="PBKD"):

    #TODO: figure out if this needs to be modified at all
    #generate a salted key from our password
    shared_salt = b'\x12\x34\x56\x78\x90\xab\xcd\xef\x11\x22\x33\x44\x55\x66\x77\x88'
    key = PBKDF2(passKey,shared_salt,dkLen=32,count=1000000)

    #TODO: Check here what enc mode the user picked and decide if we use ECC or PBKD

    remote_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    remote_server.bind((remote_host_broadcast_addr,9999)) #on the remote server this is set to 0.0.0.0:9999
    remote_server.listen(5)
    print("listening on remote server")

    while True:
        client_sock, addr = remote_server.accept()

        if enc_mode == "ECC":
            #generate our new for the server
            # then send the public to the client and read the clients public
            server_key = ECC.generate(curve='p256')
            server_pub_key_bytes = server_key.public_key().export_key(format='DER')

            client_ECC = ECC_Handshake(client_sock,server_pub_key_bytes, is_client=False)

            if client_ECC is None:
                client_sock.close()
                continue
            
            key = key_agreement(static_priv=server_key, static_pub=client_ECC,kdf=lambda x: SHA256.new(x).digest())
            
    
        

        #Check if we got a a port and addr back from CONNECT request
        request_reseult = transmit_handshake_server(remote_server, client_sock, key)
        if request_reseult is None:
            client_sock.close()
            continue

        #if we got an addr and port back we can read them here
        site_addr,site_port = request_reseult


        #Connection to the website from our server
        remote_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_connection.connect((site_addr,int(site_port)))


        #We now send data between client and server
        t1 = threading.Thread(target=forward_traffic, args=(client_sock,remote_connection,"dec",key))
        t2 = threading.Thread(target=forward_traffic, args=(remote_connection,client_sock,"enc",key))

        t1.start()
        t2.start()


def start_client_proxy(passKey="testPass",local_host_addr='127.0.0.1:8888',remote_host_connection="127.0.0.1",enc_mode="PBKD"):

    shared_salt = b'\x12\x34\x56\x78\x90\xab\xcd\xef\x11\x22\x33\x44\x55\x66\x77\x88'
    key = PBKDF2(passKey,shared_salt,dkLen=32,count=1000000)
    
    
    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_server.bind(('127.0.0.1',8888))
    local_server.listen(5)
    print("listening on localhost:8888")

    while True:
        client_sock, addr = local_server.accept()
        remote_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


        try:
            remote_connection.connect((remote_host_connection,9999))

            if enc_mode == "ECC":
                client_key = ECC.generate(curve='p256')
                client_pub_key_bytes = client_key.public_key().export_key(format='DER')

                server_ECC = ECC_Handshake(remote_connection,client_pub_key_bytes, is_client=True)

                if server_ECC is None:
                    remote_connection.close()
                    continue
            
                key = key_agreement(static_priv=client_key, static_pub=server_ECC,kdf=lambda x: SHA256.new(x).digest())



            if transmit_handshake_client(client_sock, remote_connection, key):
        
        
                t1 = threading.Thread(target=forward_traffic, args=(client_sock,remote_connection,"enc",key))
                t2 = threading.Thread(target=forward_traffic, args=(remote_connection,client_sock,"dec",key))

                t1.start()
                t2.start()
            else:
                print("Handshake failed, closing connection")
                client_sock.close()
                remote_connection.close()
        except Exception as e:
            print(f"Connection Error: {e}")
            client_sock.close()


def process_com_args():
    try:
        if sys.argv[1] == "client":
            if sys.argv[2] == "ECC":
                if sys.argv[3] == "local":
                    start_client_proxy(enc_mode="ECC")

                elif sys.argv[3] == "remote":
                     start_client_proxy(enc_mode="ECC",remote_host_broadcast_addr = "0.0.0.0")

            elif sys.argv[2] == "PBKD":
                if sys.argv[3] == "local":
                    start_client_proxy(enc_mode="PBKD",passKey = sys.argv[4])

                elif sys.argv[3] == "remote":
                     start_client_proxy(enc_mode="PBDK",passKey = sys.argv[4],remote_host_broadcast_addr = "0.0.0.0")
        
        elif sys.argv[1] == "server":
            if sys.argv[2] == "ECC":
                if sys.argv[3] == "local":
                    start_remote_proxy(enc_mode="ECC")

                elif sys.argv[3] == "remote":
                     start_remote_proxy(enc_mode="ECC",remote_host_broadcast_addr = "0.0.0.0")

            elif sys.argv[2] == "PBKD":
                if sys.argv[3] == "local":
                    start_remote_proxy(enc_mode="PBKD",passKey = sys.argv[4])

                elif sys.argv[3] == "remote":
                     start_remote_proxy(enc_mode="PBDK",passKey = sys.argv[4],remote_host_broadcast_addr = "0.0.0.0")

                     
    except Exception as e:
        print(f"invalid arguments {e}")



process_com_args()