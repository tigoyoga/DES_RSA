# client.py
import json
import socket
import random
import time
import des
from rsa import RSA
import traceback
from logger import setup_logger


class ChatClient:
    def __init__(self, client_id, host="localhost", port=5000, pka_host="localhost", pka_port=6000):
        self.host = host
        self.logger = setup_logger(f"{client_id}")    
        self.port = port
        self.pka_host = pka_host
        self.pka_port = pka_port
        self.client_id = client_id
        self.rsa = RSA()
        self.public_key = '26858627481455264727858704072963116162849816880908732465731330254347364959544380193164933578851384040736507241619240780621767106121559768200762625636323091476054671187018048595532994447999597581042653023433502827305440202229962408785487010855070606563770434482792518501741282588643183500523897546817076278989:65537'
        self.private_key = '26858627481455264727858704072963116162849816880908732465731330254347364959544380193164933578851384040736507241619240780621767106121559768200762625636323091476054671187018048595532994447999597581042653023433502827305440202229962408785487010855070606563770434482792518501741282588643183500523897546817076278989:11607031867949036538480769897225405129380846143416651981238731334416071385388649706743019192520696687393981386043611050075067335697008037520515114870560786964160381757240035025284540296468867660258095170048956573756590933204676877770547913732814019180812390644014681585105892782619316436215020160899117864833'
        self.auth_public_key = '6161317031919495016749804258153971457780741115257801805278754622435339417881069548961565696474842999157534163002139523775502237244750110892994874339059804277076970008600002638922509853943230417198200736775561193127505226294240453897883745935955067580497948801361046898423328694100129153386023796404727556977:65537'
        
        self.logger.info(f"Client {client_id} started")
        self.des_key = None

    def authenticate_server(self, client_socket):
        try:
            # Step 1: Receive initial encrypted message from server
            init_data = json.loads(client_socket.recv(4096).decode())
            decrypted_init = json.loads(
                self.rsa.decrypt(init_data["data"], self.rsa.import_key(self.private_key))
            )
            self.logger.debug(f"Received ENCRYPTED N1 data: {init_data}")
            self.logger.debug(f"Received DECRYPTED N1 data: {decrypted_init}")

            server_id = decrypted_init["id"]
            n1 = decrypted_init["n1"]

            # Step 2: Get server's public key from PKA
            req = {"type": "get_key", "requested_id": "server"}
            pka_request = {"req": req, "timestamp": time.time()}
            
            server_public_key = self.get_public_key_from_pka(pka_request)

            self.logger.debug(f"Received server public key: {server_public_key}")
           
            if not server_public_key:
                return False

            # Step 3: Generate N2 and send response
            n2 = random.randint(1, 1000000)
            response_data = {"n1": n1, "n2": n2}

            if isinstance(server_public_key, str):
                server_public_key = self.rsa.import_key(server_public_key)

            encrypted_response = self.rsa.encrypt(
                json.dumps(response_data), self.rsa.import_key(server_public_key)
            )

            client_socket.send(
                json.dumps({"data": str(encrypted_response)}).encode()
            )

            self.logger.debug(f"Sent N2 response: {response_data}")

            # Step 4: Verify N2
            try:
                self.logger.debug("Waiting for N2 verification...")
                received_data = client_socket.recv(4096).decode()

                if not received_data:
                    self.logger.error("No data received for N2 verification")
                    return False
                    
                n2_response = json.loads(received_data)
                self.logger.debug(f"Received N2 response: {n2_response}")
                
                if not n2_response or "data" not in n2_response:
                    self.logger.error("Invalid N2 response")
                    return False
                    
                decrypted_n2 = self.rsa.decrypt(
                    n2_response["data"], 
                    self.rsa.import_key(self.private_key)
                )
                self.logger.debug(f"Decrypted N2: {decrypted_n2}")
                
                received_n2 = int(decrypted_n2)
                
                if received_n2 != n2:
                    self.logger.error("N2 verification failed")
                    return False
                
                self.logger.info("N2 verification successful")

            except json.JSONDecodeError as e:
                self.logger.error(f"JSON decode error: {e}")
                return False
            except Exception as e:
                self.logger.error(f"Error in N2 verification: {e}")
                return False


            # Step 5: Send DES key
            self.des_key = des.generate_random_des_key()
            encrypted_des_key = self.rsa.encrypt(
                str(self.des_key), self.rsa.import_key(server_public_key)
            )
            client_socket.send(
                json.dumps({"data": str(encrypted_des_key)}).encode()
            )

            self.logger.info("DES key sent successfully")

            return True

        except Exception as e:
            self.logger.error(f"Error in authenticate_server: {e}")
            return False

    def get_public_key_from_pka(self, request_data):
        pka_socket = socket.socket()
        try:
            pka_socket.connect((self.pka_host, self.pka_port))
            
            # Send request to PKA
            pka_socket.send(json.dumps(request_data).encode())
            response = json.loads(pka_socket.recv(4096).decode())

            if response["status"] == "success":
                # Decrypt response using auth public key
                decrypted_data = self.rsa.decrypt(
                    response["data"],
                    self.rsa.import_key(self.auth_public_key)
                )
                
                key_data = json.loads(decrypted_data)
                
                # Verify request and timestamp
                if (key_data["req"] == request_data["req"] and 
                    key_data["timestamp"] == request_data["timestamp"]):
                    return key_data["public_key"]
                else:
                    self.logger.error("Invalid response from PKA")
                    return None
            else:
                self.logger.error("Failed to get public key from PKA")
                return None

        except Exception as e:
            self.logger.error(f"Error in get_public_key_from_pka: {e}")
            return None
        finally:
            pka_socket.close()

    def handle_chat(self, client_socket):
        try:
            print("\nStarting chat session...")
            print("Type 'quit' to exit")
            
            while True:
                try:
                    # Get message from user
                    message = input("You: ")
                    if message.lower() == "quit":
                        print("Closing connection...")
                        break

                    # Encrypt and send message
                    encrypted_msg = des.des_encrypt(message, self.des_key)
                    client_socket.send(encrypted_msg.encode())

                    # Receive and decrypt response
                    data = client_socket.recv(1024).decode()
                    if not data:
                        print("Server disconnected")
                        break
                        
                    decrypted_msg = des.des_decrypt(data, self.des_key)
                    print(f"Server: {decrypted_msg}")

                except ConnectionResetError:
                    print("Server disconnected unexpectedly")
                    break
                except Exception as e:
                    print(f"Error during chat: {e}")
                    break

        except Exception as e:
            print(f"Error in chat handling: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            print("Chat session ended")


    def start(self):
            try:
                client_socket = socket.socket()
                client_socket.connect((self.host, self.port))
                # Set timeout untuk socket
                client_socket.settimeout(30)  # 30 seconds timeout
                print("Connected to server")

                if self.authenticate_server(client_socket):
                    print("Authentication successful")
                    self.handle_chat(client_socket)
                else:
                    print("Authentication failed")
                    
            except socket.timeout:
                print("Connection timed out")
            except ConnectionRefusedError:
                print(f"Could not connect to server at {self.host}:{self.port}")
            except Exception as e:
                print(f"Error: {e}")
                print(f"Stack trace: {traceback.format_exc()}")
            finally:
                print("Closing connection...")
                client_socket.close()


if __name__ == "__main__":
    import sys
    client_id = sys.argv[1] if len(sys.argv) > 1 else "client1"
    client = ChatClient(client_id)
    client.start()