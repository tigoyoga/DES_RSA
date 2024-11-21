import socket
import json
import time
import random
import des
from rsa import RSA
from rsa import ImprovedRSA
from logger import setup_logger


class ChatServer:

    def __init__(self, host="localhost", port=5000, pka_host="localhost", pka_port=6000):
        self.logger = setup_logger("server")
        self.host = host
        self.port = port
        self.pka_host = pka_host
        self.pka_port = pka_port
        self.server_id = "server1"
        self.rsa = RSA()
        self.improved_rsa = ImprovedRSA()
        self.public_key = "51863431050711052966272446829276768371276448210025419682214432876672068925826744257233541925030795541707029056444584082234321902855422624744834879595778287369055521334581321377332227806045229697190315487434544332679135272739001159333166106058837293584567775125456316293061226640871778272831798721100556958253:65537"
        self.private_key = "51863431050711052966272446829276768371276448210025419682214432876672068925826744257233541925030795541707029056444584082234321902855422624744834879595778287369055521334581321377332227806045229697190315487434544332679135272739001159333166106058837293584567775125456316293061226640871778272831798721100556958253:48864963921438364565991593249831116672865375651504487763208215226036390314356009649444691499256932162127128647593575810760408759288899953198102814368679016290936984510465520925570054663926978579641117706295471705285861666118001830412509405252270750177109817018958822196750491367668600840562977112964567631665"
        self.auth_public_key = "6161317031919495016749804258153971457780741115257801805278754622435339417881069548961565696474842999157534163002139523775502237244750110892994874339059804277076970008600002638922509853943230417198200736775561193127505226294240453897883745935955067580497948801361046898423328694100129153386023796404727556977:65537"

        print("Server initialized with hardcoded keys")
        self.des_key = None

    def authenticate_client(self, client_socket):
        try:
            # Step 1: Get client's public key from PKA
            
            req = {"type": "get_key", "requested_id": "client"}
            pka_request = {"req": req, "timestamp": time.time()}
            
            client_public_key = self.get_public_key_from_pka(pka_request)
            self.logger.debug(f"Client public key: {client_public_key}")
            if not client_public_key:
                return False
                
            # Step 2: Generate N1 and send encrypted initial message
            n1 = random.randint(1, 1000000)
            init_data = {"id": "server", "n1": n1}

            if isinstance(client_public_key, str):
                client_public_key = self.rsa.import_key(client_public_key)

            encrypted_init = self.rsa.encrypt(json.dumps(init_data), self.rsa.import_key(client_public_key))
            client_socket.send(json.dumps({"data": str(encrypted_init)}).encode())

            # Step 3: Receive and verify N1, N2
            response = json.loads(client_socket.recv(4096).decode())
            print(f"Received N1 response: {response}")  # Debug print
            decrypted_response = json.loads(
                self.rsa.decrypt(response["data"], self.rsa.import_key(self.private_key))
            )
            
            received_n1 = decrypted_response["n1"]
            n2 = decrypted_response["n2"]

            if received_n1 != n1:
                print("Authentication failed: N1 mismatch")
                return False

           # Step 4: Send back N2
            try:
                encrypted_n2 = self.rsa.encrypt(str(n2), self.rsa.import_key(client_public_key))
                response_data = {"data": str(encrypted_n2)}
                print(f"Sending N2 response: {response_data}")  # Debug print
                client_socket.send(json.dumps(response_data).encode())
                # Tambahkan flush atau sleep kecil
                time.sleep(0.1)
            except Exception as e:
                print(f"Error sending N2: {e}")
                return False

            return True

        except Exception as e:
            print(f"Authentication error: {e}")
            return False

    def handle_connection(self, client_socket):
        try:
            # Receive initial encrypted data
            data = client_socket.recv(4096).decode()

            print(f"Received data: {data}")  # Debug print
            if not data:
                print("Received empty data from client")
                return False

            init_data = json.loads(data)
            decrypted_init = json.loads(
                self.rsa.decrypt(int(init_data["data"]), self.private_key)
            )

            client_id = decrypted_init["id"]
            n1 = decrypted_init["n1"]

            # Generate and send response with N2
            n2 = random.randint(1, 1000)
            response_data = {"n1": n1, "n2": n2}

            encrypted_response = self.rsa.encrypt(
                json.dumps(response_data), self.public_key
            )
            client_socket.send(
                json.dumps({"data": str(encrypted_response)}).encode()
            )

            # Verify N2 response
            n2_response = json.loads(client_socket.recv(4096).decode())
            decrypted_n2 = int(
                self.rsa.decrypt(n2_response["data"], self.private_key)
            )

            if decrypted_n2 != n2:
                print("Authentication failed: N2 mismatch")
                return False

            # Receive DES key
            encrypted_des_key = json.loads(client_socket.recv(4096).decode())
            # Decrypt and convert back to appropriate type
            self.des_key = self.rsa.decrypt(
                encrypted_des_key["data"], self.rsa.import_key(self.private_key)
            )
            # Convert string representation back to original type if needed
            self.des_key = eval(
                self.des_key
            )  # Be careful with eval, only use with trusted data

            print(f"Authenticated client: {client_id}")
            print(f"Received DES key: {self.des_key}")
            return True

        except Exception as e:
            print(f"Error handling connection: {e}")
            print(f"Error details: {str(e)}")
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
                    return self.rsa.import_key(key_data["public_key"])
                else:
                    print("Request verification failed")
                    return None
            else:
                print(f"Failed to get public key: {response.get('message')}")
                return None

        except Exception as e:
            print(f"Error in get_public_key_from_pka: {e}")
            return None
        finally:
            pka_socket.close()

    def handle_chat(self, client_socket):
        try:
            # Receive DES key first
            des_key_data = json.loads(client_socket.recv(4096).decode())
            self.des_key = self.rsa.decrypt(
                des_key_data["data"], 
                self.rsa.import_key(self.private_key)
            )
            print("Received DES key from client")

            while True:
                try:
                    # Receive and decrypt message
                    data = client_socket.recv(1024).decode()
                    if not data:
                        print("Client disconnected")
                        break

                    decrypted_msg = des.des_decrypt(data, self.des_key)
                    print(f"Client: {decrypted_msg}")

                    # Send response
                    message = input("You: ")
                    if message.lower() == "quit":
                        print("Closing connection...")
                        break

                    # Encrypt and send message
                    encrypted_msg = des.des_encrypt(message, self.des_key)
                    client_socket.send(encrypted_msg.encode())

                except ConnectionResetError:
                    print("Client disconnected unexpectedly")
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
                server_socket = socket.socket()
                server_socket.bind((self.host, self.port))
                server_socket.listen(5)
                print(f"Server started at {self.host}:{self.port}")

                while True:
                    print("\nWaiting for connections...")
                    client_socket, address = server_socket.accept()
                    print(f"Connection from: {address}")

                    if self.authenticate_client(client_socket):
                        self.handle_chat(client_socket)
                    else:
                        print("Authentication failed")
                        client_socket.close()

        except Exception as e:
                print(f"Server error: {e}")

if __name__ == "__main__":
    server = ChatServer()
    server.start()
