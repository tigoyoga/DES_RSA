import socket
import json
import time
from rsa import RSA
from rsa import ImprovedRSA


class PublicKeyAuthority:

    def __init__(self, host="localhost", port=6000):
        self.host = host
        self.port = port
        self.rsa = RSA()
        self.improved_rsa = ImprovedRSA()
        self.server_socket = socket.socket()
        self.server_socket.bind((host, port))

        self.keys = {
            'auth': {
                'public': '6161317031919495016749804258153971457780741115257801805278754622435339417881069548961565696474842999157534163002139523775502237244750110892994874339059804277076970008600002638922509853943230417198200736775561193127505226294240453897883745935955067580497948801361046898423328694100129153386023796404727556977:65537',
                'private':'6161317031919495016749804258153971457780741115257801805278754622435339417881069548961565696474842999157534163002139523775502237244750110892994874339059804277076970008600002638922509853943230417198200736775561193127505226294240453897883745935955067580497948801361046898423328694100129153386023796404727556977:1333195551057423422380166534703777549213248848062482069680608195382082614171711358069853108041407885180172909433348193946326460264702402041191392846822512628622447988883637380042046581642844435874954430571417912978341148483910105322275860161732143643919264071731618110164640292170560578623636564722141884613'
            },
            'client': {
                'public': '26858627481455264727858704072963116162849816880908732465731330254347364959544380193164933578851384040736507241619240780621767106121559768200762625636323091476054671187018048595532994447999597581042653023433502827305440202229962408785487010855070606563770434482792518501741282588643183500523897546817076278989:65537'
            },
            'server': {
                'public': '51863431050711052966272446829276768371276448210025419682214432876672068925826744257233541925030795541707029056444584082234321902855422624744834879595778287369055521334581321377332227806045229697190315487434544332679135272739001159333166106058837293584567775125456316293061226640871778272831798721100556958253:65537'
            }
        }
        

    def handle_key_request(self, request_data):
        try:
            req = request_data['req']
            timestamp = request_data['timestamp']
            requested_id = req['requested_id']

            # Get appropriate key based on requested_id
            if requested_id == 'client':
                key_data = {
                    "public_key": self.keys['client']['public'],
                    "req": req,
                    "timestamp": timestamp
                }
            else:
                key_data = {
                    "public_key": self.keys['server']['public'],
                    "req": req,
                    "timestamp": timestamp
                }

            # Encrypt with auth private key
            encrypted_data = self.rsa.encrypt(
                json.dumps(key_data),
                self.rsa.import_key(self.keys['auth']['private'])
            )

            return {
                "status": "success",
                "data": encrypted_data
            }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


    def start(self):
        self.server_socket.listen(5)
        print(f"PKA started at {self.host}:{self.port}")

        while True:
            try:
                conn, address = self.server_socket.accept()
                print(f"Connection from: {address}")

                data = conn.recv(4096).decode()
                if not data:
                    print("Received empty data")
                    conn.close()
                    continue

                print(f"Received data: {data}")  # Debug print

                try:
                    request = json.loads(data)
                except json.JSONDecodeError as e:
                    print(f"JSON decode error: {e}")
                    conn.close()
                    continue

                # Check for both direct type and nested type in req
                request_type = request.get("type")
                if not request_type and "req" in request:
                    request_type = request["req"].get("type")

                if request_type == "get_key" or (
                    "req" in request and request["req"].get("type") == "get_key"
                ):
                    response = self.handle_key_request(request)
                    requested_id = request.get("requested_id") or request[
                        "req"
                    ].get("requested_id")
                    print(f"Handled key request for: {requested_id}")
                else:
                    print(f"Invalid request format or type: {request}")
                    response = {
                        "status": "error",
                        "message": "Invalid request format or type",
                    }


                # print type of response
                print(f"Type of response: {type(response)}")  # Debug print
                print(f"Sending response: {response}")  # Debug print
                conn.send(json.dumps(response).encode())
                conn.close()

            except Exception as e:
                print(f"Error handling connection: {e}")
                try:
                    conn.close()
                except:
                    pass


if __name__ == "__main__":
    pka = PublicKeyAuthority()
    pka.start()