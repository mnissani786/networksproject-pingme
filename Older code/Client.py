import socket

HEADER = 64 # Specifies how many bytes to accept from the client
PORT = 2323
SERVER = socket.gethostbyname(socket.gethostname()) # Gets the name and ip address of the device running the server
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!disconnect"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows socket to be used right after termination of the program
client.connect(ADDR) # Connects to the server
