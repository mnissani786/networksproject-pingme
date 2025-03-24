
# Tutorial: https://www.youtube.com/watch?v=3QiPPX-KeSc&ab_channel=TechWithTim      Left off at 36:00
# https://stackoverflow.com/questions/12362542/python-server-only-one-usage-of-each-socket-address-is-normally-permitted   

import socket
import threading 
#threading allows multiple threads in a python program
#basically, multiple users can connect to the server and not have to wait for each other when sending and recieving messages

HEADER = 64 # Specifies how many bytes to accept from the client
PORT = 2323
SERVER = socket.gethostbyname(socket.gethostname()) # Gets the name and ip address of the device running the server
print(f"Server IP: {SERVER}")
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!disconnect" 

# AF_INET accepts IPV4 addresses over the internet, other types of sockets accept other types (like AF_INET accepts IPV6 addresses)
# socket.SOCK_STREAM allows the streaming of data through the socket through TCP
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows socket to be used again right after termination of the program
server.bind(ADDR) # Binds the socket to the address

#handles communication between client and server, runs for each client connected
def handle_client(connection, addr):
    print("New Connection! {addr} connected")
    while True:
        # recieves a message from the client of length HEADER bytes
        # .decode decodes the message from a bytes format into a string using utf-8
        msg_length = int(connection.recv(HEADER).decode(FORMAT))
        msg = connection.recv(msg_length).decode(FORMAT) #stores the actual message the user sends
        if msg == DISCONNECT_MESSAGE: # if user types "!disconnect" the thread will break
            break
        print(f"[{addr}]: {msg}")
    connection.close() #Cleanly disconnects client from server 


# listens for connections and passes them off to the handle_client
def start():
    server.listen()
    while True:
        connection, addr = server.accept() # waits for a new connection to the server, stores what address and port number the connection came from to send info back
        thread = threading.Thread(target=handle_client, args=(connection, addr)) # this allows multiple handle_client() functions to run at once
        thread.start() # starts the thread
        print(f"Active connections: {threading.activeCount()-1}") # Shows how many threads are running/clients currently connected to the server

print("Starting server!")
start()