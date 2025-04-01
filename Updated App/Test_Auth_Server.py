import socket
import threading
#threading allows multiple threads in a python program
#basically, multiple users can connect to the server and not have to wait for each other when sending and recieving messages
import hashlib
import secrets

# In-memory storage
users = {}  # {username: (hashed_password, token)}
logged_in_clients = {}  # {conn: (username, token)} for tracking active clients
HOST = '127.0.0.1'
PORT = 65432

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def broadcast_message(sender_conn, message):
    """Send a chat message to all logged-in clients including the sender."""
    sender_username = logged_in_clients[sender_conn][0]  # Get sender's username
    formatted_message = f"CHAT {sender_username}: {message}"  # Format message with sender's username
    for client_conn in logged_in_clients.keys():
        try:
            client_conn.sendall(formatted_message.encode('utf-8'))
        except ConnectionError:
            del logged_in_clients[client_conn]  # Remove disconnected clients
            client_conn.close()


#handles communication between client and server, runs for each new client connected
def handle_client(conn, addr):
    """Handle individual client connections."""
    print(f"New connection from {addr}") #Announces the connection of a new connected user
    try:
        while True:
            # recieves a message from the client of 1024 bytes
            # .decode decodes the message from a bytes format into a string using utf-8
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break
            parts = data.split()
            if len(parts) < 2:
                conn.sendall(b"ERROR Invalid command format")
                continue
            command = parts[0]

            if command == "REGISTER":
                if len(parts) != 3:
                    conn.sendall(b"ERROR Usage: REGISTER username password")
                    continue
                username, password = parts[1], parts[2]
                if username in users:
                    conn.sendall(b"ERROR Username already exists")
                else:
                    hashed_pw = hash_password(password)
                    users[username] = (hashed_pw, None)
                    conn.sendall(b"SUCCESS User registered successfully")
           
            elif command == "LOGIN":
                if len(parts) != 3:
                    conn.sendall(b"ERROR Usage: LOGIN username password")
                    continue
                username, password = parts[1], parts[2]
                if username in users and users[username][0] == hash_password(password):
                    token = secrets.token_hex(16)
                    users[username] = (users[username][0], token)
                    logged_in_clients[conn] = (username, token)  # Add to logged-in list
                    conn.sendall(f"SUCCESS Token: {token}".encode('utf-8'))
                else:
                    conn.sendall(b"ERROR Invalid username or password")
           
            elif command == "RECOVER":
                if len(parts) != 2:
                    conn.sendall(b"ERROR Usage: RECOVER username")
                    continue
                username = parts[1]
                if username in users:
                    conn.sendall(b"SUCCESS Recovery code: 12345")
                else:
                    conn.sendall(b"ERROR Username not found")
           
            elif command == "CHAT":                
                if conn not in logged_in_clients:
                    conn.sendall(b"ERROR You must log in to chat")
                elif len(parts) < 2:
                    conn.sendall(b"ERROR Usage: CHAT message")
                else:
                    message = " ".join(parts[1:])
                    broadcast_message(conn, message)  # Broadcast to all including sender
            else:
                conn.sendall(b"ERROR Unknown command")
    except ConnectionError as e:
        print(f"Connection error with {addr}: {e}")
    finally:
        if conn in logged_in_clients:
            del logged_in_clients[conn]
        conn.close() #Cleanly disconnects client from server 
        print(f"Connection closed with {addr}")

def start_server():
    """Start the TCP server and listen for connections."""
    # AF_INET accepts IPV4 addresses over the internet, other types of sockets accept other types (like AF_INET accepts IPV6 addresses)
    # socket.SOCK_STREAM allows the streaming of data through the socket through TCP
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, PORT)) # Binds the socket to the HOST and PORT
        server.listen() # listens for connections and passes them off to the handle_client
        print(f"Server started on {HOST}:{PORT}")
        while True:
            conn, addr = server.accept() # waits for a new connection to the server, stores what address and port number the connection came from to send info back
            thread = threading.Thread(target=handle_client, args=(conn, addr)) # this allows multiple handle_client() functions to run at once
            thread.start() # starts the thread
    except Exception as e:
        print(f"Server error: {e}") # Displays any error messages
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
    