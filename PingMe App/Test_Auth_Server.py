import socket
import threading
import hashlib
import secrets

# In-memory storage
# username: { 'password': ..., 'token': ..., 'question': ..., 'answer': ... }
users = {}
logged_in_clients = {}

HOST = '127.0.0.1'
PORT = 65432

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def broadcast_message(sender_conn, message):
    sender_username = logged_in_clients[sender_conn][0]
    formatted_message = f"CHAT {sender_username}: {message}"
    for client_conn in logged_in_clients.keys():
        try:
            client_conn.sendall(formatted_message.encode('utf-8'))
        except ConnectionError:
            del logged_in_clients[client_conn]
            client_conn.close()

def handle_client(conn, addr):
    print(f"New connection from {addr}")
    try:
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break
            parts = data.split()
            command = parts[0]

            if command == "REGISTER":
                if len(parts) < 5:
                    conn.sendall(b"ERROR Usage: REGISTER username password question answer")
                    continue
                username = parts[1]
                password = parts[2]
                question = parts[3]
                answer = " ".join(parts[4:])
                if username in users:
                    conn.sendall(b"ERROR Username already exists")
                else:
                    users[username] = {
                        'password': hash_password(password),
                        'token': None,
                        'question': question,
                        'answer': hash_password(answer.lower())
                    }
                    conn.sendall(b"SUCCESS User registered")

            elif command == "LOGIN":
                if len(parts) != 3:
                    conn.sendall(b"ERROR Usage: LOGIN username password")
                    continue
                username, password = parts[1], parts[2]
                user = users.get(username)
                if user and user['password'] == hash_password(password):
                    token = secrets.token_hex(16)
                    users[username]['token'] = token
                    logged_in_clients[conn] = (username, token)
                    conn.sendall(f"SUCCESS Token: {token}".encode('utf-8'))
                else:
                    conn.sendall(b"ERROR Invalid username or password")

            elif command == "RECOVER":
                if len(parts) < 2:
                    conn.sendall(b"ERROR Usage: RECOVER username")
                    continue
                username = parts[1]
                if username in users:
                    question = users[username]['question']
                    conn.sendall(f"QUESTION {question}".encode('utf-8'))
                else:
                    conn.sendall(b"ERROR Username not found")

            elif command == "ANSWER":
                if len(parts) < 3:
                    conn.sendall(b"ERROR Usage: ANSWER username answer")
                    continue
                username = parts[1]
                answer = " ".join(parts[2:]).lower()
                if username in users:
                    if users[username]['answer'] == hash_password(answer):
                        conn.sendall(b"SUCCESS Verified")
                    else:
                        conn.sendall(b"ERROR Incorrect answer")
                else:
                    conn.sendall(b"ERROR Username not found")

            elif command == "NEWPASS":
                if len(parts) < 3:
                    conn.sendall(b"ERROR Usage: NEWPASS username newpassword")
                    continue
                username, new_password = parts[1], parts[2]
                if username in users:
                    users[username]['password'] = hash_password(new_password)
                    conn.sendall(b"SUCCESS Password reset")
                else:
                    conn.sendall(b"ERROR Username not found")

            elif command == "CHAT":
                if conn not in logged_in_clients:
                    conn.sendall(b"ERROR You must log in to chat")
                elif len(parts) < 2:
                    conn.sendall(b"ERROR Usage: CHAT message")
                else:
                    message = " ".join(parts[1:])
                    broadcast_message(conn, message)
            else:
                conn.sendall(b"ERROR Unknown command")
    except ConnectionError as e:
        print(f"Connection error with {addr}: {e}")
    finally:
        if conn in logged_in_clients:
            del logged_in_clients[conn]
        conn.close()
        print(f"Connection closed with {addr}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, PORT))
        server.listen()
        print(f"Server started on {HOST}:{PORT}")
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()

#cd Desktop/WIN25/COMPUTER NETWORKS 2470/network prj/PingMe App
#python test_auth_server.py