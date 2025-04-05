import socket
import threading
import hashlib
import secrets

# In-memory storage
users = {}  # {username: (hashed_password, token, two_factor_code, security_questions)}
logged_in_clients = {}  # {conn: (username, token)} for tracking active clients

HOST = '127.0.0.1'
PORT = 65433

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_2fa_code():
    """Generate a 6-digit 2FA code."""
    return str(secrets.randbelow(900000) + 100000)  # Ensures a 6-digit number

def broadcast_message(sender_conn, message):
    """Send a chat message to all logged-in clients including the sender."""
    sender_username = logged_in_clients[sender_conn][0]
    formatted_message = f"CHAT {sender_username}: {message}"
    for client_conn in list(logged_in_clients.keys()):
        try:
            client_conn.sendall(formatted_message.encode('utf-8'))
        except ConnectionError:
            del logged_in_clients[client_conn]
            client_conn.close()

def handle_client(conn, addr):
    """Handle individual client connections."""
    print(f"New connection from {addr}")
    try:
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break
            parts = data.split()
            if len(parts) < 2:
                conn.sendall(b"ERROR Invalid command format")
                continue

            command = parts[0]

            if command == "REGISTER":
                if len(parts) != 6:  # username password q1 a1 q2 a2
                    conn.sendall(b"ERROR Usage: REGISTER username password q1 a1 q2 a2")
                    continue

                username, password, q1, a1, q2, a2 = parts[1:7]
                username = username.replace("_", " ")
                password = password.replace("_", " ")
                q1 = q1.replace("_", " ")
                a1 = a1.replace("_", " ")
                q2 = q2.replace("_", " ")
                a2 = a2.replace("_", " ")

                if username in users:
                    conn.sendall(b"ERROR Username already exists")
                else:
                    hashed_pw = hash_password(password)
                    two_factor_code = generate_2fa_code()
                    security_questions = {q1: a1.lower(), q2: a2.lower()}
                    users[username] = (hashed_pw, None, two_factor_code, security_questions)
                    conn.sendall(f"SUCCESS User registered. Your 2FA code is: {two_factor_code}".encode('utf-8'))

            elif command == "LOGIN":
                if len(parts) != 4:  # username, password, 2fa_code
                    conn.sendall(b"ERROR Usage: LOGIN username password 2fa_code")
                    continue
                username, password, two_fa_input = parts[1], parts[2], parts[3]
                username = username.replace("_", " ")
                password = password.replace("_", " ")
                two_fa_input = two_fa_input.replace("_", " ")
                if (username in users and
                    users[username][0] == hash_password(password) and
                    users[username][2] == two_fa_input):
                    token = secrets.token_hex(16)
                    users[username] = (users[username][0], token, users[username][2], users[username][3])
                    logged_in_clients[conn] = (username, token)
                    conn.sendall(f"SUCCESS Token: {token}".encode('utf-8'))
                else:
                    conn.sendall(b"ERROR Invalid username, password, or 2FA code")

            elif command == "RECOVER":
                if len(parts) == 2:
                    username = parts[1].replace("_", " ")
                    if username in users:
                        questions = list(users[username][3].keys())
                        q1 = questions[0].replace(" ", "_")
                        q2 = questions[1].replace(" ", "_")
                        conn.sendall(f"QUESTIONS {q1} {q2}".encode('utf-8'))
                    else:
                        conn.sendall(b"ERROR Username not found")
                elif len(parts) == 5 and parts[1] == "VERIFY":
                    username, a1, a2 = parts[2], parts[3], parts[4]
                    username = username.replace("_", " ")
                    a1 = a1.replace("_", " ")
                    a2 = a2.replace("_", " ")
                    if username in users:
                        sec_questions = users[username][3]
                        if (sec_questions[list(sec_questions.keys())[0]] == a1.lower() and
                            sec_questions[list(sec_questions.keys())[1]] == a2.lower()):
                            new_2fa_code = generate_2fa_code()
                            users[username] = (users[username][0], users[username][1], new_2fa_code, sec_questions)
                            conn.sendall(f"SUCCESS New 2FA code: {new_2fa_code}".encode('utf-8'))
                        else:
                            conn.sendall(b"ERROR Incorrect answers")
                    else:
                        conn.sendall(b"ERROR Username not found")
                else:
                    conn.sendall(b"ERROR Usage: RECOVER username or RECOVER VERIFY username answer1 answer2")

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
    port = PORT
    attempt = 0
    max_attempts = 10

    while attempt < max_attempts:
        try:
            server.bind((HOST, port))
            server.listen()
            print(f"Server started on {HOST}:{port}")
            break
        except OSError as e:
            if e.errno == 48:  # Address already in use
                attempt += 1
                port += 1
                print(f"Port {port - 1} in use, trying port {port}...")
            else:
                print(f"Server error: {e}")
                server.close()
                return
    else:
        print("Failed to bind to any port.")
        return

    try:
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
