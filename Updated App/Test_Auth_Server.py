import socket
import threading
import hashlib
import secrets
import sqlite3
import json
from contextlib import contextmanager
import os

# In-memory storage for active clients
logged_in_clients = {}  # {conn: (username, token)}

HOST = '127.0.0.1'
PORT = 65433

# Use the directory where the script is running
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'users.db')

# Check if the database file exists
if not os.path.exists(DB_PATH):
    raise FileNotFoundError(f"Database file not found at {DB_PATH}. Please create users.db manually with the correct schema.")

@contextmanager
def get_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        print(f"Successfully connected to database at {DB_PATH}")
    except sqlite3.Error as e:
        print(f"Failed to connect to database at {DB_PATH}: {e}")
        raise
    try:
        yield conn
    finally:
        conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_2fa_code():
    max_attempts = 10
    for _ in range(max_attempts):
        code = str(secrets.randbelow(900000) + 100000)
        with get_db() as db:
            c = db.cursor()
            c.execute("SELECT 1 FROM users WHERE two_factor_code = ?", (code,))
            if not c.fetchone():
                return code
    raise ValueError("Unable to generate a unique 2FA code after multiple attempts")

def verify_token(token):
    if not token:
        return None
    try:
        with get_db() as db:
            c = db.cursor()
            c.execute("SELECT username FROM users WHERE token = ?", (token,))
            result = c.fetchone()
            if result:
                return result[0]  # Return the username associated with the token
            return None
    except sqlite3.Error as e:
        print(f"Database error during token verification: {e}")
        return None

def send_response(conn, response):
    try:
        conn.sendall((json.dumps(response) + "\n").encode('utf-8'))
    except ConnectionError as e:
        print(f"Failed to send response: {e}")

def broadcast_message(sender_conn, message):
    sender_username = logged_in_clients[sender_conn][0]
    response = {"type": "CHAT", "message": f"{sender_username}: {message}"}
    for client_conn in list(logged_in_clients.keys()):
        send_response(client_conn, response)

def handle_client(conn, addr):
    print(f"New connection from {addr}")
    buffer = ""
    try:
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break
            buffer += data
            while '\n' in buffer:
                message, buffer = buffer.split('\n', 1)
                try:
                    request = json.loads(message)
                    print(f"Received request: {request}")
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON: {e}")
                    send_response(conn, {"type": "ERROR", "message": "Invalid request format"})
                    continue

                request_type = request.get("type")

                if request_type == "REGISTER":
                    username = request.get("username")
                    password = request.get("password")
                    answer1 = request.get("answer1")
                    answer2 = request.get("answer2")

                    if not all([username, password, answer1, answer2]):
                        send_response(conn, {"type": "ERROR", "message": "All fields are required"})
                        continue

                    try:
                        with get_db() as db:
                            c = db.cursor()
                            c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
                            if c.fetchone():
                                send_response(conn, {"type": "ERROR", "message": "Username already exists"})
                            else:
                                hashed_pw = hash_password(password)
                                try:
                                    two_factor_code = generate_2fa_code()
                                except ValueError as e:
                                    send_response(conn, {"type": "ERROR", "message": str(e)})
                                    continue
                                # Store both the hashed and plaintext password
                                c.execute('''
                                    INSERT INTO users (username, hashed_password, plaintext_password, two_factor_code, 
                                    security_answer1, security_answer2, token)
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                ''', (username, hashed_pw, password, two_factor_code, answer1.lower(), answer2.lower(), None))
                                db.commit()
                                send_response(conn, {"type": "SUCCESS", "message": f"User registered. Your 2FA code is: {two_factor_code}"})
                    except sqlite3.Error as e:
                        print(f"Database error during REGISTER: {e}")
                        send_response(conn, {"type": "ERROR", "message": f"Database error: {e}"})

                elif request_type == "LOGIN":
                    username = request.get("username")
                    password = request.get("password")
                    two_fa_input = request.get("two_fa_code")

                    if not all([username, password, two_fa_input]):
                        send_response(conn, {"type": "ERROR", "message": "All fields are required"})
                        continue

                    try:
                        with get_db() as db:
                            c = db.cursor()
                            c.execute("SELECT hashed_password, two_factor_code FROM users WHERE username = ?", (username,))
                            result = c.fetchone()
                            if result and result[0] == hash_password(password) and result[1] == two_fa_input:
                                token = secrets.token_hex(16)
                                c.execute("UPDATE users SET token = ? WHERE username = ?", (token, username))
                                db.commit()
                                logged_in_clients[conn] = (username, token)
                                send_response(conn, {"type": "SUCCESS", "message": f"Login successful. Token: {token}"})
                            else:
                                send_response(conn, {"type": "ERROR", "message": "Invalid username, password, or 2FA code"})
                    except sqlite3.Error as e:
                        print(f"Database error during LOGIN: {e}")
                        send_response(conn, {"type": "ERROR", "message": f"Database error: {e}"})

                elif request_type == "RECOVER":
                    username = request.get("username")
                    answer1 = request.get("answer1")
                    answer2 = request.get("answer2")

                    if not username:
                        send_response(conn, {"type": "ERROR", "message": "Username is required"})
                        continue

                    try:
                        with get_db() as db:
                            c = db.cursor()
                            if answer1 is None and answer2 is None:
                                # First step: Check if username exists and prompt for security questions
                                c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
                                if c.fetchone():
                                    send_response(conn, {"type": "QUESTIONS"})
                                else:
                                    send_response(conn, {"type": "ERROR", "message": "Username not found"})
                            else:
                                # Second step: Verify security answers and return original password and 2FA code
                                if not all([answer1, answer2]):
                                    send_response(conn, {"type": "ERROR", "message": "Both answers are required"})
                                    continue
                                c.execute("SELECT security_answer1, security_answer2, plaintext_password, two_factor_code FROM users WHERE username = ?", (username,))
                                result = c.fetchone()
                                if result:
                                    sec_answer1, sec_answer2, plaintext_password, two_factor_code = result
                                    if sec_answer1 == answer1.lower() and sec_answer2 == answer2.lower():
                                        # Return the original plaintext password and 2FA code
                                        send_response(conn, {"type": "SUCCESS", "message": f"Recovery successful. Your password is: {plaintext_password}. Your 2FA code is: {two_factor_code}"})
                                    else:
                                        send_response(conn, {"type": "ERROR", "message": "Incorrect answers"})
                                else:
                                    send_response(conn, {"type": "ERROR", "message": "Username not found"})
                    except sqlite3.Error as e:
                        print(f"Database error during RECOVER: {e}")
                        send_response(conn, {"type": "ERROR", "message": f"Database error: {e}"})

                elif request_type == "CHAT":
                    # Verify the token in the request
                    token = request.get("token")
                    username = verify_token(token)
                    if not username:
                        send_response(conn, {"type": "ERROR", "message": "Invalid or missing token"})
                        continue
                    # Ensure the connection is in logged_in_clients
                    if conn not in logged_in_clients:
                        logged_in_clients[conn] = (username, token)
                    message = request.get("message")
                    if not message:
                        send_response(conn, {"type": "ERROR", "message": "Message cannot be empty"})
                        continue
                    broadcast_message(conn, message)

                elif request_type == "LOGOUT":
                    # Verify the token in the request
                    token = request.get("token")
                    username = verify_token(token)
                    if not username:
                        send_response(conn, {"type": "ERROR", "message": "Invalid or missing token"})
                        continue
                    try:
                        with get_db() as db:
                            c = db.cursor()
                            c.execute("UPDATE users SET token = ? WHERE username = ?", (None, username))
                            db.commit()
                    except sqlite3.Error as e:
                        print(f"Database error during LOGOUT: {e}")
                        send_response(conn, {"type": "ERROR", "message": f"Database error: {e}"})
                        continue
                    if conn in logged_in_clients:
                        del logged_in_clients[conn]
                    send_response(conn, {"type": "LOGOUT", "message": "Logged out successfully"})

                else:
                    send_response(conn, {"type": "ERROR", "message": "Unknown request type"})
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
            if e.errno == 98:
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
    print(f"Connecting to database at {DB_PATH}...")
    start_server()