import tkinter as tk
from tkinter import messagebox
import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 65433

class PingMeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PingMe")
        self.geometry("400x600")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.token = None  # Store the session token after login
        try:
            print(f"Connecting to {HOST}:{PORT}")
            self.sock.connect((HOST, PORT))
        except ConnectionError as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            self.destroy()
            return

        self.frames = {}
        self.current_frame = None  # Track the currently active frame
        for Page in (MainPage, RegisterPage, LoginPage, ForgotPasswordPage, ChatPage):
            frame = Page(self)
            self.frames[Page] = frame
            frame.place(x=0, y=0, relwidth=1, relheight=1)

        self.show_frame(MainPage)

        self.listen_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        self.listen_thread.start()

    def reconnect(self):
        """Reconnect the socket to the server if it's disconnected."""
        try:
            self.sock.close()  # Close the existing socket
        except:
            pass
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print(f"Reconnecting to {HOST}:{PORT}")
            self.sock.connect((HOST, PORT))
            print("Reconnection successful")
        except ConnectionError as e:
            print(f"Reconnection failed: {e}")
            if self.current_frame:
                self.current_frame.update_status(f"Error: Failed to reconnect to server - {e}")
            return False
        return True

    def show_frame(self, page):
        if self.current_frame == self.frames[RegisterPage]:
            self.frames[RegisterPage].clear_status()  # Clear the status when leaving RegisterPage
        if self.current_frame == self.frames[LoginPage]:
            self.frames[LoginPage].clear_status()  # Clear the status when leaving LoginPage
        # Clear chat messages when navigating to ChatPage (on login)
        if page == ChatPage:
            self.frames[ChatPage].clear_messages()
        self.frames[page].tkraise()
        self.current_frame = self.frames[page]  # Update the current frame

    def send(self, request):
        # Include the token in requests if it exists (except for REGISTER and initial RECOVER)
        if self.token and request.get("type") not in ["REGISTER", "RECOVER"]:
            request["token"] = self.token
        message = json.dumps(request)
        print(f"Sending request: {message}")
        try:
            self.sock.sendall(f"{message}\n".encode('utf-8'))
        except (ConnectionError, OSError) as e:
            print(f"Failed to send request: {e}")
            # Attempt to reconnect and retry sending
            if self.reconnect():
                try:
                    self.sock.sendall(f"{message}\n".encode('utf-8'))
                except ConnectionError as e2:
                    print(f"Retry failed: {e2}")
                    if self.current_frame:
                        self.current_frame.update_status(f"Error: Connection to server lost - {e2}")
            else:
                if self.current_frame:
                    self.current_frame.update_status(f"Error: Connection to server lost - {e}")

    def listen_for_messages(self):
        buffer = ""
        while True:
            try:
                data = self.sock.recv(1024).decode('utf-8')
                if not data:
                    break
                buffer += data
                while '\n' in buffer:
                    message, buffer = buffer.split('\n', 1)
                    try:
                        response = json.loads(message)
                        print(f"Received response: {response}")
                    except json.JSONDecodeError as e:
                        print(f"Invalid JSON response: {e}")
                        continue

                    response_type = response.get("type")
                    if response_type == "CHAT":
                        self.frames[ChatPage].append_message(response.get("message"))
                    elif response_type == "QUESTIONS":
                        self.frames[ForgotPasswordPage].show_questions()
                    elif response_type == "SUCCESS":
                        message = response.get("message")
                        if "Login successful" in message:
                            # Extract and store the token, but don't display it in the UI
                            self.token = message.split("Token: ")[1]
                            print(f"Stored token: {self.token}")
                            self.frames[LoginPage].update_status("Login successful")
                        else:
                            if self.current_frame:
                                self.current_frame.update_status(message)
                    elif response_type == "ERROR":
                        if self.current_frame:
                            self.current_frame.update_status(response.get("message"))
                    elif response_type == "LOGOUT":
                        self.token = None  # Clear the token on logout
                        self.frames[ChatPage].append_message("You have logged out.")
                        # Clear chat messages on logout
                        self.frames[ChatPage].clear_messages()
                        # Reconnect the socket after logout
                        self.reconnect()
                        self.show_frame(MainPage)
                    else:
                        print(f"Unknown response type: {response_type}")
            except (ConnectionError, OSError) as e:
                print(f"Connection error in listen thread: {e}")
                if self.current_frame:
                    self.current_frame.update_status(f"Error: Connection to server lost - {e}")
                break

class MainPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="PingMe", font=("Arial", 20)).pack(pady=20)
        tk.Label(self, text="Welcome to PingMe").pack(pady=10)
        tk.Button(self, text="Register", command=lambda: master.show_frame(RegisterPage)).pack(pady=10)
        tk.Button(self, text="Login", command=lambda: master.show_frame(LoginPage)).pack(pady=10)

    def update_status(self, msg):
        pass

class RegisterPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="PingMe", font=("Arial", 20)).pack(pady=10)
        self.status = tk.Label(self, text="")
        self.status.pack()

        tk.Label(self, text="Note: Save your 2FA code; it will disappear after you leave this page.", fg="red").pack(pady=5)

        self.entries = {}
        tk.Label(self, text="Username:").pack()
        self.entries["username"] = tk.Entry(self)
        self.entries["username"].pack(pady=2)

        tk.Label(self, text="Password:").pack()
        self.entries["password"] = tk.Entry(self, show="*")
        self.entries["password"].pack(pady=2)

        tk.Label(self, text="What is your pet's name?").pack()
        self.entries["answer1"] = tk.Entry(self)
        self.entries["answer1"].pack(pady=2)

        tk.Label(self, text="What is your favorite color?").pack()
        self.entries["answer2"] = tk.Entry(self)
        self.entries["answer2"].pack(pady=2)

        tk.Button(self, text="Register", command=self.register).pack(pady=10)
        tk.Button(self, text="Back", command=lambda: master.show_frame(MainPage)).pack()

    def register(self):
        username = self.entries["username"].get().strip()
        password = self.entries["password"].get().strip()
        answer1 = self.entries["answer1"].get().strip()
        answer2 = self.entries["answer2"].get().strip()

        print(f"Register fields - username: '{username}', password: '{password}', answer1: '{answer1}', answer2: '{answer2}'")

        if not all([username, password, answer1, answer2]):
            self.update_status("Please fill all fields")
            return

        request = {
            "type": "REGISTER",
            "username": username,
            "password": password,
            "answer1": answer1,
            "answer2": answer2
        }
        self.master.send(request)

    def update_status(self, msg):
        self.status.config(text=msg)

    def clear_status(self):
        self.status.config(text="")  # Clear the status label when leaving the page

class LoginPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="PingMe", font=("Arial", 20)).pack(pady=10)
        self.status = tk.Label(self, text="")
        self.status.pack()

        self.entries = {}
        tk.Label(self, text="Username:").pack()
        self.entries["username"] = tk.Entry(self)
        self.entries["username"].pack(pady=2)

        tk.Label(self, text="Password:").pack()
        self.entries["password"] = tk.Entry(self, show="*")
        self.entries["password"].pack(pady=2)

        tk.Label(self, text="2FA Code:").pack()
        self.entries["two_fa_code"] = tk.Entry(self)
        self.entries["two_fa_code"].pack(pady=2)

        tk.Button(self, text="Login", command=self.login).pack(pady=10)
        tk.Button(self, text="Forgot Password?", command=lambda: master.show_frame(ForgotPasswordPage)).pack()
        tk.Button(self, text="Back", command=lambda: master.show_frame(MainPage)).pack()

    def login(self):
        username = self.entries["username"].get().strip()
        password = self.entries["password"].get().strip()
        two_fa_code = self.entries["two_fa_code"].get().strip()

        if not all([username, password, two_fa_code]):
            self.update_status("Please fill all fields")
            return

        request = {
            "type": "LOGIN",
            "username": username,
            "password": password,
            "two_fa_code": two_fa_code
        }
        self.master.send(request)

    def update_status(self, msg):
        if "Login successful" in msg:
            self.master.show_frame(ChatPage)
        self.status.config(text=msg)

    def clear_status(self):
        self.status.config(text="")  # Clear the status label when leaving the page

class ForgotPasswordPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="PingMe", font=("Arial", 20)).pack(pady=10)
        self.status = tk.Label(self, text="")
        self.status.pack()

        self.username_frame = tk.Frame(self)
        tk.Label(self.username_frame, text="Enter Username:").pack()
        self.username_entry = tk.Entry(self.username_frame)
        self.username_entry.pack()
        tk.Button(self.username_frame, text="Submit", command=self.request_questions).pack(pady=5)
        self.username_frame.pack()

        self.questions_frame = tk.Frame(self)
        tk.Label(self.questions_frame, text="What is your pet's name?").pack()
        self.answer1_entry = tk.Entry(self.questions_frame)
        self.answer1_entry.pack(pady=2)
        tk.Label(self.questions_frame, text="What is your favorite color?").pack()
        self.answer2_entry = tk.Entry(self.questions_frame)
        self.answer2_entry.pack(pady=2)
        tk.Button(self.questions_frame, text="Verify", command=self.verify_answers).pack(pady=5)

        tk.Button(self, text="Back", command=lambda: master.show_frame(MainPage)).pack()

    def request_questions(self):
        username = self.username_entry.get().strip()
        if not username:
            self.status.config(text="Please enter a username")
            return

        request = {"type": "RECOVER", "username": username}
        self.master.send(request)

    def show_questions(self):
        self.username_frame.pack_forget()
        self.questions_frame.pack()
        self.status.config(text="Please answer the security questions.")

    def verify_answers(self):
        username = self.username_entry.get().strip()
        answer1 = self.answer1_entry.get().strip()
        answer2 = self.answer2_entry.get().strip()

        if not all([answer1, answer2]):
            self.status.config(text="Please provide answers to both questions")
            return

        request = {
            "type": "RECOVER",
            "username": username,
            "answer1": answer1,
            "answer2": answer2
        }
        self.master.send(request)

    def update_status(self, msg):
        self.status.config(text=msg)
        if "Recovery successful" in msg:
            self.questions_frame.pack_forget()
            self.username_frame.pack()

class ChatPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#2C2F33")  # Dark background for the frame
        tk.Label(self, text="PingMe - Chat", font=("Arial", 16), fg="white", bg="#2C2F33").pack(pady=10)

        # Chat area with a border and background
        self.text_area = tk.Text(self, state='disabled', height=20, bg="#1C2526", fg="white", 
                                 insertbackground="white", borderwidth=2, relief="solid")
        self.text_area.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

        # Frame for input and button
        input_frame = tk.Frame(self, bg="#2C2F33")
        input_frame.pack(pady=5)

        self.entry = tk.Entry(input_frame, width=30, bg="#40444B", fg="white", 
                              insertbackground="white", borderwidth=1, relief="solid")
        self.entry.pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="Send", command=self.send_message, bg="#7289DA", fg="white", 
                  borderwidth=1, relief="solid").pack(side=tk.LEFT)

        # Add Log Out button
        tk.Button(self, text="Log Out", command=self.logout, bg="#FF5555", fg="white", 
                  borderwidth=1, relief="solid").pack(pady=10)

    def send_message(self):
        msg = self.entry.get().strip()
        if not msg:
            self.append_message("Cannot send an empty message")
            return

        request = {"type": "CHAT", "message": msg}
        self.master.send(request)
        self.entry.delete(0, tk.END)

    def logout(self):
        request = {"type": "LOGOUT"}
        self.master.send(request)

    def append_message(self, msg):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def clear_messages(self):
        self.text_area.config(state='normal')
        self.text_area.delete(1.0, tk.END)
        self.text_area.config(state='disabled')

    def update_status(self, msg):
        self.append_message(msg)

if __name__ == "__main__":
    app = PingMeApp()
    app.mainloop()