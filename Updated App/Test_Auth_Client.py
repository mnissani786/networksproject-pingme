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

    def show_frame(self, page):
        if self.current_frame == self.frames[RegisterPage]:
            self.frames[RegisterPage].clear_status()  # Clear the status when leaving RegisterPage
        self.frames[page].tkraise()
        self.current_frame = self.frames[page]  # Update the current frame

    def send(self, request):
        message = json.dumps(request)
        print(f"Sending request: {message}")
        try:
            self.sock.sendall(f"{message}\n".encode('utf-8'))
        except ConnectionError as e:
            print(f"Failed to send request: {e}")
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
                    elif response_type == "SUCCESS" or response_type == "ERROR":
                        # Only update the status of the current frame
                        if self.current_frame:
                            self.current_frame.update_status(response.get("message"))
                    else:
                        print(f"Unknown response type: {response_type}")
            except ConnectionError as e:
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
        if "New 2FA code" in msg:
            self.questions_frame.pack_forget()
            self.username_frame.pack()
        self.status.config(text=msg)

class ChatPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="PingMe - Chat", font=("Arial", 16)).pack(pady=10)
        self.text_area = tk.Text(self, state='disabled', height=20)
        self.text_area.pack(pady=5)
        self.entry = tk.Entry(self, width=30)
        self.entry.pack(side=tk.LEFT, padx=5)
        tk.Button(self, text="Send", command=self.send_message).pack(side=tk.LEFT)

    def send_message(self):
        msg = self.entry.get().strip()
        if not msg:
            self.append_message("Cannot send an empty message")
            return

        request = {"type": "CHAT", "message": msg}
        self.master.send(request)
        self.entry.delete(0, tk.END)

    def append_message(self, msg):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def update_status(self, msg):
        self.append_message(msg)

if __name__ == "__main__":
    app = PingMeApp()
    app.mainloop()