import tkinter as tk
from tkinter import messagebox
import socket
import threading
import json

# Oakland University colors
GOLDEN_GRIZZLY = "#F2A900"
BLACK = "#2D2926"
GRAY = "#B4B7B9"
WHITE = "#FFFFFF"

class PingMeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PingMe")
        self.geometry("400x600")
        self.config(bg=WHITE)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.token = None

        try:
            host, port = self.enter_server()
            print(f"Connecting to {host}:{port}")
            self.sock.connect((host, port))
        except ConnectionError as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            self.destroy()
            return

        self.frames = {}
        self.current_frame = None
        for Page in (MainPage, RegisterPage, LoginPage, ForgotPasswordPage, ChatPage):
            frame = Page(self)
            self.frames[Page] = frame
            frame.place(x=0, y=0, relwidth=1, relheight=1)

        self.show_frame(MainPage)

        self.listen_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        self.listen_thread.start()

    def enter_server(self):
        host = input(f"Enter the server ip: ")
        port = int(input(f"Enter the server port number: "))
        return host, port

    def reconnect(self):
        try: self.sock.close()
        except: pass
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print(f"Reconnecting to {self.host}:{self.port}")
            self.sock.connect((self.host, self.port))
            print("Reconnection successful")
        except ConnectionError as e:
            print(f"Reconnection failed: {e}")
            if self.current_frame:
                self.current_frame.update_status(f"Error: Failed to reconnect to server - {e}")
            return False
        return True

    def show_frame(self, page):
        if self.current_frame == self.frames[RegisterPage]:
            self.frames[RegisterPage].clear_status()
        if self.current_frame == self.frames[LoginPage]:
            self.frames[LoginPage].clear_status()
        if page == ChatPage:
            self.frames[ChatPage].clear_messages()
        self.frames[page].tkraise()
        self.current_frame = self.frames[page]

    def send(self, request):
        if self.token and request.get("type") not in ["REGISTER", "RECOVER"]:
            request["token"] = self.token
        message = json.dumps(request)
        try:
            self.sock.sendall(f"{message}\n".encode('utf-8'))
        except (ConnectionError, OSError) as e:
            if self.reconnect():
                try:
                    self.sock.sendall(f"{message}\n".encode('utf-8'))
                except ConnectionError as e2:
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
                if not data: break
                buffer += data
                while '\n' in buffer:
                    message, buffer = buffer.split('\n', 1)
                    try:
                        response = json.loads(message)
                    except json.JSONDecodeError: continue
                    t = response.get("type")
                    if t == "CHAT":
                        self.frames[ChatPage].append_message(response.get("message"))
                    elif t == "QUESTIONS":
                        self.frames[ForgotPasswordPage].show_questions()
                    elif t == "SUCCESS":
                        msg = response.get("message")
                        if "Login successful" in msg:
                            self.token = msg.split("Token: ")[1]
                            self.frames[LoginPage].update_status("Login successful")
                        else:
                            if self.current_frame:
                                self.current_frame.update_status(msg)
                    elif t == "ERROR":
                        if self.current_frame:
                            self.current_frame.update_status(response.get("message"))
                    elif t == "LOGOUT":
                        self.token = None
                        self.frames[ChatPage].append_message("You have logged out.")
                        self.frames[ChatPage].clear_messages()
                        self.reconnect()
                        self.show_frame(MainPage)
            except (ConnectionError, OSError) as e:
                if self.current_frame:
                    self.current_frame.update_status(f"Error: Connection to server lost - {e}")
                break

# ---------------- UI Frames ----------------

class MainPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=WHITE)
        tk.Label(self, text="PingMe", font=("Arial", 20), bg=WHITE, fg=BLACK).pack(pady=20)
        tk.Label(self, text="Welcome to PingMe", bg=WHITE, fg=BLACK).pack(pady=10)
        tk.Button(self, text="Register", command=lambda: master.show_frame(RegisterPage),
                  bg=GOLDEN_GRIZZLY, fg=BLACK).pack(pady=10)
        tk.Button(self, text="Login", command=lambda: master.show_frame(LoginPage),
                  bg=GOLDEN_GRIZZLY, fg=BLACK).pack(pady=10)
    def update_status(self, msg): pass

class RegisterPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=WHITE)
        tk.Label(self, text="Register", font=("Arial", 20), bg=WHITE, fg=BLACK).pack(pady=10)
        self.status = tk.Label(self, text="", bg=WHITE, fg="red")
        self.status.pack()

        tk.Label(self, text="Note: Save your 2FA code.", fg=BLACK, bg=WHITE).pack(pady=5)
        self.entries = {}
        for label in ["Username", "Password", "What is your pet's name?", "What is your favorite color?"]:
            tk.Label(self, text=label, bg=WHITE, fg=BLACK).pack()
            entry = tk.Entry(self, show="*" if "Password" in label else None)
            entry.pack(pady=2)
            self.entries[label.lower()] = entry

        tk.Button(self, text="Register", command=self.register, bg=GOLDEN_GRIZZLY, fg=BLACK).pack(pady=10)
        tk.Button(self, text="Back", command=lambda: master.show_frame(MainPage),
                  bg=GRAY, fg=BLACK).pack()

    def register(self):
        username = self.entries["username"].get().strip()
        password = self.entries["password"].get().strip()
        answer1 = self.entries["what is your pet's name?"].get().strip()
        answer2 = self.entries["what is your favorite color?"].get().strip()
        if not all([username, password, answer1, answer2]):
            self.update_status("Please fill all fields")
            return
        req = {"type": "REGISTER", "username": username, "password": password,
               "answer1": answer1, "answer2": answer2}
        self.master.send(req)

    def update_status(self, msg): self.status.config(text=msg)
    def clear_status(self): self.status.config(text="")

class LoginPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=WHITE)
        tk.Label(self, text="Login", font=("Arial", 20), bg=WHITE, fg=BLACK).pack(pady=10)
        self.status = tk.Label(self, text="", bg=WHITE, fg="red")
        self.status.pack()

        self.entries = {}
        for label in ["Username", "Password", "2FA Code"]:
            tk.Label(self, text=label, bg=WHITE, fg=BLACK).pack()
            entry = tk.Entry(self, show="*" if "Password" in label else None)
            entry.pack(pady=2)
            self.entries[label.lower()] = entry

        tk.Button(self, text="Login", command=self.login, bg=GOLDEN_GRIZZLY, fg=BLACK).pack(pady=10)
        tk.Button(self, text="Forgot Password?", command=lambda: master.show_frame(ForgotPasswordPage),
                  bg=GRAY, fg=BLACK).pack()
        tk.Button(self, text="Back", command=lambda: master.show_frame(MainPage),
                  bg=GRAY, fg=BLACK).pack()

    def login(self):
        u = self.entries["username"].get().strip()
        p = self.entries["password"].get().strip()
        c = self.entries["2fa code"].get().strip()
        if not all([u, p, c]):
            self.update_status("Please fill all fields")
            return
        self.master.send({"type": "LOGIN", "username": u, "password": p, "two_fa_code": c})

    def update_status(self, msg):
        if "Login successful" in msg:
            self.master.show_frame(ChatPage)
        self.status.config(text=msg)

    def clear_status(self): self.status.config(text="")

class ForgotPasswordPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=WHITE)
        tk.Label(self, text="Forgot Password", font=("Arial", 20), bg=WHITE, fg=BLACK).pack(pady=10)
        self.status = tk.Label(self, text="", bg=WHITE, fg="red")
        self.status.pack()

        self.username_frame = tk.Frame(self, bg=WHITE)
        tk.Label(self.username_frame, text="Enter Username:", bg=WHITE, fg=BLACK).pack()
        self.username_entry = tk.Entry(self.username_frame)
        self.username_entry.pack()
        tk.Button(self.username_frame, text="Submit", command=self.request_questions,
                  bg=GOLDEN_GRIZZLY, fg=BLACK).pack(pady=5)
        self.username_frame.pack()

        self.questions_frame = tk.Frame(self, bg=WHITE)
        tk.Label(self.questions_frame, text="What is your pet's name?", bg=WHITE, fg=BLACK).pack()
        self.answer1_entry = tk.Entry(self.questions_frame)
        self.answer1_entry.pack()
        tk.Label(self.questions_frame, text="What is your favorite color?", bg=WHITE, fg=BLACK).pack()
        self.answer2_entry = tk.Entry(self.questions_frame)
        self.answer2_entry.pack()
        tk.Button(self.questions_frame, text="Verify", command=self.verify_answers,
                  bg=GOLDEN_GRIZZLY, fg=BLACK).pack(pady=5)

        tk.Button(self, text="Back", command=lambda: master.show_frame(MainPage),
                  bg=GRAY, fg=BLACK).pack()

    def request_questions(self):
        u = self.username_entry.get().strip()
        if not u:
            self.status.config(text="Please enter a username")
            return
        self.master.send({"type": "RECOVER", "username": u})

    def show_questions(self):
        self.username_frame.pack_forget()
        self.questions_frame.pack()
        self.status.config(text="Please answer the questions.")

    def verify_answers(self):
        u = self.username_entry.get().strip()
        a1 = self.answer1_entry.get().strip()
        a2 = self.answer2_entry.get().strip()
        if not all([a1, a2]):
            self.status.config(text="Answer both questions")
            return
        self.master.send({"type": "RECOVER", "username": u, "answer1": a1, "answer2": a2})

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
        self.master.send({"type": "CHAT", "message": msg})
        self.entry.delete(0, tk.END)

    def logout(self):
        self.master.send({"type": "LOGOUT"})

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
