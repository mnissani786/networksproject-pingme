import tkinter as tk
from tkinter import messagebox, simpledialog
import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

class PingMeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PingMe")
        self.geometry("400x600")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((HOST, PORT))
        except ConnectionError as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            self.destroy()
            return

        self.frames = {}
        for Page in (MainPage, RegisterPage, LoginPage, ForgotPasswordPage, ChatPage):
            frame = Page(self)
            self.frames[Page] = frame
            frame.place(x=0, y=0, relwidth=1, relheight=1)

        self.show_frame(MainPage)

        self.listen_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        self.listen_thread.start()

    def show_frame(self, page):
        self.frames[page].tkraise()

    def send(self, message):
        self.sock.sendall(message.encode('utf-8'))

    def listen_for_messages(self):
        while True:
            try:
                data = self.sock.recv(1024).decode('utf-8')
                if data.startswith("CHAT"):
                    message = data[5:]
                    self.frames[ChatPage].append_message(message)
                elif data.startswith("QUESTIONS"):
                    self.frames[ForgotPasswordPage].handle_questions(data)
                else:
                    for frame in self.frames.values():
                        frame.update_status(data)
            except:
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
        self.entries = {}
        tk.Label(self, text="Username:").pack()
        self.entries["Username"] = tk.Entry(self)
        self.entries["Username"].pack(pady=2)
        tk.Label(self, text="Password:").pack()
        self.entries["Password"] = tk.Entry(self, show="*")
        self.entries["Password"].pack(pady=2)

        # Security Questions
        tk.Label(self, text="What is your pet's name?").pack()
        self.entries["A1"] = tk.Entry(self)
        self.entries["A1"].pack(pady=2)
        tk.Label(self, text="What is your favorite color?").pack()
        self.entries["A2"] = tk.Entry(self)
        self.entries["A2"].pack(pady=2)

        tk.Button(self, text="Register", command=self.register).pack(pady=10)
        tk.Button(self, text="Back", command=lambda: master.show_frame(MainPage)).pack()

    def register(self):
        username = self.entries["Username"].get().strip().replace(" ", "_")
        password = self.entries["Password"].get().strip().replace(" ", "_")
        q1 = "What_is_your_pet's_name?"
        a1 = self.entries["A1"].get().strip().replace(" ", "_")
        q2 = "What_is_your_favorite_color?"
        a2 = self.entries["A2"].get().strip().replace(" ", "_")

        if all([username, password, a1, a2]):
            command = f"REGISTER {username} {password} {q1} {a1} {q2} {a2}"
            self.master.send(command)
        else:
            self.update_status("Please fill all fields")

    def update_status(self, msg):
        self.status.config(text=msg)

class LoginPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="PingMe", font=("Arial", 20)).pack(pady=10)
        self.status = tk.Label(self, text="")
        self.status.pack()
        self.user = tk.Entry(self)
        self.passw = tk.Entry(self, show="*")
        self.twofa = tk.Entry(self)
        tk.Label(self, text="Username").pack()
        self.user.pack()
        tk.Label(self, text="Password").pack()
        self.passw.pack()
        tk.Label(self, text="2FA Code").pack()
        self.twofa.pack()
        tk.Button(self, text="Login", command=self.login).pack(pady=10)
        tk.Button(self, text="Forgot Password?", command=lambda: master.show_frame(ForgotPasswordPage)).pack()
        tk.Button(self, text="Back", command=lambda: master.show_frame(MainPage)).pack()

    def login(self):
        username = self.user.get().strip().replace(" ", "_")
        password = self.passw.get().strip().replace(" ", "_")
        twofa = self.twofa.get().strip().replace(" ", "_")
        if username and password and twofa:
            self.master.send(f"LOGIN {username} {password} {twofa}")

    def update_status(self, msg):
        if "SUCCESS" in msg:
            self.master.show_frame(ChatPage)
        self.status.config(text=msg)

class ForgotPasswordPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="PingMe", font=("Arial", 20)).pack(pady=10)
        self.status = tk.Label(self, text="")
        self.status.pack()
        self.username_entry = tk.Entry(self)
        tk.Label(self, text="Enter Username").pack()
        self.username_entry.pack()
        tk.Button(self, text="Submit", command=self.request_questions).pack(pady=5)
        self.q1_label = tk.Label(self, text="")
        self.q2_label = tk.Label(self, text="")
        self.a1_entry = tk.Entry(self)
        self.a2_entry = tk.Entry(self)
        self.verify_button = tk.Button(self, text="Verify", command=self.verify_answers)
        self.login_btn = tk.Button(self, text="Login Again", command=lambda: master.show_frame(LoginPage))
        tk.Button(self, text="Back", command=lambda: master.show_frame(MainPage)).pack()

    def request_questions(self):
        username = self.username_entry.get().strip().replace(" ", "_")
        self.master.send(f"RECOVER {username}")

    def handle_questions(self, data):
        parts = data.split()
        self.q1_label.config(text=parts[1].replace("_", " "))
        self.q2_label.config(text=parts[2].replace("_", " "))
        self.q1_label.pack()
        self.a1_entry.pack()
        self.q2_label.pack()
        self.a2_entry.pack()
        self.verify_button.pack()

    def verify_answers(self):
        username = self.username_entry.get().strip().replace(" ", "_")
        a1 = self.a1_entry.get().strip().replace(" ", "_")
        a2 = self.a2_entry.get().strip().replace(" ", "_")
        self.master.send(f"RECOVER VERIFY {username} {a1} {a2}")
        self.login_btn.pack()

    def update_status(self, msg):
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
        if msg:
            self.master.send(f"CHAT {msg}")
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
