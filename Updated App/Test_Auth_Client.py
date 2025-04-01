import tkinter as tk
from tkinter import messagebox
import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PingMe")
        self.root.geometry("400x500")  

        # Initialize socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((HOST, PORT))
        except ConnectionError as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            self.root.destroy()
            return

        # GUI Layout
        tk.Label(root, text="Authentication & Chat", font=("Arial", 14, "bold")).pack(pady=10)

        # Username
        tk.Label(root, text="Username:").pack()
        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.pack(pady=5)

        # Password
        tk.Label(root, text="Password:").pack()
        self.password_entry = tk.Entry(root, width=30, show="*")
        self.password_entry.pack(pady=5)

        # Auth Buttons
        auth_frame = tk.Frame(root)
        auth_frame.pack(pady=10)
        tk.Button(auth_frame, text="Register", command=self.register).pack(side=tk.LEFT, padx=5)
        tk.Button(auth_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=5)
        tk.Button(auth_frame, text="Recover", command=self.recover).pack(side=tk.LEFT, padx=5)

        # Status display
        self.status_label = tk.Label(root, text="Status: Ready", wraplength=350, justify="center")
        self.status_label.pack(pady=10)

        # Chat section
        tk.Label(root, text="Chat (Login Required):").pack()
        self.chat_display = tk.Text(root, height=10, width=40, state='disabled')
        self.chat_display.pack(pady=5)
       
        chat_frame = tk.Frame(root)
        chat_frame.pack(pady=5)
        self.chat_entry = tk.Entry(chat_frame, width=25)
        self.chat_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(chat_frame, text="Send", command=self.send_chat).pack(side=tk.LEFT)

        # Start listening for server responses
        self.running = True
        self.listen_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        self.listen_thread.start()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def send_command(self, command):
        """Send a command to the server."""
        try:
            self.sock.sendall(command.encode('utf-8'))
        except ConnectionError as e:
            self.status_label.config(text=f"Error: Connection lost - {e}")

    def listen_for_messages(self):
        """Listen for server responses and update GUI."""
        while self.running:
            try:
                data = self.sock.recv(1024).decode('utf-8')
                if not data:
                    self.status_label.config(text="Error: Server disconnected")
                    break
                if data.startswith("CHAT"):
                    chat_message = data[5:]  # Remove "CHAT " prefix
                    self.display_chat_message(chat_message)  # Show message correctly
                else:
                    self.status_label.config(text=data)
            except ConnectionError:
                self.status_label.config(text="Error: Connection lost")
                break

    def register(self):
        """Handle register button click."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if username and password:
            self.send_command(f"REGISTER {username} {password}")
        else:
            messagebox.showerror("Input Error", "Please fill in both username and password")

    def login(self):
        """Handle login button click."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if username and password:
            self.send_command(f"LOGIN {username} {password}")
        else:
            messagebox.showerror("Input Error", "Please fill in both username and password")

    def recover(self):
        """Handle recover password button click."""
        username = self.username_entry.get().strip()
        if username:
            self.send_command(f"RECOVER {username}")
        else:
            messagebox.showerror("Input Error", "Please enter a username")

    def send_chat(self):
        """Handle chat message send."""
        message = self.chat_entry.get().strip()
        if message:
            self.send_command(f"CHAT {message}")  # Send raw message (server formats it)
            self.chat_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Chat Error", "Please enter a message")

    def display_chat_message(self, message):
        """Display a chat message in the chat window."""
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)  # Auto-scroll to latest message

    # def send_chat(self):
    #     """Handle chat message send."""
    #     message = self.chat_entry.get().strip()
    #     if message:
    #         self.send_command(f"CHAT {message}")
    #         self.chat_entry.delete(0, tk.END)
    #     else:
    #         messagebox.showwarning("Chat Error", "Please enter a message")

    def on_closing(self):
        """Clean up on window close."""
        self.running = False
        self.sock.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()