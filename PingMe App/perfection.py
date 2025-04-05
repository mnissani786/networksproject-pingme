import tkinter as tk
from tkinter import messagebox
import socket
import threading
import hashlib
import secrets

HOST = '127.0.0.1'
PORT = 65432

# In-memory storage for users and logged in clients
users = {}  # {username: (hashed_password, security_question, security_answer, token)}
logged_in_clients = {}  # {conn: (username, token)}

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PingMe")
        self.root.geometry("375x667")  # Size for iPhone-like display

        self.current_page = None
        self.display_home()

    def display_home(self):
        """Display the home page with Register and Login options."""
        self.clear_window()
        self.current_page = "home"

        tk.Label(self.root, text="Welcome to PingMe", font=("Arial", 20, "bold")).pack(pady=20)

        register_button = tk.Button(self.root, text="Register", width=20, command=self.display_register)
        register_button.pack(pady=10)

        login_button = tk.Button(self.root, text="Login", width=20, command=self.display_login)
        login_button.pack(pady=10)

    def display_register(self):
        """Display the registration page."""
        self.clear_window()
        self.current_page = "register"

        tk.Label(self.root, text="Register", font=("Arial", 18, "bold")).pack(pady=20)

        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root, width=30)
        self.username_entry.pack(pady=5)

        tk.Label(self.root, text="Password:").pack()
        self.password_entry = tk.Entry(self.root, width=30, show="*")
        self.password_entry.pack(pady=5)

        # Security questions
        tk.Label(self.root, text="Security Question:").pack()
        self.security_question_var = tk.StringVar()
        security_questions = [
            "What is your pet's name?",
            "What is your mother's maiden name?",
            "What was the name of your first school?"
        ]
        self.security_question_menu = tk.OptionMenu(self.root, self.security_question_var, *security_questions)
        self.security_question_menu.pack(pady=5)

        tk.Label(self.root, text="Security Answer:").pack()
        self.security_answer_entry = tk.Entry(self.root, width=30)
        self.security_answer_entry.pack(pady=5)

        # Buttons for registration
        register_button = tk.Button(self.root, text="Register", command=self.register_account)
        register_button.pack(pady=10)

        back_button = tk.Button(self.root, text="Back", command=self.display_home)
        back_button.pack(pady=10)

    def register_account(self):
        """Handle account registration."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        security_answer = self.security_answer_entry.get().strip()

        if username and password and security_answer:
            # Hash the password
            hashed_pw = hash_password(password)

            # Store the user in the dictionary with the security question and answer
            users[username] = (hashed_pw, self.security_question_var.get(), security_answer, None)

            # Proceed to chat screen after registration
            self.display_chat()
        else:
            messagebox.showerror("Input Error", "Please fill in all fields.")

    def display_login(self):
        """Display the login page."""
        self.clear_window()
        self.current_page = "login"

        tk.Label(self.root, text="Login", font=("Arial", 18, "bold")).pack(pady=20)

        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root, width=30)
        self.username_entry.pack(pady=5)

        tk.Label(self.root, text="Password:").pack()
        self.password_entry = tk.Entry(self.root, width=30, show="*")
        self.password_entry.pack(pady=5)

        # Buttons for login
        login_button = tk.Button(self.root, text="Login", command=self.login_account)
        login_button.pack(pady=10)

        recovery_button = tk.Button(self.root, text="Forgot Password", command=self.display_recovery)
        recovery_button.pack(pady=5)

        back_button = tk.Button(self.root, text="Back", command=self.display_home)
        back_button.pack(pady=10)

    def login_account(self):
        """Handle login."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if username in users and users[username][0] == hash_password(password):
            token = secrets.token_hex(16)
            users[username] = (users[username][0], users[username][1], users[username][2], token)
            logged_in_clients[username] = (username, token)  # Add to logged-in clients

            # Proceed to chat screen after login
            self.display_chat()
        else:
            messagebox.showerror("Login Error", "Invalid username or password.")

    def display_recovery(self):
        """Display the recovery page."""
        self.clear_window()
        self.current_page = "recovery"

        tk.Label(self.root, text="Password Recovery", font=("Arial", 18, "bold")).pack(pady=20)

        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root, width=30)
        self.username_entry.pack(pady=5)

        recover_button = tk.Button(self.root, text="Recover", command=self.ask_security_question)
        recover_button.pack(pady=10)

        back_button = tk.Button(self.root, text="Back", command=self.display_home)
        back_button.pack(pady=10)

    def ask_security_question(self):
        """Ask the corresponding security question."""
        username = self.username_entry.get().strip()

        if username in users:
            question = users[username][1]
            self.clear_window()

            tk.Label(self.root, text="Answer Security Question", font=("Arial", 18, "bold")).pack(pady=20)
            tk.Label(self.root, text=question).pack()

            self.security_answer_entry = tk.Entry(self.root, width=30)
            self.security_answer_entry.pack(pady=5)

            submit_button = tk.Button(self.root, text="Submit", command=lambda: self.check_security_answer(username))
            submit_button.pack(pady=10)

            back_button = tk.Button(self.root, text="Back", command=self.display_home)
            back_button.pack(pady=10)
        else:
            messagebox.showerror("Error", "Username not found.")

    def check_security_answer(self, username):
        """Check if the security answer is correct."""
        answer = self.security_answer_entry.get().strip()
        if answer == users[username][2]:
            self.reset_password(username)
        else:
            messagebox.showerror("Error", "Incorrect security answer.")

    def reset_password(self, username):
        """Allow user to reset their password."""
        self.clear_window()

        tk.Label(self.root, text="Set New Password", font=("Arial", 18, "bold")).pack(pady=20)

        tk.Label(self.root, text="New Password:").pack()
        self.password_entry = tk.Entry(self.root, width=30, show="*")
        self.password_entry.pack(pady=5)

        set_button = tk.Button(self.root, text="Set Password", command=lambda: self.set_new_password(username))
        set_button.pack(pady=10)

        back_button = tk.Button(self.root, text="Back", command=self.display_home)
        back_button.pack(pady=10)

    def set_new_password(self, username):
        """Set the new password."""
        new_password = self.password_entry.get().strip()
        if new_password:
            hashed_pw = hash_password(new_password)
            users[username] = (hashed_pw, users[username][1], users[username][2], None)  # Update password
            messagebox.showinfo("Success", "Password reset successful.")
            self.display_login()
        else:
            messagebox.showerror("Error", "Please enter a valid password.")

    def display_chat(self):
        """Display the chat screen."""
        self.clear_window()
        self.current_page = "chat"

        tk.Label(self.root, text="Chat", font=("Arial", 18, "bold")).pack(pady=20)

        self.chat_display = tk.Text(self.root, height=10, width=40, state='disabled')
        self.chat_display.pack(pady=10)

        chat_frame = tk.Frame(self.root)
        chat_frame.pack(pady=5)

        self.chat_entry = tk.Entry(chat_frame, width=30)
        self.chat_entry.pack(side=tk.LEFT, padx=5)

        send_button = tk.Button(chat_frame, text="Send", command=self.send_chat)
        send_button.pack(side=tk.LEFT)

        logout_button = tk.Button(self.root, text="Logout", command=self.logout)
        logout_button.pack(pady=10)

    def send_chat(self):
        """Send a chat message."""
        message = self.chat_entry.get().strip()
        if message:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, "You: " + message + "\n")
            self.chat_display.config(state='disabled')
            self.chat_entry.delete(0, tk.END)

    def logout(self):
        """Handle logout."""
        self.display_home()

    def clear_window(self):
        """Clear all widgets in the window."""
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
