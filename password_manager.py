import sqlite3
from cryptography.fernet import Fernet
import os
import hashlib
import random
import string
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext

# Secure encryption key generation
def generate_key():
    return Fernet.generate_key()

# Save key securely (in a real-world application, this should be done securely)
def load_key():
    return open("secret.key", "rb").read()

# Encrypt the password
def encrypt_password(fernet, password):
    return fernet.encrypt(password.encode()).decode()

# Decrypt the password
def decrypt_password(fernet, encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

# Generate a strong, unique password
def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# User authentication using a hash function
def authenticate_user(role, password):
    file_name = f"{role}.hash"
    if not os.path.exists(file_name):
        return False
    
    stored_hash = open(file_name, "r").read()
    entered_hash = hashlib.sha256(password.encode()).hexdigest()

    return entered_hash == stored_hash

# Initialize database
def init_db():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       service TEXT NOT NULL,
                       username TEXT NOT NULL,
                       password TEXT NOT NULL);''')
    conn.commit()
    conn.close()

# Add a new password
def add_password(service, username, password):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    encrypted_password = encrypt_password(fernet, password)
    cursor.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                   (service, username, encrypted_password))
    conn.commit()
    conn.close()

# Retrieve passwords for a service
def retrieve_passwords(service):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM passwords WHERE service=?", (service,))
    records = cursor.fetchall()
    conn.close()
    
    if records:
        return [(username, decrypt_password(fernet, password)) for username, password in records]
    else:
        return []

# Edit an existing password
def edit_password(service, username, new_password):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    encrypted_password = encrypt_password(fernet, new_password)
    cursor.execute("UPDATE passwords SET password=? WHERE service=? AND username=?", 
                   (encrypted_password, service, username))
    conn.commit()
    conn.close()

# Delete a password
def delete_password(service, username):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE service=? AND username=?", (service, username))
    conn.commit()
    conn.close()

# Function to set the initial password
def set_initial_password(role):
    password = simpledialog.askstring("Set Password", f"Set password for {role.capitalize()}:", show="*")
    if password:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        with open(f"{role}.hash", "w") as file:
            file.write(password_hash)
        messagebox.showinfo("Success", f"{role.capitalize()} password set successfully!")

# GUI for Login
class LoginApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Login")
        self.master.geometry("300x200")
        
        self.label = tk.Label(master, text="Login as Host or User", font=("Arial", 14))
        self.label.pack(pady=10)

        self.role_var = tk.StringVar(value="user")

        self.radio_host = tk.Radiobutton(master, text="Host", variable=self.role_var, value="host")
        self.radio_host.pack(anchor=tk.W)

        self.radio_user = tk.Radiobutton(master, text="User", variable=self.role_var, value="user")
        self.radio_user.pack(anchor=tk.W)

        self.password_label = tk.Label(master, text="Password")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.pack(pady=5)

        self.login_button = tk.Button(master, text="Login", command=self.login)
        self.login_button.pack(pady=10)
    
    def login(self):
        role = self.role_var.get()
        password = self.password_entry.get()

        # Check if it's the first run and set initial password if necessary
        if not os.path.exists(f"{role}.hash"):
            set_initial_password(role)
        
        if authenticate_user(role, password):
            messagebox.showinfo("Login Successful", f"Logged in as {role.capitalize()}")
            self.master.destroy()
            root = tk.Tk()
            app = PasswordManagerApp(root, role)
            root.mainloop()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials. Please try again.")

# GUI for Password Manager
class PasswordManagerApp:
    def __init__(self, master, role):
        self.master = master
        self.role = role
        self.master.title("Password Manager")
        self.master.geometry("400x500")
        
        self.setup_gui()
    
    def setup_gui(self):
        self.label = tk.Label(self.master, text="Password Manager", font=("Arial", 16))
        self.label.pack(pady=10)
        
        self.service_label = tk.Label(self.master, text="Service Name")
        self.service_label.pack(pady=5)
        self.service_entry = tk.Entry(self.master)
        self.service_entry.pack(pady=5)

        self.username_label = tk.Label(self.master, text="Username")
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(self.master)
        self.username_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.master, text="Password")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.master, show="*")
        self.password_entry.pack(pady=5)

        self.add_button = tk.Button(self.master, text="Add Password", command=self.add_password)
        self.add_button.pack(pady=5)

        self.retrieve_button = tk.Button(self.master, text="Retrieve Passwords", command=self.retrieve_passwords)
        self.retrieve_button.pack(pady=5)

        if self.role == "host":
            self.edit_button = tk.Button(self.master, text="Edit Password", command=self.edit_password)
            self.edit_button.pack(pady=5)
            self.delete_button = tk.Button(self.master, text="Delete Password", command=self.delete_password)
            self.delete_button.pack(pady=5)

        self.generate_button = tk.Button(self.master, text="Generate Strong Password", command=self.generate_password)
        self.generate_button.pack(pady=5)

        self.logout_button = tk.Button(self.master, text="Logout", command=self.logout)
        self.logout_button.pack(pady=10)
        
        self.display_area = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, width=40, height=10)
        self.display_area.pack(pady=10)

    def add_password(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not service or not username or not password:
            messagebox.showerror("Error", "All fields must be filled!")
            return
        
        add_password(service, username, password)
        messagebox.showinfo("Success", "Password added successfully!")
        self.clear_entries()

    def retrieve_passwords(self):
        service = self.service_entry.get()
        passwords = retrieve_passwords(service)
        
        self.display_area.delete(1.0, tk.END)
        if passwords:
            for idx, (username, password) in enumerate(passwords, 1):
                self.display_area.insert(tk.END, f"{idx}. Username: {username}, Password: {password}\n")
        else:
            self.display_area.insert(tk.END, "No passwords found for this service.")

    def edit_password(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        new_password = simpledialog.askstring("New Password", "Enter the new password:", show="*")
        
        if new_password:
            edit_password(service, username, new_password)
            messagebox.showinfo("Success", "Password updated successfully!")
            self.clear_entries()

    def delete_password(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        
        delete_password(service, username)
        messagebox.showinfo("Success", "Password deleted successfully!")
        self.clear_entries()

    def generate_password(self):
        length = simpledialog.askinteger("Password Length", "Enter desired password length:")
        if length:
            strong_password = generate_strong_password(length)
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, strong_password)
            messagebox.showinfo("Generated Password", f"Strong password: {strong_password}")

    def logout(self):
        self.master.destroy()
        root = tk.Tk()
        login_app = LoginApp(root)
        root.mainloop()

    def clear_entries(self):
        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)


def main():
    global fernet
    
    # Load the encryption key (generate and save a new key only once)
    if not os.path.exists("secret.key"):
        with open("secret.key", "wb") as key_file:
            key_file.write(generate_key())

    fernet = Fernet(load_key())
    
    init_db()

    root = tk.Tk()
    login_app = LoginApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
