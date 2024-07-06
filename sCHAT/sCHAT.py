import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import os,sys
import base64
import shutil
import pystray
from PIL import Image, ImageDraw
from tkinter import ttk, scrolledtext
from pystray import MenuItem as item
import ctypes
 # Server configuration
HOST = '10.12.1.65'
PORT = 4321
client = None
username = ''
online_users = []

lock_file_path = "app.lock"

def hide_file(file_path):
    try:
        if os.path.exists(file_path):
            ctypes.windll.kernel32.SetFileAttributesW(file_path, 2)  # Hide the file by setting attribute to hidden
    except Exception as e:
        print(f"Error hiding file: {e}")

def check_if_already_running():
    if os.path.exists(lock_file_path):
        messagebox.showerror("Error", "Another instance of the application is already running.")
        sys.exit()
    else:
        with open(lock_file_path, 'w') as lock_file:
            lock_file.write("Lock file created")
        # Hide the lock file
        hide_file(lock_file_path)
    
def add_message(message, color="white"):
    message_box.config(state=tk.NORMAL)
    
    # Create a unique tag for each message
    tag_name = f"tag_{message_box.index(tk.END)}"
    message_box.insert(tk.END, message + '\n', (tag_name,))
    message_box.tag_config(tag_name, foreground=color)
    
    message_box.config(state=tk.DISABLED)

def connect():
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((HOST, PORT))
        authenticate()
        add_message("[CLIENT] Successfully connected to the server")
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect to the server: {e}")
        return

def authenticate(event=None):
    global username
    global password
    username = username_textbox.get()
    password = password_textbox.get()
    print(username,password)
    if username == '' or password == '':
        messagebox.showerror("Invalid credentials", "Username or password cannot be empty")
        return
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    credentials = f"{username}~{password}~{ip_address}"
    print(credentials)
    try:
        client.sendall(credentials.encode())
        response = client.recv(1024).decode('utf-8')
        print(response)
    except Exception as e:
        messagebox.showerror("Authentication Error", f"Failed to send credentials: {e}")
        return

    if response == "[SERVER] Login successful":
        add_message("[SERVER] Login successful")
        threading.Thread(target=listen_for_messages_from_server, args=(client,)).start()
        username_textbox.config(state=tk.DISABLED)
        password_textbox.config(state=tk.DISABLED)
        connect_button.config(state=tk.DISABLED)
        show_chatroom()
        request_profile_details()  # Request profile details after successful authentication
    else:
        messagebox.showerror("Invalid credentials", response)
        username_textbox.delete(0, tk.END)
        password_textbox.delete(0, tk.END)
        username_textbox.focus_set()
        return

def request_profile_details():
    try:
        client.sendall(f"profile_request~{username}".encode())
    except Exception as e:
        messagebox.showerror("Profile Request Error", f"Failed to request profile details: {e}")

def create_image():
    # Generate an image for the icon
    width = 64
    height = 64
    image = Image.new('RGB', (width, height), color1 := (0, 0, 0))

    # Draw a square
    dc = ImageDraw.Draw(image)
    dc.rectangle(
        (width // 2 - 10, height // 2 - 10, width // 2 + 10, height // 2 + 10),
        fill=(255, 255, 255))

    return image

def minimize_to_tray():
    root.withdraw()
    image = create_image()
    menu = (item('Show', show_window), item('Quit', on_closing))
    global icon
    icon = pystray.Icon("s-CHAT", image, "s-CHAT", menu)
    icon.run()

def show_window(icon, item):
    icon.stop()
    root.after(0, root.deiconify)

def on_quit(icon, item):
    icon.stop()
    root.quit()
    
def popup_if_minimized():
    if root.state() == 'iconic':
        root.deiconify()
        root.lift()
        root.attributes('-topmost', True)
        root.after(500, lambda: root.attributes('-topmost', False))
    elif not root.winfo_viewable():
        root.deiconify()
        root.lift()
        root.attributes('-topmost', True)
        root.after(500, lambda: root.attributes('-topmost', False))

def send_message(event=None):  
    message = message_textbox.get("1.0", tk.END).strip()  
    recipient = recipient_listbox.get(tk.ACTIVE)
    recp=recipient.split(' ')
    if username==recp[0]:
        return
    if message and recipient:
        try:
            msg = f"[{recp[0]}] {message}"
            recp=recipient.split(" ")
            if username!=recp[0]:
                add_message(msg, "green")
            
             
            client.sendall(f"msg~{username}~{recipient}~{message}".encode())
            message_textbox.delete("1.0", tk.END)  # Corrected the delete method
        except Exception as e:
            tk.messagebox.showerror("Send Error", f"Failed to send message: {e}")
    else:
        tk.messagebox.showerror("Empty message", "Message cannot be empty or recipient not selected")


def send_file(client, recipient_listbox):
    file_path = filedialog.askopenfilename()
    recipient = recipient_listbox.get(tk.ACTIVE)
    if file_path and recipient:
        try:
            with open(file_path, 'rb') as file:
                file_name = os.path.basename(file_path)
                chunk_size = 4096  # Size of each chunk
                while True:
                    file_data = file.read(chunk_size)
                    if not file_data:
                        break
                    file_data_encoded = base64.b64encode(file_data).decode('utf-8')
                    is_last_chunk = 1 if len(file_data) < chunk_size else 0
                    message = f"file~{recipient}~{file_name}~{file_data_encoded}~{is_last_chunk}~\n"
                    client.sendall(message.encode('utf-8'))
                    print(f"Sent message: {message}")
                add_message(f"[CLIENT] File '{file_name}' has been sent to {recipient}.")
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send file: {e}")
    else:
        messagebox.showerror("File/Recipient Error", "File or recipient not selected")

        
def logout():
    if client is not None:
        try:
            client.sendall("!logout".encode())
        except Exception as e:
            print(f"Error sending logout message: {e}")
        
        try:
            client.close()
        except Exception as e:
            print(f"Error closing client socket: {e}")
    else:
        print("Client socket is not initialized.")
        root.destroy()
    
    reset_gui_to_login()

def reset_gui_to_login():
    chatroom_frame.grid_remove()
    login_frame.grid()
    username_textbox.config(state=tk.NORMAL)
    password_textbox.config(state=tk.NORMAL)
    connect_button.config(state=tk.NORMAL)
    username_textbox.delete(0, tk.END)
    password_textbox.delete(0, tk.END)
    clear_chatroom_data()

def clear_chatroom_data():
    message_box.config(state=tk.NORMAL)
    message_box.delete("1.0", tk.END)
    message_box.config(state=tk.DISABLED)
    message_textbox.delete("1.0", tk.END)

def delete_lock_file():
    try:
        if os.path.exists("app.lock"):
            os.remove("app.lock")
            print('1')
    except Exception as e:
        print(f"Error deleting lock file: {e}")

def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit? You will get logged out!"):
        delete_lock_file()
        logout()
        root.destroy()
        

received_files = {}  # Dictionary to store file parts for each file being received

def handle_received_file(message):
    try:
        # Unpack the message
        _, file_name, file_data = message.split("~", 2)
        # Decode the file data from Base64
        file_data = base64.b64decode(file_data + '=' * (-len(file_data) % 4))

        # Add the chunk to the received files dictionary
        if file_name not in received_files:
            received_files[file_name] = b''
        received_files[file_name] += file_data

        # Check if the file is complete (in this example, assume single message files)
        file_ext = os.path.splitext(file_name)[1]
        file_types = [(f"{file_ext.upper()} Files", f"*{file_ext}"), ("All Files", "*.*")]
        save_path = filedialog.asksaveasfilename(defaultextension=file_ext, initialfile=file_name, filetypes=file_types)
        
        if save_path:
            with open(save_path, 'wb') as file:
                file.write(received_files[file_name])
            add_message(f"File received: {file_name} saved as {save_path}")
        else:
            add_message("File transfer canceled by the user")
        
        # Remove the entry from the dictionary
        del received_files[file_name]
    except ValueError as e:
        add_message(f"Error: {e} - message format is incorrect")
    except Exception as e:
        add_message(f"Error handling received file: {e}")


def handle_received_directory(message):
    _, zip_name, zip_data = message.split("~", 2)
    zip_data = base64.b64decode(zip_data)
    save_path = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("ZIP Files", ".zip"), ("All Files", ".*")])
    if save_path:
        with open(save_path, 'wb') as file:
            file.write(zip_data)
        unzip_path = filedialog.askdirectory(title="Select Directory to Extract Files")
        if unzip_path:
            shutil.unpack_archive(save_path, unzip_path)
            add_message(f"Directory received: {zip_name} extracted to {unzip_path}")
        else:
            add_message("Directory extraction canceled by the user")
    else:
        add_message("Directory transfer canceled by the user")

def listen_for_messages_from_server(client):
    while True:
        try:
            chunks = []
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if len(chunk) < 4096:
                    break
            message = b''.join(chunks).decode('utf-8').strip()
            print(message)
            if message:
                if message.startswith("users"):
                    update_online_users(message)
                elif message.startswith("directory"):
                    handle_received_directory(message)
                elif message.startswith("file"):
                    popup_if_minimized()
                    handle_received_file(message)
                elif message.startswith("profile_response"):
                    handle_profile_response(message)
                elif message == "[SERVER] Password changed successfully":
                    messagebox.showinfo("Success", "Password changed successfully")
                    back_to_profile()
                elif message == "[SERVER] Error: Incorrect current password":
                    messagebox.showerror("Error", "Incorrect current password")
                    current_password_entry.delete(0, tk.END)
                elif message.startswith("[SERVER]"):
                    add_message(message)
                    if message == "[SERVER] Logout successful":
                        try:
                            client.close()
                        except Exception as e:
                            print(f"Error closing client socket after logout: {e}")
                        reset_gui_to_login()
                        break
                else:
                    sender, content = message.split("~", 1)
                    add_message(f"[{sender}] {content}")
                    popup_if_minimized()
            else:
                messagebox.showerror("Error", "Message received from the server is empty")
                break
        except Exception as e:
            print(f"Error: {e}")
            break
        
def handle_profile_response(message):
    _, user, dept, desig, masked_pwd = message.split("~")
    new_username_textbox.config(text=user)
    new_department_textbox.config(text=dept)
    new_designation_textbox.config(text=desig)
    new_password_textbox.config(text=masked_pwd)
    
def show_chatroom():
    login_frame.grid_remove()
    chatroom_frame.grid()

def update_online_users(message):
    global online_users
    parts = message.split("~")

    users = parts[1:]
    online_users = users
    selected_department = department_combobox.get()
    print(f"Updated online users: {online_users}")
    recipient_listbox.delete(0, tk.END)
    for user in online_users:
        if selected_department == 'All Departments' or user.endswith(selected_department):
            recipient_listbox.insert(tk.END, user)

def change_password_show():
    profile_frame.grid_remove()
    change_password_frame.grid()
    
def change_password():
    current_password = current_password_entry.get()
    new_password = new_password_entry.get()
    confirm_password = confirm_password_entry.get()

    if current_password == "" or new_password == "" or confirm_password == "":
        messagebox.showerror("Error", "All fields are required")
        return

    if new_password == current_password:
        messagebox.showerror("Error", "New password cannot be the same as the current password")
        return

    if new_password != confirm_password:
        messagebox.showerror("Error", "New password and confirm password do not match")
        new_password_entry.delete(0,tk.END)
        confirm_password_entry.delete(0,tk.END)
        return

    try:
        client.sendall(f"change_password~{username}~{current_password}~{new_password}".encode())     
    except Exception as e:
        messagebox.showerror("Error", f"Failed to change password: {e}")

def back_to_chatroom():
    profile_frame.grid_remove()
    chatroom_frame.grid()

def on_clear():
    clear_and_add_placeholder(username_textbox, "Enter Username")
    clear_and_add_placeholder(password_textbox, "Enter Password")
    root.focus()

def clear_and_add_placeholder(entry, placeholder):
    entry.delete(0, tk.END)
    set_placeholder(entry, placeholder)

def show_profile():
    chatroom_frame.grid_remove()
    profile_frame.grid()
        
def mask_password():
    if len(password) <= 2:
        return password
    return '*' * (len(password) - 2) + password[-2:]

def back_to_profile():
    change_password_frame.grid_remove()
    profile_frame.grid()
    current_password_entry.delete(0,tk.END)
    new_password_entry.delete(0,tk.END)
    confirm_password_entry.delete(0,tk.END)
    request_profile_details()

def set_placeholder(entry, placeholder):
    entry.insert(0, placeholder)
    entry.bind("<FocusIn>", lambda event: clear_placeholder(event, placeholder))
    entry.bind("<FocusOut>", lambda event: add_placeholder(event, placeholder))
    entry.config(foreground='grey')

def clear_placeholder(event, placeholder):
    entry = event.widget
    if entry.get() == placeholder:
        entry.delete(0, tk.END)
        entry.config(foreground=ENTRY_FG_COLOR, show='*'  if entry == password_textbox else '')

def add_placeholder(event, placeholder):
    entry = event.widget
    if entry.get() == "":
        entry.insert(0, placeholder)
        entry.config(foreground='grey', show='' if entry == password_textbox else '')

def expand_textbox(event):
    message_textbox.config(height=4)

def contract_textbox(event):
    if event.keysym == 'Return' and event.state & 0x0001:  # Shift key pressed
        message_textbox.insert(tk.END, '\n')
    else:
        message_textbox.config(height=1)
        send_message()
        

root = tk.Tk()
root.title("sCHAT")
FONT = ("Verdana", 12)
BUTTON_FONT = ("Verdana", 10, "bold")
SMALL_FONT = ("Verdana", 10)
BACKGROUND_COLOR = "#2E3440"
FOREGROUND_COLOR = "#D8DEE9"
BUTTON_COLOR = "#81A1C1"
ENTRY_BG_COLOR = "#3B4252"
ENTRY_FG_COLOR = "#ECEFF4"
BORDER_COLOR = "#4C566A"
LHS_FONT = ("Verdana", 10, "bold")
RHS_FONT = ("Arial", 10)

# Style configuration
style = ttk.Style()
style.theme_use('clam')
style.configure('TFrame', background=BACKGROUND_COLOR)
style.configure('TLabel', background=BACKGROUND_COLOR, foreground=FOREGROUND_COLOR, font=FONT)
style.configure('TButton', background=BUTTON_COLOR, foreground=FOREGROUND_COLOR, font=BUTTON_FONT, padding=5)
style.configure('TEntry', fieldbackground=ENTRY_BG_COLOR, foreground=ENTRY_FG_COLOR, insertcolor=FOREGROUND_COLOR, padding=5)
style.map('TButton', background=[('active', BUTTON_COLOR)], foreground=[('active', FOREGROUND_COLOR)])

# Custom style for rounded corners
style.configure('Rounded.TFrame', relief='flat', borderwidth=1, background=BACKGROUND_COLOR)
style.map('Rounded.TFrame', background=[('active', BACKGROUND_COLOR)], relief=[('active', 'flat')])

# Get screen dimensions
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate window dimensions (2/5 width, 2/3 height)
window_width = int(screen_width * 0.4)
window_height = int(screen_height * 0.67)

# Center the window on the screen
x_position = (screen_width - window_width) // 2
y_position = (screen_height - window_height) // 2
root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)
root.bind("<Unmap>", lambda event: minimize_to_tray() if root.state() == 'iconic' else None)

# Main frame
main_frame = ttk.Frame(root, style='Rounded.TFrame')
main_frame.grid(row=0, column=0, sticky='nsew')
main_frame.grid_rowconfigure(0, weight=1)
main_frame.grid_columnconfigure(0, weight=1)

# Outer frame for the border and heading
outer_frame = ttk.Frame(main_frame, style='Rounded.TFrame', padding=20)
outer_frame.grid(row=0, column=0)
outer_frame.grid_rowconfigure(0, weight=0)
outer_frame.grid_rowconfigure(1, weight=1)
outer_frame.grid_columnconfigure(0, weight=1)

# Heading
heading_label = ttk.Label(outer_frame, text="SIGN-IN", font=("Verdana", 16, "bold"), background=BACKGROUND_COLOR, foreground=FOREGROUND_COLOR)
heading_label.grid(row=0, column=0, pady=10)

# Login frame
login_frame = ttk.Frame(outer_frame, style='Rounded.TFrame', padding=10)
login_frame.grid(row=1, column=0, pady=5)

# Create username textbox with placeholder
username_textbox = ttk.Entry(login_frame, font=FONT, width=23)
username_textbox.grid(row=0, column=0, pady=5)
set_placeholder(username_textbox, "Enter Username")

# Create password textbox with placeholder
password_textbox = ttk.Entry(login_frame, font=FONT, show='', width=23)
password_textbox.grid(row=1, column=0, pady=5)
set_placeholder(password_textbox, "Enter Password")

# Add button frame
button_frame_login = ttk.Frame(login_frame)
button_frame_login.grid(row=2, column=0, pady=5)

connect_button = ttk.Button(button_frame_login, text="Connect", command=connect)
connect_button.pack(side=tk.LEFT, padx=5)

show_register_button = ttk.Button(button_frame_login, text="Clear", command=on_clear)
show_register_button.pack(side=tk.LEFT, padx=5)

login_frame.bind('<Return>', authenticate)

# Profile frame
profile_frame = ttk.Frame(outer_frame, style='Rounded.TFrame', padding=15)
profile_frame.grid(row=1, column=0, pady=10)
profile_frame.grid_remove()

for i in range(6):
    profile_frame.grid_rowconfigure(i, weight=1, pad=10)
profile_frame.grid_columnconfigure(0, weight=1, pad=10)
profile_frame.grid_columnconfigure(1, weight=1, pad=10)

# Heading for profile frame
profile_heading_label = ttk.Label(profile_frame, text="Profile Information", font=("Verdana", 16, "bold"))
profile_heading_label.grid(row=0, column=0, columnspan=2, pady=10)

new_username_label = ttk.Label(profile_frame, text="Username: ")
new_username_label.grid(row=1, column=0, pady=10, padx=10, sticky='e')

new_username_textbox = ttk.Label(profile_frame, text=username)
new_username_textbox.grid(row=1, column=1, pady=10, padx=10, sticky='w')

masked_password = ""  # Initialize masked_password as an empty string
new_password_label = ttk.Label(profile_frame, text="Password: ")
new_password_label.grid(row=2, column=0, pady=10, padx=10, sticky='e')

new_password_textbox = ttk.Label(profile_frame, text=masked_password)
new_password_textbox.grid(row=2, column=1, pady=10, padx=10, sticky='w')

desig = ""
new_designation_label = ttk.Label(profile_frame, text="Designation: ")
new_designation_label.grid(row=3, column=0, pady=10, padx=10, sticky='e')

new_designation_textbox = ttk.Label(profile_frame, text=desig)
new_designation_textbox.grid(row=3, column=1, pady=10, padx=10, sticky='w')

dept = ""
new_department_label = ttk.Label(profile_frame, text="Department: ")
new_department_label.grid(row=4, column=0, pady=10, padx=10, sticky='e')

new_department_textbox = ttk.Label(profile_frame, text=dept)
new_department_textbox.grid(row=4, column=1, pady=10, padx=10, sticky='w')

# Button frame for profile frame
button_frame_profile = ttk.Frame(profile_frame, style='Rounded.TFrame', padding=15)
button_frame_profile.grid(row=5, column=0, columnspan=2, pady=10)

change_password_button = ttk.Button(button_frame_profile, text="Change Password", command=change_password_show)
change_password_button.pack(side=tk.LEFT, padx=10)

back_button_profile = ttk.Button(button_frame_profile, text="Back", command=back_to_chatroom)
back_button_profile.pack(side=tk.LEFT, padx=10)

# Change password frame
change_password_frame = ttk.Frame(outer_frame, style='Rounded.TFrame', padding=15)
change_password_frame.grid(row=1, column=0, pady=10)
change_password_frame.grid_remove()

for i in range(4):
    change_password_frame.grid_rowconfigure(i, weight=1, pad=10)
change_password_frame.grid_columnconfigure(0, weight=1, pad=10)
change_password_frame.grid_columnconfigure(1, weight=1, pad=10)

# Heading for change password frame
change_password_heading_label = ttk.Label(change_password_frame, text="Change Password", font=("Verdana", 16, "bold"))
change_password_heading_label.grid(row=0, column=0, columnspan=2, pady=10)

current_password_label = ttk.Label(change_password_frame, text="Current Password")
current_password_label.grid(row=1, column=0, sticky='e', padx=10, pady=10)
current_password_entry = ttk.Entry(change_password_frame, show='*')
current_password_entry.grid(row=1, column=1, sticky='w', padx=10, pady=10)

new_password_label = ttk.Label(change_password_frame, text="New Password")
new_password_label.grid(row=2, column=0, sticky='e', padx=10, pady=10)
new_password_entry = ttk.Entry(change_password_frame, show='*')
new_password_entry.grid(row=2, column=1, sticky='w', padx=10, pady=10)

confirm_password_label = ttk.Label(change_password_frame, text="Confirm New Password")
confirm_password_label.grid(row=3, column=0, sticky='e', padx=10, pady=10)
confirm_password_entry = ttk.Entry(change_password_frame, show='*')
confirm_password_entry.grid(row=3, column=1, sticky='w', padx=10, pady=10)

# Button frame for change password frame
button_frame_change_password = ttk.Frame(change_password_frame, style='Rounded.TFrame', padding=15)
button_frame_change_password.grid(row=4, column=0, columnspan=2, pady=10)

change_password_button = ttk.Button(button_frame_change_password, text="Change Password", command=change_password)
change_password_button.pack(side=tk.LEFT, padx=10)

back_button_change_password = ttk.Button(button_frame_change_password, text="Back", command=back_to_profile)
back_button_change_password.pack(side=tk.LEFT, padx=10)


# Chatroom frame
window_width = 800

# Chatroom frame
chatroom_frame = tk.Frame(root, bg=BACKGROUND_COLOR)
chatroom_frame.grid(row=0, column=0, sticky='nsew')
chatroom_frame.grid_remove()  # Hide the chatroom frame initially

chatroom_frame.grid_rowconfigure(0, weight=1)
chatroom_frame.grid_columnconfigure(0, weight=1)

# Creating a paned window for adjustable frames
paned_window = tk.PanedWindow(chatroom_frame, orient=tk.HORIZONTAL, sashwidth=5, bg=BACKGROUND_COLOR)
paned_window.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)

# recipient_listbox
recipient_frame = tk.Frame(paned_window, bg=BACKGROUND_COLOR)
paned_window.add(recipient_frame, minsize=window_width // 5)  # Minimum size

recipient_frame.grid_rowconfigure(0, weight=0)
recipient_frame.grid_rowconfigure(1, weight=0)
recipient_frame.grid_rowconfigure(2, weight=1)
recipient_frame.grid_columnconfigure(0, weight=1)

recipient_label = tk.Label(recipient_frame, text="Logged in users:", font=FONT, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
recipient_label.grid(row=0, column=0, pady=5, padx=5)

department_combobox = ttk.Combobox(recipient_frame, font=FONT, width=20, values=["All Departments", "IT", "Project Planning", "Environment", "HR"])
department_combobox.grid(row=1, column=0, pady=5, padx=5)
department_combobox.set("All Departments")
department_combobox.bind("<<ComboboxSelected>>", lambda e: update_online_users("users~" + "~".join(online_users)))

recipient_listbox = tk.Listbox(recipient_frame, font=SMALL_FONT, bg=ENTRY_BG_COLOR, fg=ENTRY_FG_COLOR, width=25)
recipient_listbox.grid(row=2, column=0, sticky='nsew', pady=5, padx=5)

# message_box
message_frame = tk.Frame(paned_window, bg=BACKGROUND_COLOR)
paned_window.add(message_frame, minsize=window_width // 7)  # Minimum size

message_frame.grid_rowconfigure(0, weight=1)
message_frame.grid_rowconfigure(1, weight=0)
message_frame.grid_rowconfigure(2, weight=0)
message_frame.grid_columnconfigure(0, weight=1)

message_box = scrolledtext.ScrolledText(message_frame, font=SMALL_FONT, bg=ENTRY_BG_COLOR, fg=ENTRY_FG_COLOR, state=tk.DISABLED)
message_box.grid(row=0, column=0, sticky='nsew', pady=5, padx=5)

message_textbox = tk.Text(message_frame, font=FONT, bg=ENTRY_BG_COLOR, fg=ENTRY_FG_COLOR, insertbackground=FOREGROUND_COLOR, height=1)
message_textbox.grid(row=1, column=0, sticky='ew', pady=5, padx=5)
message_textbox.bind('<Shift-Return>', expand_textbox)
message_textbox.bind('<Return>', contract_textbox)

button_frame_message = tk.Frame(message_frame, bg=BACKGROUND_COLOR)
button_frame_message.grid(row=2, column=0, sticky='ew', pady=5, padx=5)

send_button = tk.Button(button_frame_message, text="Send", font=BUTTON_FONT, bg=BUTTON_COLOR, fg=FOREGROUND_COLOR, command=send_message)
send_button.pack(side=tk.LEFT, padx=5)

client = None  # Replace with your client initialization

# Update the button to pass the required arguments
file_button = tk.Button(button_frame_message, text="Send File",  font=BUTTON_FONT, bg=BUTTON_COLOR, fg=FOREGROUND_COLOR, command=lambda: send_file(client, recipient_listbox))
file_button.pack(side=tk.LEFT, padx=5)

dir_button = tk.Button(button_frame_message, text="Profile", font=BUTTON_FONT, bg=BUTTON_COLOR, fg=FOREGROUND_COLOR, command=show_profile)
dir_button.pack(side=tk.LEFT, padx=5)

logout_button = tk.Button(button_frame_message, text="Logout", font=BUTTON_FONT, bg=BUTTON_COLOR, fg=FOREGROUND_COLOR, command=logout)
logout_button.pack(side=tk.LEFT, padx=5)
root.protocol("WM_DELETE_WINDOW", on_closing)
#on_startup()
check_if_already_running()
root.mainloop()