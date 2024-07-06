import socket
import threading
import base64
import os
import zipfile
import mysql.connector
from datetime import datetime

HOST = '10.12.1.65'
PORT = 4321
LISTENER_LIMIT =1000
active_clients = []

# Database configuration
DB_CONFIG = {
    'username': 'root',
    'password': 'sccl',
    'host': 'localhost',  # usually 'localhost'
    'database': 'messaging'
}

# Function to initialize the database connection
def get_db_connection():
    conn = mysql.connector.connect(**DB_CONFIG)
    return conn

def validate_credentials(username, password, ip_address):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.department 
        FROM users u
        JOIN ip_table ip ON u.username = ip.username
        WHERE u.username = %s AND u.password = %s AND ip.ip_address = %s
    ''', (username, password, ip_address))
    user = cursor.fetchone()
    conn.close()
    if user:
        return user[0]  # Return the department information along with validation result
    else:
        return None



def listen_for_messages(client, username):
    while True:
        try:
            chunks = []
            while True:
                chunk = client.recv(4096)  # Increase buffer size to 4 KB
                if not chunk:
                    break
                chunks.append(chunk)
                if len(chunk) < 4096:  # End of message
                    break
            message = b''.join(chunks).decode('utf-8')
            if message:
                if message == "!logout":
                    handle_logout(client, username)
                    break
                elif message.startswith("file"):
                    handle_received_file(client, message)
                elif message.startswith("directory"):
                    handle_received_directory(client, message)
                elif message.startswith("msg"):
                    handle_personal_message(client, message)
                elif message.startswith("profile_request"):
                    send_user_details(client, username)
                elif message.startswith("change_password"):
                    handle_change_password(client, message)
                else:
                    print(f"Unknown message type: {message}")
            else:
                print(f"The message sent from client {username} is empty")
        except Exception as e:
            print(f"Error: {e}")
            handle_logout(client, username)
            break


def handle_change_password(client, message):
    try:
        _, username, current_password, new_password = message.split("~")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if user and user[0] == current_password:
            cursor.execute('UPDATE users SET password = %s WHERE username = %s', (new_password, username))
            conn.commit()
            conn.close()
            client.sendall("[SERVER] Password changed successfully".encode())
        else:
            conn.close()
            client.sendall("[SERVER] Error: Incorrect current password".encode())
    except Exception as e:
        print(f"Error changing password: {e}")
        client.sendall("[SERVER] Error: Failed to change password".encode())
       
def send_user_details(client, username):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username, department, designation, password FROM users WHERE username = %s', 
                       (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            username, department, designation, password = user
            masked_password = ('*' * (len(password)-2))+password[-2:]
            response = f"profile_response~{username}~{department}~{designation}~{masked_password}"
            client.sendall(response.encode())
        else:
            client.sendall("profile_response~Error: User not found".encode())
    except Exception as e:
        print(f"Error sending user details: {e}")


def insert_to_users(client,message):
    print(client)
    parts=message.split(' ')
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users VALUES (%s, %s, %s, %s)', 
                       (parts[1], parts[2], parts[3],parts[4]))
        msg='[SERVER] Register Successful'
        client.sendall(msg.encode())
        print(1)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error inserting into users: {e}")


def send_message_to_client(client, message):
    try:
        client.sendall(message.encode())
    except Exception as e:
        print(f"Error sending message to client: {e}")

def send_message_to_user(username, message):
    print("send msg to user \n",username)
    username_list=username.split(" ")
    for user in active_clients:
        if user[0] == username_list[0]:
            send_message_to_client(user[1], message)
            break

def log_message(sender, recipient, message):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('INSERT INTO messages (sender, recipient, message, timestamp) VALUES (%s, %s, %s, %s)', 
                       (sender, recipient, message, timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging message: {e}")

# Function to insert file details into the database
def log_file(sender, recipient, file_name):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('INSERT INTO files (sender, recipient, file_name, timestamp) VALUES (%s, %s, %s, %s)', 
                       (sender, recipient, file_name, timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging file: {e}")


def handle_logout(client, username):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT department FROM users WHERE username = %s ', (username,))
        department = cursor.fetchone()
        usern = (username, client, department[0])
        print(usern)
        print(active_clients, "  before")
        active_clients.remove(usern)  # Remove the client from active_clients list
        print(active_clients, " after")
        update_user_list()  # Update user list after removal
    except ValueError:
        pass
    except Exception as e:
        print(f"Error in handle_logout: {e}")

    logout_message = f"[SERVER] {username} has logged out."
    send_messages_to_all(logout_message)

    try:
        send_message_to_client(client, "[SERVER] Logout successful")
    except Exception as e:
        if isinstance(e, OSError) and e.errno == 10054:
            print(f"Client {username} disconnected before logout message could be sent.")
        else:
            print(f"Error sending logout message: {e}")

    try:
        client.close()
    except Exception as e:
        print(f"Error closing client socket: {e}")
 
 
 
    logout_message = f"[SERVER] {username} has logged out."
    send_messages_to_all(logout_message)
    
    try:
        send_message_to_client(client, "[SERVER] Logout successful")
    except Exception as e:
        if isinstance(e, OSError) and e.errno == 10054:
            print(f"Client {username} disconnected before logout message could be sent.")
        else:
            print(f"Error sending logout message: {e}")
    
    try:
        client.close()
    except Exception as e:
        print(f"Error closing client socket: {e}")


def handle_personal_message(client, message):
    try:
        parts = message.split("~", 3)  # Split the message into at most 4 parts
        if len(parts) == 4:
            _, sender, recipient, content = parts
            final_msg = f"{sender}~{content}"
            print(final_msg, recipient)
            send_message_to_user(recipient, final_msg)
            log_message(sender, recipient, content)
        else:
            print(f"Error: Expected 4 parts in the message, got {len(parts)}")
    except ValueError as e:
        print(f"Error: {e} - message format is incorrect")
    except Exception as e:
        print(f"Error handling personal message: {e}")

def finddept(username):
    for i in active_clients:
        if i[0]==username:
            return i[1]
    return 

# Inside handle_received_file function
def handle_received_file(client, message):
    try:
        # Ensure the message is split correctly
        parts = message.split("~", 5)
        if len(parts) != 6 or parts[-1] != '\n':
            raise ValueError("Message format is incorrect")
        
        _, recipient, file_name, file_data, is_last_chunk, _ = parts
        
        # Properly pad the Base64 data
        file_data = base64.b64decode(file_data + '=' * (-len(file_data) % 4))

        save_path = f"received_files/{file_name}"
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'ab') as file:
            file.write(file_data)
        
        print(f"Chunk of file received and saved: {file_name} as {save_path}")

        if int(is_last_chunk):
            print(f"File transfer complete: {file_name}")
            send_file_to_user(recipient, file_name)
            #log_file(sender, recipient, file_name)
    except ValueError as e:
        print(f"Error: {e} - message format is incorrect")
    except Exception as e:
        print(f"Error handling received file: {e}")

        
def handle_received_directory(client, message):
    try:
        _, sender, recipient, zip_name, zip_data = message.split("~", 4)
        zip_data = base64.b64decode(zip_data)

        save_path = f"received_directories/{zip_name}"
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'wb') as zip_file:
            zip_file.write(zip_data)
        print(f"Directory received and saved as zip: {zip_name} as {save_path}")

        if not zipfile.is_zipfile(save_path):
            print(f"Error: {save_path} is not a valid zip file")
            return
        
        extract_path = os.path.join("received_directories", zip_name.replace(".zip", ""))
        with zipfile.ZipFile(save_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        print(f"Directory extracted to: {extract_path}")

        send_directory_to_user(recipient, zip_name, zip_data)
    except ValueError as e:
        print(f"Error: {e} - message format is incorrect")
    except Exception as e:
        print(f"Error handling received directory: {e}")

def send_file_to_user(username, file_name):
    with open(f"received_files/{file_name}", 'rb') as file:
        file_data = file.read()
        
    encoded_data = base64.b64encode(file_data).decode('utf-8')
    message = f"file~{file_name}~{encoded_data}"
    send_message_to_user(username, message)


def send_directory_to_user(username, zip_name, zip_data):
    encoded_data = base64.b64encode(zip_data).decode('utf-8')
    message = f"directory~{zip_name}~{encoded_data}"
    send_message_to_user(username, message)

def send_messages_to_all(message):
    for user in active_clients:
        send_message_to_client(user[1], message)

def update_user_list():
    user_list_message = "users~" + "~".join([f"{user[0]} {user[2]}" for user in active_clients])  # Include department info
    print(f"Updated user list: {user_list_message}")
    send_messages_to_all(user_list_message)


def client_handler(client):
    authenticated = False
    while not authenticated:
        try:
            message = client.recv(2048).decode('utf-8')
            print(message)
            if not message:  # Check if credentials are empty
                print("Client credentials are empty")
                break

            print(message,client)
            
            if(message.startswith('register')):
                insert_to_users(client,message)
            else:     
                username, password ,ip_address= message.split('~')
                department = validate_credentials(username, password,ip_address) # Get department information
                if department:
                    active_clients.append((username, client, department))  # Add department info
                    send_message_to_client(client, "[SERVER] Login successful")
                    update_user_list()  # Update user list after login
                    threading.Thread(target=listen_for_messages, args=(client, username)).start()
                    authenticated = True
                else:
                    send_message_to_client(client, "[SERVER] Invalid credentials")
        except Exception as e:
            print(f"Error: {e}")
            break

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse

    try:
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST} {PORT}")
    except Exception as e:
        print(f"Unable to bind to host {HOST} and port {PORT}: {e}")
        return  # Exit the function if the server fails to bind

    server.listen(LISTENER_LIMIT)  # Ensure this is called

    os.makedirs("received_files", exist_ok=True)
    os.makedirs("received_directories", exist_ok=True)

    while True:
        try:
            client, address = server.accept()
            print(f"Successfully connected to client {address}")
            threading.Thread(target=client_handler, args=(client,)).start()
        except Exception as e:
            print(f"Error accepting client: {e}")

if __name__ == '__main__':
    main()