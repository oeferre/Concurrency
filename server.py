#https://thepythoncode.com/article/make-a-chat-room-application-in-python used as help with multithreading
import socket
import threading
import os
import queue
import hashlib
from datetime import datetime

# Constants
HOST = "127.0.0.1"
PORT = 12345
MAX_CONNECTIONS = 3
assumed_lenght = 2
# Syncronization 

#Declarate semaphore with space 3 to control connections
semaphore = threading.Semaphore(MAX_CONNECTIONS)
waiting_queue = queue.Queue()
clients = {}
nicknames = {}
lock = threading.Lock()

UPLOAD_FOLDER = "server_uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# User Data
users_db = {}
messages = {}
conversations = {}
#Protect passwrod
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
#Loop check user
def authenticate_user(client):
    client.send("ENTER R OR L".encode('utf-8'))
    while True:
        choice = client.recv(1024).decode('utf-8').strip().upper()
        if choice == "R":
            client.send("USERNAME".encode('utf-8'))
            username = client.recv(1024).decode('utf-8').strip()
            if username in users_db:
                client.send("USER_EXISTS".encode('utf-8'))
                continue
            client.send("PASSWORD".encode('utf-8'))
            password = client.recv(1024).decode('utf-8').strip()
            users_db[username] = hash_password(password)
            messages[username] = []
            client.send("R completed".encode('utf-8'))
            print(f"[NEW USER] {username} registered.")
            return username
        elif choice == "L":
            client.send("USERNAME".encode('utf-8'))
            username = client.recv(1024).decode('utf-8').strip()
            if username not in users_db:
                client.send("USER_NOT_FOUND".encode('utf-8'))
                continue
            client.send("PASSWORD".encode('utf-8'))
            password = client.recv(1024).decode('utf-8').strip()
            if hash_password(password) == users_db[username]:
                client.send("Log in completed".encode('utf-8'))
                print(f"[LOGIN SUCCESS] {username} logged in.")
                return username
            else:
                client.send("INVALID_PASSWORD".encode('utf-8'))
        else:
            client.send("INVALID_OPTION".encode('utf-8'))

#If exit kick out
def remove_client(client, username):
    with lock:
        if username in clients:
            del clients[username]
            del nicknames[username]
            print(f"[DISCONNECTED] {username} left the chat.")
            #Generate free space in semaphore so if possible add someone
            semaphore.release()
            if not waiting_queue.empty():
                #Soemone waiting go into server
                next_client, next_nickname = waiting_queue.get()
                print(f"[QUEUE MOVED UP] {next_nickname} is now connecting...")
                semaphore.acquire()
                threading.Thread(target=handle_client, args=(next_client, next_nickname)).start()
            else:
                print("[INFO] Queue empty.")

#Organising clients
def handle_client(client, username):
    try:
        with lock:
            clients[username] = client
            nicknames[username] = username
            if username in messages and messages[username]:
                client.send("\n".join(messages[username]).encode('utf-8'))
                messages[username] = []

        print(f"[CONNECTED] {username} joined.")

        while True:
            message = client.recv(4096).decode('utf-8')
            if not message or message.lower() == "exit":
                break
            #Problems inpit
            elif message.lower().startswith("chat "):
                parts = message.strip().split(" ", 2)
                if len(parts) < 3:
                    client.send("[ERROR] Usage: chat <username> <message>".encode('utf-8'))
                    continue
                _, target_user, msg = parts
                sent_time = datetime.now().strftime("%H:%M:%S")
                full_msg = f"[{sent_time}] {username}: {msg}"
                #Send chat
                if target_user in clients:
                    clients[target_user].send(f"[PRIVATE] {full_msg}".encode('utf-8'))
                    client.send("[SENT] Message delivered.".encode('utf-8'))
                else:
                    client.send("[ERROR] User not found or offline.".encode('utf-8'))
            #Upload method in server
            elif message.lower().startswith("upload "):
                
                filename = message.split(" ", 1)[1]
                print("Receiving file: " + filename)
                if not allowed_extension(filename):
                    print(f"[ERROR] '{filename}' is not an allowed file type.") 
                    continue
                file_path = os.path.join(UPLOAD_FOLDER, filename)

                #Retrieve data from file
                with open(file_path, "wb") as f:
                    while True:
                        data = client.recv(4096)
                        if b"EOF" in data:
                            f.write(data.replace(b"EOF", b""))  #Might be too small so just in case
                            break
                        f.write(data)
                #Debug 
                print(filename + " uploaded successfully")
                client.send(f"File '{filename}' uploaded successfully.".encode('utf-8'))




            #Doenloading method
            elif message.lower().startswith("download "): 
                #Obtain file name  
                filename = message.strip().split(" ", 1)[1]
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                #Check path, if in there retrieve data
                if os.path.exists(file_path):
                    client.send(f"FILE_FOUND {filename}".encode('utf-8'))
                    with open(file_path, "rb") as f:
                        while (data := f.read(4096)):
                            client.send(data)
                    client.send(b"EOF")
                else:
                    client.send("ERROR: File not found.".encode('utf-8'))


            #Output whole conversation
            elif message.lower().startswith("conversation "):
                parts = message.strip().split(" ", 1)
                if len(parts) < 2:
                    client.send("[ERROR] Usage: conversation <username>".encode('utf-8'))
                    continue

                other_user = parts[1]
                chat_key = "_".join(sorted([username.lower(), other_user.lower()]))
                #If empty
                with lock:
                    history = conversations.get(chat_key, ["[INFO] No messages found."])

                # If conversation exists
                client.send("[CONVERSATION]\n".encode('utf-8'))
                for line in history:
                    client.send(f"{line}\n".encode('utf-8'))
                client.send("[END]\n".encode('utf-8'))



            #For storing messages in conversation
            elif message.startswith("STORE "):
                try:
                    _, payload = message.split(" ", 1)
                    sender, msg, sent_time, received_time = payload.split("|", 3)
                    chat_key = "_".join(sorted([username.lower(), sender.lower()]))
                    #Generate the appended message 
                    final_msg = f"[{sent_time}/{received_time}] {sender}: {msg}"
                    #Check if created if not create if it's append
                    with lock:
                        if chat_key not in conversations:
                            conversations[chat_key] = []
                        conversations[chat_key].append(final_msg)

                    print(f"[DEBUG] Stored: {final_msg}")
                except Exception as e:
                    print(f"[ERROR] Failed to process STORE message: {e}")

    except Exception as e:
        print(f"[ERROR] {e}")

    finally:
        remove_client(client, username)
        client.close()
#Method to connect to server
def accept_connections():
    while True:
        print("Server waiting for a connection...")
        client, _ = server.accept()
        username = authenticate_user(client)
        with lock:
            if len(clients) >= MAX_CONNECTIONS:
                position = waiting_queue.qsize() + 1  # Line
                estimated_time = position * assumed_lenght
                client.send(f"[INFO] You are in the queue. Estimated wait time: {estimated_time} minute(s).".encode('utf-8')) #Gueses on time taken
                print(f"Server is full. Client {username} is waiting (Position {position}, ~{estimated_time} min).")
                waiting_queue.put((client, username))
            else: 
                #Decrease space in semaphor if free
                semaphore.acquire()
                print(f"{username} is connecting...")
                threading.Thread(target=handle_client, args=(client, username)).start()
#Types extensions availables
def allowed_extension(filename):
    return os.path.splitext(filename)[1].lower() in {'.docx', '.pdf', '.jpeg'}

#Store message with the time 
def store_message(sender, recipient, message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    chat_key = "_".join(sorted([sender.lower(), recipient.lower()]))
    full_msg = f"[{timestamp}] {sender}: {message}"

    if chat_key not in conversations:
        conversations[chat_key] = []
    #Append to conversations if creaated
    conversations[chat_key].append(full_msg)
    #Debugging
    print(f"[DEBUG] Stored under key '{chat_key}': {full_msg}")

    return full_msg

# Start the Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

#Outputs when creating server
print(f"Server running on {HOST}:{PORT}")
accept_connections()
