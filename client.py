import socket
import threading
import os
from datetime import datetime
import winsound


HOST = "127.0.0.1"
PORT = 12345
DOWNLOAD_FOLDER = "client_downloads"
notifications_enabled = True
if not os.path.exists(DOWNLOAD_FOLDER):
    os.makedirs(DOWNLOAD_FOLDER)

#Start onection
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
ALLOWED_EXTENSIONS = {".docx", ".pdf", ".jpeg"}
# Authenticate user
server_message = client.recv(1024).decode('utf-8')
if server_message == "ENTER R OR L":
    #Keep asking if need
    while True:
        choice = input("Enter 'R' to Register or 'L' to Log in: ").strip().upper()
        if choice in ["R", "L"]:
            client.send(choice.encode('utf-8'))

            server_response = client.recv(1024).decode('utf-8')
            if server_response == "USERNAME":
                username = input("Enter username: ")
                client.send(username.encode('utf-8'))

            server_response = client.recv(1024).decode('utf-8')
            if server_response == "PASSWORD":
                password = input("Enter password: ")
                client.send(password.encode('utf-8'))

            server_response = client.recv(1024).decode('utf-8')
            if server_response in ["R completed", "Log in completed"]:
                print("Login successful!" if "Log in" in server_response else "Registration successful!")
                break
            elif server_response == "USER_EXISTS":
                print("Username already exists. Try again.")
            elif server_response == "USER_NOT_FOUND":
                print("User not found. Try again.")
            elif server_response == "INVALID_PASSWORD":
                print("Incorrect password. Try again.")




# Thread always running recieve ingo
def receive():
    is_conversation = False
    conversation_lines = []

    while True:

        try:
            messages = client.recv(4096).decode('utf-8')
            if not messages:
                break #If message to big break

            for message in messages.split("\n"):
                message = message.strip() #Need to split as is returned as one big list
                if not message:
                    continue    

                if message == "[CONVERSATION]": #Method output conversation 2 clients
                    is_conversation = True
                    conversation_lines = []
                    continue
                elif message == "[END]": 
                    for line in conversation_lines:
                        print(line)
                    is_conversation = False #Flag to check wether the end of the conversation was reched
                    continue
                
                elif message.startswith("File '") and message.endswith("uploaded successfully."):
                    print(message)
                
                #Append conversation
                if is_conversation:
                    conversation_lines.append(message)
                    continue
                
                if message.startswith("[PRIVATE] [") and "]" in message and ":" in message:
                    try:
                        raw = message.replace("[PRIVATE] ", "", 1)
                        sent_part, rest = raw.split("]", 1)
                        sent_time = sent_part[1:]
                        sender, msg = rest.strip().split(":", 1)
                        #Obtain time
                        received_time = datetime.now().strftime("%H:%M:%S")

                        # Build combined timestamp message
                        combined = f"[{sent_time}/{received_time}] {sender.strip()}: {msg.strip()}"
                        print(f"[INFO] Received a message from {sender.strip()}: [{sent_time}/{received_time}] {sender.strip()}: {msg.strip()}")
                        #If notification send
                        if notifications_enabled:
                            winsound.Beep(500, 200)  # Frequency=1000Hz, Duration=200ms

                        # Send it back to be stored on the server
                        store_payload = f"STORE {sender.strip()}|{msg.strip()}|{sent_time}|{received_time}"
                        client.send(store_payload.encode('utf-8'))
                        continue
                    except Exception as e:
                        print(f"[ERROR] Failed to handle private msg: {e}")
                #File uploading process
                if message.startswith("FILE_FOUND"):
                    filename = message.split(" ", 1)[1]
                    file_path = os.path.join(DOWNLOAD_FOLDER, filename)
                    print(f"Receiving file: {filename}") #Small debug that also helps user exprrience

                    #Cases in which file might be small
                    with open(file_path, "wb") as f:
                        while True:
                            data =    client.recv(4096)
                            if data == b"EOF":
                                break
                            f.write(data)

                    print(f"File {filename} downloaded to {file_path}")
                    continue


        except:
            print("ERROR: Connection lost.")
            break

    client.close()

# Reciever thread
threading.Thread(target=receive, daemon=True).start()
def allowed_extension(filename):
    return os.path.splitext(filename)[1].lower() in {'.docx', '.pdf', '.jpeg'}


# As it's input loop running always
while True:
    try:
        message = input()
        #Method upload files
        if message.startswith("upload "):
                #Obatin name
            _, filename = message.split(" ", 1)
            if not allowed_extension(filename): #Catch exception
                print(f"[ERROR] '{filename}' is not an allowed file type.")
                continue
            if not os.path.exists(filename):  #Catch exception
                print(f"[ERROR] File '{filename}' not found!")
                continue

            client.send(f"UPLOAD {filename}".encode('utf-8')) #Connect with server to obtain file

            with open(filename, "rb") as f:
                sent_any = False
                while (data := f.read(4096)):
                    client.send(data)
                    sent_any = True

                if not sent_any:
                    print("[DEBUG] Empty file. Still sending EOF.")

            client.send(b"EOF")
            print(f"[UPLOAD] '{filename}' sent to server.")
            continue  # skip normal chat


        #Method off notification
        if message.strip().lower() == "notifications off":
            notifications_enabled = False
            print("[INFO] Notifications turned OFF.")
            continue

        if message.strip().lower() == "notifications on":
            notifications_enabled = True
            print("[INFO] Notifications turned ON.")
            continue

        if message.startswith("download "):
            _, filename = message.split(" ", 1)
            client.send(f"DOWNLOAD {filename}".encode('utf-8'))
            continue
        #Always listen input
        client.send(message.encode('utf-8'))
        #Exit all
        if message.lower() == "exit":
            print("[INFO] You have left the chat.")
            client.close()
            break

    except:
        break


