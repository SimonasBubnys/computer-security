from jsonschema import validate, ValidationError
from cryptography.fernet import Fernet as fern
from required import messageFormating as mf
from schema import Schema, Use, SchemaError
from random import randint
from decimal import Decimal
import socket
import threading
import base64 
import json
import time
import re
from datetime import datetime

FORMAT = 'utf-8'  ##TODO ## NEWLY ADDED ##
HEADER = 64

# Structure = Schema({   ##TODO changed here
#     'id': str,
#     'password': str,
#     'server': {
#         'ip': str,
#         'port': Use(int),
#     },
#     'actions': {
#         'delay': Use(int),
#         'steps': list
#     }
# })

Structure = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "id": {
            "type": "string",
            "maxLength": 100
        },
        "password": {
            "type": "string",
            "maxLength": 100
        },
        "server": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "pattern": "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\.?\\b){4}$"
                },
                "port": {
                    "type": "string",
                    "pattern": "^(4915[0-1]|491[0-4]\\d|490\\d\\d|4[0-8]\\d{3}|[1-3]\\d{4}|[1-9]\\d{0,3}|0)$"
                }
            },
            "required": [
                "ip",
                "port"
            ]
        },
        "actions": {
            "type": "object",
            "properties": {
                "delay": {
                    "type": "string",
                    "pattern": "^([0-9]+)$"
                },
                "steps": {
                    "type": "array",
                    "items": [
                        {
                            "type": "string",
                            "pattern": "^((INCREASE|DECREASE) [-+]?([0-9]{1,3}[,]?)?([0-9]{3}[,]?)*[.]?[0-9]*)$"
                        }
                    ]
                }
            },
            "required": [
                "delay",
                "steps"
            ]
        }
    },
    "required": [
        "id",
        "password",
        "server",
        "actions"
    ]
}


def key_change(conn):  ## CHANGED ##
    # Calculate public key using Diffie-Hellman key exchange
    key_pub = (G ** PRIVATE_VALUE) % P
    # Encode and send the public key to the server using mf
    mf.msg_enc(str(key_pub), conn)
    # Receive the server's public key, decode it, and convert it to an integer
    public_key_server = int(mf.msg_dec(conn))
    # Calculate the shared private key
    key_priv = (public_key_server ** PRIVATE_VALUE) % P
    # Return the derived key after base64 encoding
    
    #return fern(base64.urlsafe_b64encode(key_priv.to_bytes(32, byteorder="big")))

    return key_priv #TODO changed here

# def validation(json_str: str):  ## THIS METHOD IS LITERALLY NEVER USED ##
#     # Attempt to parse the input JSON string
#     try:
#         encode_message_act = json.loads(json_str)
#     except json.decoder.JSONDecodeError:
#         # Return False if there's an error decoding the JSON
#         return False

#     # Validate the JSON structure using a predefined schema (assuming SchemaError is defined somewhere)
#     try:
#         Structure.validate(encode_message_act)
#     except SchemaError:
#         # Return False if the structure does not match the expected schema
#         return False

#     # Iterate over the 'steps' in the 'actions' key of the JSON
#     for step in encode_message_act['actions']['steps']:
#         try:
#             # Check if the step matches the pattern 'INCREASE \d' or 'DECREASE \d'
#             if re.compile('INCREASE \\d').match(step) is None and re.compile('DECREASE \\d').match(step) is None:
#                 # Return False if the step does not match the expected pattern
#                 return False
#         except TypeError:
#             # Return False if there's a TypeError during the regular expression matching
#             return False

#     # Return True if all checks pass
#     return True


def check_pass(pas1: str, pas2: str): #### UNCHANGED ####
    # Check if passwords match
    return pas1 == pas2

def conn_det_change(id: str, password: str): #### UNCHANGED ####
    # Update the user's password and reset counters
    pass_con_now[id] = password
    id_total_collector[id] = 0


def con_det_delete(id: str):  #### UNCHANGED #####
    # Delete user details and counters when signing out
    global id_accumulator
    with counter_lock:
        if id_accumulator[id]:
            if id_accumulator[id] > 1:
                id_accumulator[id] -= 1
            elif id_accumulator[id] == 1:
                id_accumulator.pop(id)
                id_total_collector.pop(id)
                pass_con_now.pop(id)


def handling(msg: str, conn): #### CHANGED ####
    # Parse the incoming JSON message
    data = json.loads(msg)
    id = data["id"]
    password = data["password"]
    actions = data["actions"]["steps"]
    delay = int(data["actions"]["delay"])

    # Check if the user is not already in the system
    if id not in pass_con_now:
        # Initialize the user's counters and log the sign-in
        with counter_lock:
            id_accumulator[id] = 1
        conn_det_change(id, password)
        with open("logfile.txt", "a") as logfile:
            logfile.write(
                f"{id}\t\t\tSign-in \t\t\t{id_total_collector[id]}\t\t\t{datetime.now()}\n")
        # Handle the specified actions
            
        #handle_actions(id, actions, delay) ## TODO changed here

        if validate_data(msg): #TODO
            handle_actions(id, actions, delay)
    else:
        # If the user is already in the system, check the password
        if check_pass(pass_con_now[id], password):
            # Increment the user's counters and log the sign-in
            with counter_lock:
                id_accumulator[id] += 1
            with open("logfile.txt", "a") as logfile:
                logfile.write(
                    f"{id}\t\t\tSign-in \t\t\t{id_total_collector[id]}\t\t\t{datetime.now()}\n")
            # Handle the specified actions
            handle_actions(id, actions, delay)
        else:
            # If the password is incorrect, send an access denied message
            mf.msg_enc(
                "\nAccess Denied: Another user with the same ID is currently logged in with a different password\n", conn)

    # Log the sign-out and remove user details
    with open("logfile.txt", "a") as logfile:
        logfile.write(
            f"{id}\t\t\tSign-out\t\t\t{id_total_collector[id]}\t\t\t{datetime.now()}\n")
    con_det_delete(id)


def process_client(conn, addr):    #### CHANGED ####
    # Establish a new connection and generate a key for communication encryption
    key = key_change(conn)
    print(f"\nEstablishing a new connection {addr}\n.")

    # Process incoming messages until the client signals to disconnect
    while True:
        #message = mf.dec_rec(conn, key)  ## TODO changed here
        try:              
            message = mf.dec_rec(conn, key)
        except (ConnectionResetError):
            print("Client connection refused - Incorrect Password.")
            break

        if message == DISCONNECT:
            break
        elif message != "":
            handling(message, conn)
            mf.s_encr("Message Received!", conn, key)

            # # If the message is valid, handle it  ##TODO changed here
            # if validation(message):
            #     handling(message, conn)
            #     mf.s_encr("Message has been received!", conn, key)
            # else:
            #     # If the message is invalid, send an error message
            #     mf.s_encr(
            #         "Invalid data or data format. Please try again.", conn, key)

    # Close the connection when done
    print(f"\nClosing the connection {addr}\n.")
    conn.close()


def start_server():   #### UNCHANGED ####
    # Start listening for incoming connections
    server.listen()
    print(f"Server at {SERVER}:{PORT} initiated.")

    # Clear and initialize the logfile
    open("logfile.txt", "w").close()
    with open("logfile.txt", "a") as logfile:
        logfile.write("ID\t\t\t\tAction\t\t\t\tCounter\t\tDate\n")

    # Accept and handle incoming connections
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=process_client, args=(conn, addr))
        thread.start()


def handle_actions(id: str, actions: list, delay: int): #### CHANGED ####
    k = 0
    const = len(actions)

    # Iterate through each action in the list
    for action in actions:
        if "INCREASE" in action:
            # Extract the numeric value from the action string
            
            ##counter1 = [int(s) for s in action.split() if s.isdigit()]
            counter1 = re.findall(r"[-+]?(?:\d*\.\d+|\d+)", action) #TODO changed here

            # Update the connection count with the extracted value
            with conn_details_lock:
                id_total_collector[id] += Decimal(counter1[0])  ##TODO changed here id_total_collector[id] += counter1[0]
                # Log the increase action to a file
                with open("logfile.txt", "a") as logfile:
                    logfile.write(
                        f"{id}\t\t\tIncrease\t\t\t{id_total_collector[id]}\t\t\t{datetime.now()}\n")
                # Print the updated connection count
                print(
                    f"Augment by {counter1[0]}, the counter for id - {id} is now: {id_total_collector[id]}")
        elif "DECREASE" in action:
            # Extract the numeric value from the action string

            ##counter1 = [int(s) for s in action.split() if s.isdigit()]
            counter1 = re.findall(r"[-+]?(?:\d*\.\d+|\d+)", action) #TODO changed here

            # Update the connection count with the extracted value
            with conn_details_lock:
                id_total_collector[id] -= Decimal(counter1[0]) ##TODO changed here id_total_collector[id] += counter1[0]
                # Log the decrease action to a file
                with open("logfile.txt", "a") as logfile:
                    logfile.write(
                        f"{id}\t\t\tDecrease\t\t\t{id_total_collector[id]}\t\t\t{datetime.now()}\n")
                # Print the updated connection count
                print(
                    f"Decreased by {counter1[0]}, the counter for ID - {id} is now: {id_total_collector[id]}")

        k += 1

        # If there are more actions and delay is greater than 1000000 microseconds, sleep for 1 second
        if k < const and delay > 1000000:
            delay = 1000000
            time.sleep(delay)

def validate_data(json_str):  ## NEWLY ADDED ##

    try:
        json_data = json.loads(json_str)
    except json.decoder.JSONDecodeError:
        print("INVALID INPUT: the json file does not follow the json structure.")
        return False

    try:
        validate(json_data, Structure)
    except ValidationError as e:
        if e.validator == "required":
            print(f"INVALID INPUT: {e.message}.")
        else:
            print(f"INVALID INPUT: \'{e.instance}\' is an invalid argument for field {e.json_path}.")
        return False

    if int(json_data["actions"]["delay"]) > 1000000:
        return False

    for step in json_data["actions"]["steps"]:
        if float(step.split()[1])  > 1000000000000:
            return False

    return True


if __name__ == "__main__":
    # Server configuration
    G = 6143
    P = 7919
    PORT = 5050
    PRIVATE_VALUE = randint(1, 10000)
    SERVER = "127.0.0.1"
    ADDR = (SERVER, PORT)
    DISCONNECT = "Sock It"
     
    # Data structures to manage connections and user information
    id_accumulator = {}
    id_total_collector = {}
    pass_con_now = {}

    # Locks for thread safety
    conn_details_lock = threading.Lock()
    counter_lock = threading.Lock()

    # Create and bind the server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    # Start the server
    start_server()