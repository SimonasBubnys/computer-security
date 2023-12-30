from jsonschema import validate, ValidationError
from cryptography.fernet import Fernet as fern
from required import messageFormating as mf
from schema import Schema, Use, SchemaError
from random import randint
import tkinter
from tkinter import filedialog
import sys
import ipaddress
import socket
import base64
import json
import settings


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

# Define the schema for the JSON structure

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

# Function to manually input client configuration data


def inp_cc():  #### UNCHANGED ####
    # Gather information from the user for client configuration
    id = input("Input your ID: ")
    password = input("Input password: ")
    server = input("Input server IP: ")
    port = input("Input server port: ")

    # Initialize an empty list to store actions
    actions = []
    print("Input actions, press 'e' to exit: ")

    # Gather user input for actions until 'e' is entered
    while True:
        action = input()
        if action == "e":
            break
        actions.append(action)

    # Gather user input for delay between actions
    delay = input("Input delay between actions: ")

    # Create a dictionary representing the client configuration
    data = {
        "id": str(id),
        "password": str(password),
        "server": {
            "ip": str(server),
            "port": str(port)
        },
        "actions": {
            "delay": str(delay),
            "steps": actions
        }
    }

    # Convert the dictionary to a JSON-formatted string and return
    return json.dumps(data)
    


def choice(connected: bool): #### CHANGED ####
    # Prompt the user to choose an input method
    decision = input(
        "What would you like to do?\n[1] Input Data\n[0] Quit\n")

    # Check user's decision
    if decision == "0":
        pass  # User chose to quit, do nothing
    elif decision == "1":
        try:    ##TODO added this try and excpet clause
            # User chose JSON file input, locate file and attempt connection
            json_data = cl_file_locate()
            if con_val(json_data):
                encr_send_mes(json_data)
                connected = True
            else:
                # If connection validation fails, recursively call choice with False
                choice(False)
        except FileNotFoundError:
            choice(False)
    else:
        # Invalid input, prompt user to retry
        print(f"{decision} isn't 0 or 1; please pick a valid entry.")
        # Recursively call choice with False
        choice(False)

    # Return the current connection status
    return connected


# Function to validate and establish connection with the server
# Function to validate and establish connection with the server
def con_val(json_str: str): #### CHANGED ####
    # Check if the provided JSON data is valid

    #if validate_input(json_str): ##TODO changed here
    if validate_data(json_str):

        # If valid, load the content into a dictionary
        content_dict = json.loads(json_str)
        try:
            # Attempt to connect to the server using the provided IP and port
            client.connect((content_dict['server']['ip'], int(
                content_dict['server']['port'])))
            # If successful, set the global encryption key using initiate_key
            global encryption_key
            encryption_key = initiate_key()
        except (TimeoutError, ConnectionRefusedError):  ##TODO added ConnectionRefusedError
            # Handle a TimeoutError, indicating an issue with server IP or port
            print(
                "Invalid server IP and/or port. Please provide valid values and try again.\n")
            return False  # Return False to indicate connection failure
        return True  # Return True to indicate successful connection
    else:
        # Handle the case where the provided JSON data is invalid
        print("Invalid data or data format. Please provide correct information and try again.\n")
        return False  # Return False to indicate validation failure


# Function to encrypt and send the message to the server
def encr_send_mes(msg: str): #### CHANGED ####
    
    #mf.s_encr(msg, client, encryption_key)     ##TODO changed these
    #print(mf.dec_rec(client, encryption_key))

    # Encrypt and send the message to the server using the provided encryption_key
    mf.s_encr(msg, client, encryption_key)
    try:
        # Print the decrypted response from the server using the same encryption_key
        print(mf.dec_rec(client, encryption_key))
    except(ValueError):
        print('Incorrect Password, try again!')


# Function to initiate the encryption key
def initiate_key():     #### CHANGED ####
    key_pub = (G**PRIVATE_VALUE) % P
    # Encode and send the public key to the server
    mf.msg_enc(str(key_pub), client)
    # Receive and decode the server's public key
    key_pub_serv = int(mf.msg_dec(client))
    # Calculate the shared private key
    key_priv = (key_pub_serv**PRIVATE_VALUE) % P
    # Return the Fernet key based on the shared private key

    #return fern(base64.urlsafe_b64encode(key_priv.to_bytes(32, byteorder="big")))
    return key_priv #TODO changed here

# Function to locate and load client configuration data from a file

# def cl_file_locate():  #### COMPLETELY CHANGED ####
#     while True:
#         # Prompt the user to input the filename
#         file_name = input("Input filename: ")
#         try:
#             # Attempt to open the file at the specified path
#             file = open(settings.data_path + file_name)
#             try:
#                 # Attempt to load JSON data from the file
#                 data = json.load(file)
#                 file.close()
#                 break  # Break out of the loop if successful
#             except json.decoder.JSONDecodeError:
#                 # Handle a JSONDecodeError, indicating an issue with the file format
#                 print(
#                     f"Data/{file_name} can't be read. The format appears to deviate from the JSON structure. Please make another attempt.")
#                 file.close()
#         except FileNotFoundError:
#             # Handle a FileNotFoundError, indicating that the file is not present
#             print(f"Data/{file_name} not present. Please make another attempt.")

#     # Return the JSON data as a string
#     return json.dumps(data)

def cl_file_locate():   #### THE REPLACEMENT OF THE ONE ABOVE ####

    root = tkinter.Tk()
    root.attributes("-topmost", True)
    root.withdraw()
    filename = filedialog.askopenfilename(
        initialdir="../data",   ##TODO not sure if this is the same for us gotta check
        filetypes=[("Json File", "*.json")],
        title="Select a File"
    )
    if filename == "":
        sys.exit("INVALID INPUT: no file was selected.")

    with open(filename, 'r') as file:
        json_str = file.read()
    
    return json_str


# Function to validate the input data against the defined schema
# def validate_input(json_str: str):  ##TODO not used anymore
#     try:
#         # Attempt to load JSON data from the provided string
#         content_dict = json.loads(json_str)
#     except json.decoder.JSONDecodeError:
#         # Handle a JSONDecodeError, indicating an issue with the data format
#         return False

#     try:
#         # Validate the JSON structure against the defined schema
#         Structure.validate(content_dict)
#     except SchemaError:
#         # Handle a SchemaError, indicating a mismatch between data and schema
#         return False

#     try:
#         # Validate the server IP address
#         ipaddress.ip_address(content_dict['server']['ip'])
#     except ValueError:
#         # Handle a ValueError, indicating an issue with the server IP format
#         return False

#     # Validate the server port range
#     if 1 <= int(content_dict['server']['port']) <= 65535:
#         pass
#     else:
#         # Handle an invalid server port range
#         return False

#     return True  # Return True if all validations pass

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
    # Define constants for disconnection, private value, generator, and prime modulus
    DISCONNECT = "Sock It"
    PRIVATE_VALUE = randint(1, 10000)
    G = 6143
    P = 7919

    # Create a socket object for the client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Call the choice function to handle user input and connection
    connected = choice(False)

    # Check if the connection was successful
    if connected:
        # Securely disconnect if connected
        mf.s_encr(DISCONNECT, client, encryption_key)
