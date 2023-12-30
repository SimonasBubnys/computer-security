FORMAT = 'utf-8'
HEADER = 64


def msg_enc(msg, conn):
    """
    Encodes and sends a message over the connection.

    Parameters:
    - msg (str): The message to be sent.
    - conn: The connection over which the message will be sent.
    """
    encoded_msg = msg.encode(FORMAT)
    msg_length = str(len(encoded_msg)).encode(FORMAT)
    msg_length += b' ' * (HEADER - len(msg_length))
    conn.send(msg_length)
    conn.send(encoded_msg)


def msg_dec(conn):
    """
    Receives and decodes a message from the connection.

    Parameters:
    - conn: The connection from which the message will be received.

    Returns:
    - message (str): The decoded message.
    """
    msg_length = conn.recv(HEADER).decode(FORMAT)
    message = ""
    if msg_length:
        msg_length = int(msg_length)
        message = conn.recv(msg_length).decode(FORMAT)
    return message


def s_encr(msg, conn, f_key): #### CHANGED #### 
    """
    Encrypts and sends a message over the connection.

    Parameters:
    - msg (str): The message to be encrypted and sent.
    - conn: The connection over which the encrypted message will be sent.
    - f_key: The encryption key.

    Note: The encryption key (f_key) is assumed to be an object with an 'encrypt' method.
    """

    encrypted_msg = ""
    for c in msg:
        encrypted_msg += chr(ord(c) + f_key)
    encrypted_msg = encrypted_msg.encode(FORMAT)
    length = str(len(encrypted_msg)).encode(FORMAT)
    length += b' ' * (HEADER - len(length))
    conn.send(length)
    conn.send(encrypted_msg)


def dec_rec(conn, f_key):  #### CHANGED ####
    """
    Receives and decrypts a message from the connection.

    Parameters:
    - conn: The connection from which the encrypted message will be received.
    - f_key: The decryption key.

    Returns:
    - decrypted_message (str): The decrypted message.

    Note: The decryption key (f_key) is assumed to be an object with a 'decrypt' method.
    """
    length = conn.recv(HEADER).decode(FORMAT)
    encrypted_msg = ""
    decrypted_msg = ""
    if length:
        length = int(length)
        encrypted_msg = conn.recv(length).decode(FORMAT)
    for c in encrypted_msg:
        decrypted_msg += chr(ord(c) - f_key)
    return decrypted_msg

    