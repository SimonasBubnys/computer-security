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


def s_encr(msg, conn, f_key):
    """
    Encrypts and sends a message over the connection.

    Parameters:
    - msg (str): The message to be encrypted and sent.
    - conn: The connection over which the encrypted message will be sent.
    - f_key: The encryption key.

    Note: The encryption key (f_key) is assumed to be an object with an 'encrypt' method.
    """
    encrypted = f_key.encrypt(msg.encode())
    length = str(len(encrypted)).encode(FORMAT)
    length += b' ' * (HEADER - len(length))
    conn.send(length)
    conn.send(encrypted)


def dec_rec(conn, f_key):
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
    encrypted = ""
    if length:
        length = int(length)
        encrypted = conn.recv(length)
        decrypted_message = f_key.decrypt(encrypted).decode()
        return decrypted_message

    