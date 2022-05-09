import codecs
import hashlib
import time
from binascii import unhexlify


def tx_compute_hash(tx):
    """
    Compute the SHA256 double hash of a transaction.
    Arguments:
        tx (string): transaction data as an ASCII hex string
    Return:
        string: transaction hash as an ASCII hex string
    """

    return hashlib.sha256(hashlib.sha256(bytes.fromhex(tx)).digest()).digest()[::-1].hex()

def little_to_big(value):
#     value = codecs.encode(bytes.fromhex(value), "hex").decode('ascii')
    ba = bytearray.fromhex(value)
    ba.reverse()
    s = ''.join(format(x, '02x') for x in ba)
    return s

def switch_h_to_int(h_char):

    if h_char == "a":
        h = 10
    elif h_char == 'b':
        h = 11
    elif h_char == 'c':
        h = 12
    elif h_char == 'd':
        h = 13
    elif h_char == 'e':
        h = 14
    elif h_char == 'f':
        h = 15
    else:
        h = int(h_char)
    return h

def switch_int_to_h(number):

    if number == 10:
        h = 'a'
    elif number == 11:
        h = 'b'
    elif number == 12:
        h = 'c'
    elif number == 13:
        h = 'd'
    elif number == 14:
        h = 'e'
    elif number == 15:
        h = 'f'
    else:
        h = str(number)
    return h


inicio = time.time()
for a in range(16): #1
    a_hex = switch_int_to_h(a)
    for b in range(16): #2
        b_hex = switch_int_to_h(b)
        for c in range(16): #3
            c_hex = switch_int_to_h(c)
            for d in range(16): #4
                d_hex = switch_int_to_h(d)
                for e in range(16): #5
                    e_hex = switch_int_to_h(e)
                    me_nonce = a_hex + b_hex + c_hex + d_hex + e_hex
                    me_nonce = me_nonce.zfill(8)
                    if me_nonce != "0" * 5:
                        # me_nonce = tx_compute_hash(codecs.encode(bytes.fromhex(me_nonce)[::-1], "hex").decode('ascii'))
                        me_hash = tx_compute_hash(little_to_big(me_nonce))
                        if me_hash == "123456789":
                            pass

fin = time.time()
print("Ejecución: {}".format(fin-inicio))

