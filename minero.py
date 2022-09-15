# coding=utf-8
#import asyncio
import base64
import hashlib
import json
import os
import random
import struct
import sys
import time
import timeit
from binascii import unhexlify
from concurrent.futures import as_completed, ThreadPoolExecutor, ProcessPoolExecutor
import numpy as np
import pandas as pd
import requests
from datetime import datetime



# JSON-HTTP RPC Configuration
# This will be particular to your local ~/.bitcoin/bitcoin.conf

RPC_URL = os.environ.get("RPC_URL", "http://localhost:8332")
RPC_USER = os.environ.get("RPC_USER", "")
RPC_PASS = os.environ.get("RPC_PASS", "")


################################################################################
# Bitcoin Daemon JSON-HTTP RPC
################################################################################




def rpc(method, params):
    """
    Make an RPC call to the Bitcoin Daemon JSON-HTTP server.
    Arguments:
        method (string): RPC method
        params: RPC arguments
    Returns:
        object: RPC response result.
    """

    rpc_id = random.getrandbits(32)
    payload = json.dumps({"id": rpc_id, "method": method, "params": params}).encode()
    auth = base64.encodebytes((RPC_USER + ":" + RPC_PASS).encode()).decode().strip()
    headers = {'content-type': "application/json", 'cache-control': "no-cache"}
    # try:
    msg = requests.request("POST", RPC_URL, data=payload, headers=headers, auth=(RPC_USER, RPC_PASS))
    response = json.loads(msg.text)

    if response['id'] != rpc_id:
        raise ValueError("Invalid response id: got {}, expected {:d}".format(response['id'], rpc_id))
    elif response['error'] is not None:
        raise ValueError("RPC error: {:s}".format(json.dumps(response['error'])))
    return response['result']
# except requests.exceptions.RequestException as e:
#     print(e)


# async def rpc_getblocktemplate():
def rpc_getblocktemplate():
    try:
        return rpc("getblocktemplate", [{"rules": ["segwit"]}])
        # return await rpc("getblocktemplate", [{"rules": ["segwit"]}])
    except ValueError:
        return {}


def rpc_submitblock(block_submission):
    return rpc("submitblock", [block_submission])


def tx_compute_merkle_root(tx_hashes):
    """
    Compute the Merkle Root of a list of transaction hashes.
    Arguments:
        tx_hashes (list): list of transaction hashes as ASCII hex strings
    Returns:
        string: merkle root as a big endian ASCII hex string
    """

    # Convert list of ASCII hex transaction hashes into bytes
    # tx_hashes = [bytes.fromhex(tx_hash["hash"])[::-1] for tx_hash in transactions]
    tx_hashes = [bytes.fromhex(tx_hash)[::-1] for tx_hash in tx_hashes]

    # Iteratively compute the merkle root hash
    while len(tx_hashes) > 1:
        # Duplicate last hash if the list is odd
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])

        tx_hashes_new = []

        for i in range(len(tx_hashes) // 2):
            # Concatenate the next two
            concat = tx_hashes.pop(0) + tx_hashes.pop(0)
            # Hash them
            concat_hash = hashlib.sha256(hashlib.sha256(concat).digest()).digest()
            # Add them to our working list
            tx_hashes_new.append(concat_hash)

        tx_hashes = tx_hashes_new
    # print(tx_hashes[0][::-1].hex())
    # Format the root in big endian ascii hex
    return str(tx_hashes[0][::-1].hex())


def sha256(data):
    return hashlib.sha256(data).digest()

def sha256d(data):
    return sha256(sha256(data))

# def get_merkle_root(transactions):
#     branches = [bytes.fromhex(tx_hash)[::-1] for tx_hash in transactions]
#
#     while len(branches) > 1:
#         if (len(branches) % 2) == 1:
#             branches.append(branches[-1])
#
#         branches = [sha256d(a + b) for (a, b) in zip(branches[0::2], branches[1::2])]
#
#     return branches[0][::-1].hex()


def block_bits2target(bits):
    """
    Convert compressed target (block bits) encoding to target value.
    Arguments:
        bits (string): compressed target as an ASCII hex string
    Returns:
        bytes: big endian target
    """

    # Bits: 1b0404cb
    #       1b          left shift of (0x1b - 3) bytes
    #         0404cb    value
    bits = bytes.fromhex(bits)
    shift = bits[0] - 3
    value = bits[1:]

    # Shift value to the left by shift
    target = value + b"\x00" * shift
    # Add leading zeros
    target = b"\x00" * (32 - len(target)) + target

    return target


def tx_compute_hash(tx):
    """
    Compute the SHA256 double hash of a transaction.
    Arguments:
        tx (string): transaction data as an ASCII hex string
    Return:
        string: transaction hash as an ASCII hex string
    """

    return hashlib.sha256(hashlib.sha256(bytes.fromhex(tx)).digest()).digest()[::-1].hex()


def int2lehex(value, width):
    """
    Convert an unsigned integer to a little endian ASCII hex string.
    Args:
        value (int): value
        width (int): byte width
    Returns:
        string: ASCII hex string
    """

    return value.to_bytes(width, byteorder='little').hex()


def int2varinthex(value):
    """
    Convert an unsigned integer to little endian varint ASCII hex string.
    Args:
        value (int): value
    Returns:
        string: ASCII hex string
    """

    if value < 0xfd:
        return int2lehex(value, 1)
    elif value <= 0xffff:
        return "fd" + int2lehex(value, 2)
    elif value <= 0xffffffff:
        return "fe" + int2lehex(value, 4)
    else:
        return "ff" + int2lehex(value, 8)


def tx_encode_coinbase_height(height):
    """
    Encode the coinbase height, as per BIP 34:
    https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
    Arguments:
        height (int): height of the mined block
    Returns:
        string: encoded height as an ASCII hex string
    """

    width = (height.bit_length() + 7) // 8

    return bytes([width]).hex() + int2lehex(height, width)


def bitcoinaddress2hash160(addr):
    """
    Convert a Base58 Bitcoin address to its Hash-160 ASCII hex string.
    Args:
        addr (string): Base58 Bitcoin address
    Returns:
        string: Hash-160 ASCII hex string
    """

    table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    hash160 = 0
    addr = addr[::-1]
    for i, c in enumerate(addr):
        hash160 += (58 ** i) * table.find(c)

    # Convert number to 50-byte ASCII Hex string
    hash160 = "{:050x}".format(hash160)

    # Discard 1-byte network byte at beginning and 4-byte checksum at the end
    return hash160[2:50 - 8]


def little_to_big(value):
    #     value = codecs.encode(bytes.fromhex(value), "hex").decode('ascii')
    ba = bytearray.fromhex(value)
    ba.reverse()
    s = ''.join(format(x, '02x') for x in ba)
    return s


def block_compute_raw_hash(header):
    """
    Compute the raw SHA256 double hash of a block header.
    Arguments:
        header (bytes): block header
    Returns:
        bytes: block hash
    """

    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]


# def tx_encode_coinbase_height(height):
#     """
#     Encode the coinbase height, as per BIP 34:
#     https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
#     Arguments:
#         height (int): height of the mined block
#     Returns:
#         string: encoded height as an ASCII hex string
#     """
#
#     width = (height.bit_length() + 7) // 8
#
#     return bytes([width]).hex() + int2lehex(height, width)


def tx_make_coinbase(coinbase_script, address, fee, height):
    """
    Create a coinbase transaction.
    Arguments:
        coinbase_script (string): arbitrary script as an ASCII hex string
        address (string): Base58 Bitcoin address
        value (int): coinbase value
        height (int): mined block height
    Returns:
        string: coinbase transaction as an ASCII hex string
    """

    # See https://en.bitcoin.it/wiki/Transaction

    # version = 2
    coinbase_script = tx_encode_coinbase_height(height) + coinbase_script

    # Create a pubkey script
    # OP_DUP OP_HASH160 <len to push> <pubkey> OP_EQUALVERIFY OP_CHECKSIG
    pubkey_script = "76" + "a9" + "14" + bitcoinaddress2hash160(address) + "88" + "ac"

    tx = ""
    # version
    tx += "01000000" #int2lehex(version, 4)
    # in-counter
    tx += "01" #"000101"
    # input[0] prev hash
    tx += "0" * 64
    # input[0] prev seqnum
    tx += "ffffffff"
    # input[0] scriptsig len
    tx += int2varinthex(len(coinbase_script) // 2)
    # input[0] scriptsig
    tx += coinbase_script
    # input[0] seqnum
    tx += "ffffffff"
    # out-counter
    tx += "01"  ##### cantidad de transacciones
    # output[0] value
    tx += int2lehex(fee, 8)  # value of fees
    # output[0] script len
    tx += int2varinthex(len(pubkey_script) // 2)
    # output[0] script
    tx += pubkey_script
    # lock-time
    tx += "00000000"

    return tx


def block_make_header(block):
    """
    Make the block header.
    Arguments:
        block (dict): block template
    Returns:
        bytes: block header
    """

    header = b""

    # Version
    header += struct.pack("<L", block['version'])
    # Previous Block Hash
    header += bytes.fromhex(block['previousblockhash'])[::-1]
    # Merkle Root Hash
    header += bytes.fromhex(block['merkleroot'])[::-1]
    # Time
    header += struct.pack("<L", block['curtime'])
    # Target Bits
    header += bytes.fromhex(block['bits'])[::-1]
    # Nonce

    header += struct.pack("<L", block['nonce'])

    return header


def to_coinbase_script(message):
    coinbase_byte = message.encode('ascii')
    scriptsig = unhexlify(coinbase_byte).hex()
    return scriptsig


def block_make_submit(block):
    """
    Format a solved block into the ASCII hex submit format.
    Arguments:
        block (dict): block template with 'nonce' and 'hash' populated
    Returns:
        string: block submission as an ASCII hex string
    """

    submission = ""

    # Block header
    submission += block_make_header(block).hex()
    # Number of transactions as a varint
    submission += int2varinthex(len(block['transactions']))
    # Concatenated transactions data
    for tx in block['transactions']:
        submission += tx['data']

    return submission


def mining(nonce, extranonce):
    block_template = __block_template
    message = __message
    mess = __mess
    address = __address

    # print('/SOLO Mined #' + mess + '/' + message)
    coinbase_message = ('/SOLO Mined #' + mess + '/' + message).encode().hex()
    coinbase_tx = {}
    block_template['transactions'].insert(0, coinbase_tx)
    block_template['nonce'] = 0
    target_hash = block_bits2target(block_template['bits'])

    coinbase_script = to_coinbase_script(coinbase_message) + int2lehex(extranonce, 4)
    coinbase_tx['data'] = tx_make_coinbase(coinbase_script, address, block_template['coinbasevalue'],
                                           block_template['height'])
    coinbase_tx['hash'] = tx_compute_hash(coinbase_tx['data'])

    merkle = []
    for tx in block_template['transactions']:
        while tx.get('hash') == None:
            pass
        merkle.append(tx['hash'])
    block_template['merkleroot'] = tx_compute_merkle_root(merkle)
    # block_template['merkleroot'] = tx_compute_merkle_root([tx['hash'] for tx in block_template['transactions']])
    _block_header = block_make_header(block_template)

    # print("nonce: {} | extranonce: {}".format(nonce, extranonce))
    block_header = _block_header[0:76] + nonce.to_bytes(4, byteorder='little')
    # block_header = _block_header[0:76] + int(nonce.encode(encoding='utf-8'), 16).to_bytes(4, byteorder='little')
    block_hash = block_compute_raw_hash(block_header)

    if block_hash < target_hash:
        block_template['nonce'] = nonce
        # block_template['nonce'] = int(nonce, 16)
        block_template['hash'] = block_hash.hex()
        print("Solved a block! Block hash: {}".format(block_template['hash']))
        submission = block_make_submit(block_template)
        # print("Submitting:", submission, "\n")
        response = rpc_submitblock(submission)
        if response is not None:
            print("Submission Error: {}".format(response))
            # break
        print(block_template["hash"])
        return block_template['hash']
    return None


def working(lon):
    df_nonce = __df_nonce
    df_extranonce = __df_extranonce
    # _message = __message
    # __message = set_message()
    with ThreadPoolExecutor(max_workers=np.compat.long(len(df_nonce)), initializer=set_message, initargs=(lon, )) as executor:
        # with ThreadPoolExecutor(np.compat.long(len(df_nonce) * len(df_extranonce))) as executor:
        for result in executor.map(mining, df_nonce, df_extranonce):
            if result is not None:
                mined_block = result
                return mined_block
                # break


def random_message(lon):
    msg = ""
    for i in range(lon):
        r = np.random.randint(128, 254)
        c = chr(r)
        msg += c
    return msg


def set_message(lon):
    global __message
    __message = random_message(lon)


def set_global(_block_template, _mess, _address, _df_nonce, _df_extranonce):
    global __block_template
    global __mess
    global __address
    global __df_nonce
    global __df_extranonce
    __block_template = _block_template
    __mess = _mess
    __address = _address
    __df_nonce = _df_nonce
    __df_extranonce = _df_extranonce



def main():
# if __name__ == "__main__":

    # global RPC_URL
    global message
    global address
    global block_template


# def main():
    print("#################################\n"
          "## Welcome to breaking bitcoin ##\n"
          "#################################\n")

    df_nonce = pd.read_csv('freq_nonce.csv', encoding="utf-8")
    df_extranonce = pd.read_csv('freq_extranonce.csv', encoding="utf-8")
    df_nonce['comb'] = df_nonce['comb'].apply(lambda x: np.compat.long(x, 16)) #optional

    url = ""
    while len(str(url)) == 0:
        url = input('URL de Bitcoin Core: ')
        if url == "":
            url = "http://localhost:8332"

    user = ""
    while len(str(user)) == 0:
        user = input('Introduce el usuario RPC: ')
    
    password = ""
    while len(str(password)) == 0:
        password = input('Introduce la pasword RPC: ')
    
    
    RPC_URL = os.environ.get("RPC_URL", url)
    RPC_USER = os.environ.get("RPC_USER", user)
    RPC_PASS = os.environ.get("RPC_PASS", password)

    # nonce
    use_nonce = ""
    while str(use_nonce) != "si" and str(use_nonce) != "no":
        use_nonce = input('utilizar lista de nonces? (si/no): ')

    if use_nonce == "si":
        y_nonce = 0
        while int(y_nonce) > len(df_nonce) - 1 or int(y_nonce) < 1:
            y_nonce = input('cantidad de nonces (min=1, max={}): '.format(len(df_nonce) - 1))

        random_nonce = ""
        while str(random_nonce) != "si" and str(random_nonce) != "no":
            random_nonce = input('nonce aleatorio? (si/no): ')
        if random_nonce == "si":
            random_nonce = True
        elif random_nonce == "no":
            random_nonce = False

        if random_nonce is True:
            x_nonce = random.randint(0, len(df_nonce)-int(y_nonce))
            df_nonce = df_nonce.iloc[np.random.permutation(len(df_nonce))]
            df_nonce = df_nonce.iloc[x_nonce:int(x_nonce) + int(y_nonce)]['comb']
        else:
            df_nonce = df_nonce.iloc[0:int(y_nonce)]['comb']

    elif use_nonce == "no":
        y_nonce = 0
        while int(y_nonce) <= 0:
            y_nonce = input('cantidad de nonces (min=1): ')

        ini_nonce = -1
        while int(ini_nonce) <= -1:
            ini_nonce = input('extraonce inicial (min=0): ')

        df_nonce = list(range(np.compat.long(ini_nonce), np.compat.long(ini_nonce) + np.compat.long(y_nonce)))


    # extranonce
    use_extranonce = ""
    while str(use_extranonce) != "si" and str(use_extranonce) != "no":
        use_extranonce = input('utilizar lista de extranonces? (si/no): ')

    if use_extranonce == "si":
        y_extranonce = 0
        while int(y_extranonce) <= 0 or int(y_extranonce) > len(df_extranonce) - 1:
            y_extranonce = input('cantidad de extranonces (min=1, max={}): '.format(len(df_extranonce)-1))

        random_extranonce = ""
        while str(random_extranonce) != "si" and str(random_extranonce) != "no":
            random_extranonce = input('extranonce aleatorio? (si/no): ')
        if random_extranonce == "si":
            random_extranonce = True
        elif random_extranonce == "no":
            random_extranonce = False

        if random_extranonce is True:
            x_extranonce = random.randint(0, len(df_extranonce) - int(y_extranonce))
            df_extranonce = df_extranonce.iloc[np.random.permutation(len(df_extranonce))]
            df_extranonce = df_extranonce.iloc[x_extranonce:int(x_extranonce) + int(y_extranonce)]['extranonce']
        else:
            df_extranonce = df_extranonce.iloc[0:int(y_extranonce)]['extranonce']

    elif use_extranonce == "no":
        y_extranonce = 0
        while int(y_extranonce) <= 0:
            y_extranonce = input('cantidad de extranonces (min=1): ')

        ini_extranonce = -1
        while int(ini_extranonce) <= -1:
            ini_extranonce = input('extraonce inicial (min=0): ')

        df_extranonce = list(range(np.compat.long(ini_extranonce), np.compat.long(ini_extranonce) + np.compat.long(y_extranonce)))


    mess = ""
    while str(mess) == "":
        mess = input('Introduce una frase de minado: ')

    size_message = -1
    while str(size_message) == "" or int(size_message) < 1:
        size_message = input('cantidad de mensajes: (min=1) ')


    address = ""
    while str(address) == "":
        address = input('Introduce tu dirección de bitcoin: ')


    mined_block = None
    while mined_block is None:

        block_template = rpc_getblocktemplate()

        if sys.platform.__contains__("win"):
            plat = "cls"
        else:
            plat = "clear"
        # ini = time.time()
        ini = timeit.default_timer()

        with ProcessPoolExecutor(max_workers=12, initializer=set_global, initargs=(block_template, mess, address, df_nonce, df_extranonce,)) as executor:
            futures = [executor.submit(working, lon) for lon in range(int(size_message))]
            for future in futures:
                if future.result() != None:
                    mined_block = future.result()
                    future.done()
                    break


        # fin = time.time()
        fin = timeit.default_timer()
        os.system(plat)
        print("#################################\n"
              "## Welcome to breaking bitcoin ##\n"
              "#################################\n")
        print("{} nonces | {} extranonces | {} segundos\nbloque: {} | tamaño message: {}".format(len(df_nonce),len(df_extranonce),(fin - ini),block_template['height'], size_message))

        seg = int(fin - ini)
        # minutes = int(seg / 60)
        now = datetime.now()
        if (fin - ini) < 1:
            pass
        elif (600 / seg) < 1:
            print("Demasiado tiempo de minado")
            # return None
            break
        elif now.minute % 10 != 0:
            if (600 / seg) < 2:
                seconds = ((600 / seg) - 1) * seg
                print("esperando {} segundos...".format(int(seconds)))
                time.sleep(seconds)
                now = datetime.now()
                while now.second % 10 != 0:
                    time.sleep(0.1)
                    now = datetime.now()

    if mined_block is not None:
        print("Felicidades has minado!\n{}".format(mined_block))


if __name__ == "__main__":
    main()
    # asyncio.run(main())