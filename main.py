# coding=utf-8
import asyncio
import ctypes
import functools
import multiprocessing
import threading
import timeit
import base64
import binascii
import codecs
import hashlib
# import scrypt
import json
import os
import random
import struct
import time
import urllib.request
from binascii import unhexlify
from multiprocessing import Process
import argparse
import pandas as pd
from numpy.compat import long
from threading import Thread
import aiohttp
import asyncio
import async_timeout


# JSON-HTTP RPC Configuration
# This will be particular to your local ~/.bitcoin/bitcoin.conf

RPC_URL = os.environ.get("RPC_URL", "http://localhost:8332")
RPC_USER = os.environ.get("RPC_USER", "user")
RPC_PASS = os.environ.get("RPC_PASS", "pass")


################################################################################
# Bitcoin Daemon JSON-HTTP RPC
################################################################################


def rpc(method, params=None):
    """
    Make an RPC call to the Bitcoin Daemon JSON-HTTP server.
    Arguments:
        method (string): RPC method
        params: RPC arguments
    Returns:
        object: RPC response result.
    """

    rpc_id = random.getrandbits(32)
    data = json.dumps({"id": rpc_id, "method": method, "params": params}).encode()
    auth = base64.encodebytes((RPC_USER + ":" + RPC_PASS).encode()).decode().strip()

    requests = urllib.request.Request(RPC_URL, data, {"Authorization": "Basic {:s}".format(auth)})

    with urllib.request.urlopen(requests) as f:
        response2 = json.loads(f.read())

    if response2['id'] != rpc_id:
        raise ValueError("Invalid response id: got {}, expected {:d}".format(response2['id'], rpc_id))
    elif response2['error'] is not None:
        raise ValueError("RPC error: {:s}".format(json.dumps(response2['error'])))

    return response2['result']


async def rpc_getblocktemplate():
    try:
        # await asyncio.sleep(seconds)
        return rpc("getblocktemplate", [{"rules": ["segwit"]}])
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
    return str(h)


def true_to_numbers(cor):
    f = ""
    for j in range(8):
        for z in range(16):
            if cor[j][z] == True:
                f += switch_int_to_h(z)
    return f


def false_to_numbers(cor):
    f = ""
    for j in range(8):
        for z in range(16):
            if cor[j][z] == False:
                f += switch_int_to_h(z)
    return f


def show_numbers(cor):
    f = ""
    for j in range(8):
        for z in range(16):
            if cor[j][z] == (1.):
                f += switch_int_to_h(z)
    return f


def create_nonces(first_nonce, num):
    ini_nonce = long(first_nonce.zfill(3) + "0"*(8 - num), 16)
    fin_nonce = long(first_nonce.zfill(3) + "f"*(8 - num), 16) + 1
    me_nonce = ini_nonce
    list_nonces = []
    # ini = time.time()
    while me_nonce < fin_nonce:
        nonce = hex(me_nonce).zfill(8)
        list_nonces.append(nonce)
        me_nonce += 1
    return list_nonces


def search_hash_time(list_nonces):
    # target_hash_hex = binascii.hexlify(target_hash)
    for nonce in list_nonces:
        block_hash = block_compute_raw_hash(nonce.encode('utf-8')) # sha256
    return None


def miner(block_template, coinbase_message, address, df, x, y):
    df = df.iloc[x:x + y]['comb']
    coinbase_tx = {}
    block_template['transactions'].insert(0, coinbase_tx)
    block_template['nonce'] = 0
    target_hash = block_bits2target(block_template['bits'])
    extranonce = 13

    # while extranonce <= 0xffffffff:
    coinbase_script = to_coinbase_script(coinbase_message) + int2lehex(extranonce, 4)
    coinbase_tx['data'] = tx_make_coinbase(coinbase_script, address, block_template['coinbasevalue'], block_template['height'])
    coinbase_tx['hash'] = tx_compute_hash(coinbase_tx['data'])
    block_template['merkleroot'] = tx_compute_merkle_root([tx['hash'] for tx in block_template['transactions']])
    _block_header = block_make_header(block_template)

    for nonce in df:
        block_header = _block_header[0:76] + int(nonce.encode(encoding='utf-8'), 16).to_bytes(4, byteorder='little')
        block_hash = block_compute_raw_hash(block_header)
        if block_hash < target_hash:
            block_template['nonce'] = int(nonce, 16)
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
    # extranonce += 1
    return None

async def main():
    print("Welcome to breaking bitcoin!")
    df = pd.read_csv('lista_combinaciones_general.csv', encoding="utf-8")

    # parser = argparse.ArgumentParser(description='Breaking bitcoin.')
    # parser.add_argument('-p', '--pos', type=int, required=True, help='posición de la lista')
    # parser.add_argument('-r', '--range', type=int, required=True, help='rango de números a seleccionar')
    # args = parser.parse_args()
    # x = args.pos
    # y = args.range

    x = 0
    y = 1000000
    df = df.iloc[:y]

    coinbase_message = "###Mined by ...@".encode().hex()
    address = "your_address_here"
    mined_block = None

    while mined_block is None:
        ini0 = time.time()
        block_template = await rpc_getblocktemplate()
        mined_block = miner(block_template, coinbase_message, address, df, x, y)
        fin0 = time.time()
        print("Minado en: {}, altura: {}".format(fin0 - ini0, block_template['height']))
    print("Felicidades!\n{}".format(mined_block))

if __name__ == "__main__":
    asyncio.run(main())