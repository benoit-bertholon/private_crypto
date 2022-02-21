import argparse
from pathlib import Path
import secrets
import hashlib
import os
import requests

p = 2**256 - 2**32 - 977
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
G = [Gx, Gy]
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
bitcoin_b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
bitcoin_b58chars_values = dict((c, val) for val, c in enumerate(bitcoin_b58chars))
PUBKEY_ADDRESS_MAIN = 0

def modInv(n, p):
    return pow(n, p - 2, p)

def secp256k1_add(P, Q):
    if P[0] % p == 0 and P[1] % p == 0:
        return Q
    if Q[0] % p == 0 and Q[1] % p == 0:
        return P

    if P[0] == Q[0] and P[1] == Q[1]:
        if P[1] == 0:
            return [0, 0]
        l = (3 * P[0]**2) * modInv((2 * P[1]), p)
    elif P[0] == Q[0]:
        return [0, 0]
    else:
        l = (P[1] - Q[1]) * modInv((P[0] - Q[0]), p)

    x = l**2 - (P[0] + Q[0])
    y = l * (Q[0] - x) - Q[1]
    return [x % p, y % p]
    
def secp256k1_mul(s, P):
    Q = (0, 0)  # Neutral element
    while s > 0:
        if s & 1:
            Q = secp256k1_add(Q, P)
        P = secp256k1_add(P, P)
        s >>= 1
    return Q


def hash_160(public_key):
    """perform the sha256 operation followed by the ripemd160 operation"""
    hash256 = hashlib.sha256(public_key).digest()
    return hashlib.new('ripemd160', hash256).digest()


def wif_export_bitcoin(privkey_bytearray):
    """convert a private key in bytearray into the bitcoin wif format"""
    first = b"\x80"
    privkey = first + privkey_bytearray
    privkey = privkey + b"\x01"
    privkey = privkey + doublesha256(privkey)[:4]
    privkey_num = int.from_bytes(privkey, "big")
    privkey_wif = base58encode(privkey_num)
    return privkey_wif
    
    
def encode_base58check(content, preserve_leading_zeros=True):
    data = content + doublesha256(content)[:4]
    leading_zeros = None
    if preserve_leading_zeros:
        leading_zeros = count_leading_values(data, 0)
    return base58encode(int.from_bytes(data, "big"), leading_zeros=leading_zeros)

def count_leading_values(lst, char):
    """count the number of char at the beginnig of the string/bytearray lst"""
    n = 0
    l = len(lst)
    while n < l and lst[n] == char:
        n += 1
    return n

def base58encode(value, leading_zeros=None, length=None):
        
    result = ""
    while value != 0:
        div, mod = divmod(value, 58)
        result = bitcoin_b58chars[mod] + result
        value = div
    if leading_zeros:
        return bitcoin_b58chars[0] * leading_zeros + result
    if length is not None:
        result = bitcoin_b58chars[0] * (length-len(result)) + result
    return result

def doublesha256(data):
    """perform double sha operation often used in bitcoin"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def generate_key(args):
    private_key = secrets.token_bytes(32)
    private_key_num = int.from_bytes(private_key,"big")
    P = secp256k1_mul(private_key_num, G)
    public_key = bytes([2 + (P[1] & 1)]) + P[0].to_bytes(32, "big")
    address = encode_base58check(PUBKEY_ADDRESS_MAIN.to_bytes(1, "big") + hash_160(public_key), preserve_leading_zeros=True)
    wif = wif_export_bitcoin(private_key)
    print(private_key.hex(), wif, address)
    open(args.wallet,"a").write(address+ ","+wif+os.linesep)

def check_balance(args):
    total = 0
    for line in open(args.wallet).readlines():
        addr, priv = line.split(",")
        r = requests.get('https://blockchain.info/rawaddr/'+addr)
        data = r.json()
        time.sleep(15) # rate limit https://www.blockchain.com/api/q
        print(addr, data["final_balance"])
        total += float( data["final_balance"])
    print ("total: %f BTC" % total)
        

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--wallet', default=Path('~/crypto_wallet.txt').expanduser(), help='Wallet file')
    subparsers = parser.add_subparsers()
    generate_key_parser = subparsers.add_parser('generate-key')
    generate_key_parser.set_defaults(func=generate_key)
    check_balance_parser = subparsers.add_parser('check-balance')
    check_balance_parser.set_defaults(func=check_balance)

    args = parser.parse_args()
    args.func(args) 

    
    
