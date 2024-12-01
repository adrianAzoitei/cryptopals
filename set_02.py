from base64 import b64decode
from os import urandom
from random import choice, randint
from collections.abc import Callable
from Crypto.Cipher import AES
from set_01 import repeating_key_xor, bytes_to_blocks, aes_ecb_dec, aes_ecb_enc

class PaddingError(Exception):
    pass

def pkcs7(bytes_in: bytes, block_size: int = 16, verbose: bool = False) -> bytes:
    padding_length = block_size - (len(bytes_in) % block_size)
    if verbose:
        print(f"{block_size=}")
        print(f"Input length: {len(bytes_in)}")
        print(f"{padding_length=}")
    return bytes_in + bytes([padding_length]) * padding_length
    
def strip_pkcs7(bytes_in: bytes, verbose: bool = False) -> bytes:
    last_byte = bytes_in[-1]
    if verbose:
        print(bytes_in)
        print(f"{last_byte=}")
    if last_byte == 0 or len(bytes_in) < last_byte or not bytes_in.endswith(bytes([last_byte]*last_byte)):
        raise PaddingError
    return bytes_in[:-last_byte]

def aes_cbc_enc(iv: bytes, key: bytes, plaintext: bytes) -> bytes:
    prev_ciphertext_block = iv
    blocks = bytes_to_blocks(plaintext, AES.block_size)
    ciphertext = b''
    for block in blocks:
        prev_ciphertext_block = aes_ecb_enc(key, repeating_key_xor(block, prev_ciphertext_block))
        ciphertext += prev_ciphertext_block
    return ciphertext

def aes_cbc_dec(iv: bytes, key: bytes, ciphertext: bytes) -> bytes:
    blocks = bytes_to_blocks(ciphertext, AES.block_size)
    prev_ciphertext_block = iv
    plaintext = b''
    for block in blocks:
        raw = aes_ecb_dec(key, block)
        plaintext += repeating_key_xor(raw, prev_ciphertext_block)
        prev_ciphertext_block = block
    return strip_pkcs7(plaintext)

def decrypt_cbc_encrpted_cipher(verbose=True):
    with open("input_10", "r") as f:
        b64data = f.read()
    ciphertext = b64decode(b64data)
    key = b'YELLOW SUBMARINE'
    iv = bytes(AES.block_size) # b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    plaintext = aes_cbc_dec(iv, key, ciphertext)
    if verbose:
        print(plaintext.decode('ascii'))
    return plaintext

def test_aes_cbc():
    with open("input_10", "r") as f:
        b64data = f.read()
    key = b'YELLOW SUBMARINE'
    iv = bytes(AES.block_size)
    ciphertext = b64decode(b64data)
    assert ciphertext == aes_cbc_enc(iv, key, pkcs7(aes_cbc_dec(iv, key, ciphertext)))

EncryptionOracle = Callable[[bytes], bytes] # Callable[[list of arguments], return type]
def get_encryption_oracle(verbose: bool = False) -> tuple[str, EncryptionOracle]:
    mode = choice(("ECB", "CBC"))
    if verbose:
        print(f"{mode=}")

    def encryption_oracle(plaintext: bytes) -> bytes:
        key = urandom(16) # key size is 16
        prefix = urandom(randint(5,10))
        suffix = urandom(randint(5,10))
        plaintext = pkcs7(prefix + plaintext + suffix)
        if mode == "ECB":
            return aes_ecb_enc(key, plaintext)
        else:
            return aes_cbc_enc(urandom(AES.block_size), key, plaintext)
    return mode, encryption_oracle

def detector(enc_func: EncryptionOracle) -> str:
    # craft a message long enough to produce two repeated plaintext blocks, no matter the length of the prefix
    # generate two full blocks + a partial block (min possible length of the preffix) of 0 bytes
    # a larger text would work, such as: plaintext = bytes(3 * AES.block_size)
    # but the smallest input that fulfills this requirement consists of
    # two full blocks + a partial block as long as block_size - min_prefix_length
    # or visually: 00000[00000000000] [0000000000000000] [0000000000000000]
    plaintext = bytes(2 * AES.block_size + (AES.block_size - 5))
    print(len(plaintext))
    ciphertext = enc_func(plaintext)
    print(len(ciphertext))
    blocks = bytes_to_blocks(ciphertext, AES.block_size)
    if (len(blocks) - len(set(blocks))) > 0:
        return "ECB"
    else:
        return "CBC"

def test_ecb_cbc_oracle():
    for _ in range(5000):
        mode_expected, enc_oracle = get_encryption_oracle()
        mode_actual = detector(enc_oracle)
        assert mode_actual == mode_expected

# CONSISTENT_KEY = ""
# def ecb_encryption_oracle(plaintext: bytes) -> bytes:
#     suffix = """
#         Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
#         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
#         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
#         YnkK
#         """
#     plaintext = pkcs7(plaintext + b64decode(suffix))
#     return aes_ecb_enc(key, plaintext)


from datetime import datetime as dt, timedelta

print(dt.now() + timedelta(days=14))
