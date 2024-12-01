import itertools as it
from base64 import b64decode
from Crypto.Cipher import AES

CHARACTER_FREQ = {
    "a": 0.0651738,
    "b": 0.0124248,
    "c": 0.0217339,
    "d": 0.0349835,
    "e": 0.1041442,
    "f": 0.0197881,
    "g": 0.0158610,
    "h": 0.0492888,
    "i": 0.0558094,
    "j": 0.0009033,
    "k": 0.0050529,
    "l": 0.0331490,
    "m": 0.0202124,
    "n": 0.0564513,
    "o": 0.0596302,
    "p": 0.0137645,
    "q": 0.0008606,
    "r": 0.0497563,
    "s": 0.0515760,
    "t": 0.0729357,
    "u": 0.0225134,
    "v": 0.0082903,
    "w": 0.0171272,
    "x": 0.0013692,
    "y": 0.0145984,
    "z": 0.0007836,
    " ": 0.1918182,
}


def singlechar_xor(input_bytes, key):
    return bytes(char ^ key for char in input_bytes)


def get_score(input_bytes):
    return sum(CHARACTER_FREQ.get(chr(byte).lower(), 0) for byte in input_bytes)


def brute_force(ciphertext):
    candidates = []
    for candidate in range(256):
        plaintext = singlechar_xor(ciphertext, candidate)
        score = get_score(plaintext)

        candidates.append((score, candidate, plaintext))

    return sorted(candidates, reverse=True)[0]

def test_brute_force():
    input_hex = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )

    score, candidate, plaintext = brute_force(input_hex)

    assert plaintext == b"Cooking MC's like a pound of bacon"

def repeating_key_xor(input_bytes: bytes, key: bytes):
    bytes_out = []
    for i in range(len(input_bytes)):
        xord = input_bytes[i] ^ key[i % len(key)]
        bytes_out.append(xord)
    return bytes(bytes_out)


def test_repeating_key_xor():
    expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    actual = repeating_key_xor(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b"ICE").hex()
    assert expected == actual

def hamming_distance(in1: bytes, in2: bytes) -> int:
    return sum([bin(by).count('1') for by in repeating_key_xor(in1, in2)])

def find_key_length(bytes_in: bytes, blocks: int):
    min_score = 10
    key_length = 0
    for keysize in range(2, 40):
        chunks = [bytes_in[start:start + keysize] for start in range(0, len(bytes_in), keysize)]
        subgroup = chunks[:blocks]
        combinations = list(it.combinations(subgroup, 2)) # iterators are stateful, can only be consumed once
        average_score = (sum(hamming_distance(a, b) for a,b in combinations) / sum(1 for _ in combinations)) / keysize
        if average_score < min_score:
            min_score = average_score
            key_length = keysize
    return key_length

def find_key(bytes_in: bytes, key_length: int) -> bytes:
    blocks = [bytes_in[start:start + key_length] for start in range(0, len(bytes_in), key_length)]
    key = []
    for n in range(key_length):
        transposed_block = []
        for block in blocks:
            try:
                transposed_block.append(block[n])
            except IndexError:
                transposed_block.append(0)
        _, char, _ = brute_force(bytes(transposed_block))
        key.append(char)
    return bytes(key)

def break_repeating_key_xor():
    with open("input", "r") as f:
        bytes_in_file = b64decode(f.read())
        key_length = find_key_length(bytes_in_file, 4)
        key = find_key(bytes_in_file, key_length)
        print(repeating_key_xor(bytes_in_file, key))

def aes_ecb_dec(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def aes_ecb_enc(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def decrypt_aes_ecb():
    with open("input_07", "r") as f:
        data_b64 = f.read()
    ciphertext = b64decode(data_b64)
    plaintext = aes_ecb_dec(b"YELLOW SUBMARINE", ciphertext)
    print(f"{plaintext=}")

def bytes_to_blocks(bytes_in: bytes, block_size: int, quiet=True) -> list[bytes]:
    blocks = [bytes_in[i:i+block_size] for i in range(0, len(bytes_in), block_size )]
    if not quiet:
        print(f"Chunked input with {block_size=} into {blocks=}")
    return blocks

def detect_aes_ecb():
    with open("input_08", "r") as f:
        lines = [bytes.fromhex(line.strip()) for line in f]
    
    for i, line in enumerate(lines):
        blocks_no = len(line) // 16 # block size with AES in ECB mode
        unique_blocks = len(set(bytes_to_blocks(line, 16))) # set dedupes elements in a list
        if (blocks_no - unique_blocks) > 0:
            print(f"Line {i} has repeated blocks and is likely encrypted using AES in ECB mode.")

