from ecdsa import SigningKey, curves
from binascii import a2b_hex, b2a_hex, a2b_uu, b2a_uu
import hashlib
BASE_58_ENCODING = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58encode(input):
    input_int = int(b2a_hex(input),16)
    output = ''
    
    while input_int >= 58:
        input_int, rem = divmod(input_int, 58)
        output = BASE_58_ENCODING[rem] + output
    output = BASE_58_ENCODING[input_int] + output
    
    if input[0] == '\0':
        output = BASE_58_ENCODING[0] + output
        
    return output
    
def base58decode(input):
    place = 0
    total = 0
    for i in reversed(input):
        val = BASE_58_ENCODING.find(i)
        if val < 0:
            raise Exception
        
        total += val * (58**place)
        place += 1
    hexed = hex(total)[2:-1]
    if len(hexed) % 2 == 1:
        hexed = '0' + hexed
    return a2b_hex(hexed)
    
def generate_random_private_key():
    sk = SigningKey.generate(curve=curves.SECP256k1)
    vk = sk.get_verifying_key()
    
    return {'private': b2a_hex(sk.to_string()), 'address': public_to_address(vk.to_string())}
    
def private_to_address(private):
    private_int = int(b2a_hex(private), 16)
    sk = SigningKey.from_secret_exponent(private_int, curves.SECP256k1)
    vk = sk.get_verifying_key()
    return public_to_address(vk.to_string())
    
def public_to_address(public_binary):
    public_key = a2b_hex('04') + public_binary
    sha256_hashed = hashlib.sha256(public_key).digest()
    ripemd160_hashed = hashlib.new('ripemd160', sha256_hashed).digest()
    extended_ripemd160_hashed = a2b_hex('00') + ripemd160_hashed
    sha256_re_hashed_once = hashlib.sha256(extended_ripemd160_hashed).digest()
    sha256_re_hashed_twice = hashlib.sha256(sha256_re_hashed_once).digest()
    address_checksum = sha256_re_hashed_twice[:4]
    binary_address = extended_ripemd160_hashed + address_checksum
    base_58_address = base58encode(binary_address)
    return base_58_address
    
def private_to_wif(private):
    extended_private_key = a2b_hex('80') + private
    sha256_re_hashed_once = hashlib.sha256(extended_private_key).digest()
    sha256_re_hashed_twice = hashlib.sha256(sha256_re_hashed_once).digest()
    address_checksum = sha256_re_hashed_twice[:4]
    binary_address = extended_private_key + address_checksum
    base_58_address = base58encode(binary_address)
    return base_58_address
    
def wif_to_private(wif):
    byte_string = base58decode(wif)
    if byte_string[0] != '\x80':
        raise Exception
        
    checksum = byte_string[-4:]
    without_checksum = byte_string[:-4]
    sha256_re_hashed_once = hashlib.sha256(without_checksum).digest()
    sha256_re_hashed_twice = hashlib.sha256(sha256_re_hashed_once).digest()
    computed_checksum = sha256_re_hashed_twice[:4]
    if checksum != computed_checksum:
        raise Exception
        
    return byte_string[1:-4]

def get_vanity(search):
    while True:
        address = generate_random_private_key()
        if address['address'][:len(search)] == search:
            print 'Found match in {} tries'.format(i)
            print address
            return

private_hex = hashlib.sha256('test').digest()
print b2a_hex(private_hex)
print private_to_address(private_hex)

get_vanity('1btc')