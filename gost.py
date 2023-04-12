import random
from tinyec import registry
from gostcrypto import gosthash

def gost_hash(data_):
    return gosthash.new('streebog256', data=data_).digest()

def int_from_hash(data):
    return int.from_bytes(data, byteorder='big')

def generate_key_pair(curve):
    private_key = random.randint(1, curve.field.n - 1)
    public_key = private_key * curve.g
    return private_key, public_key

def sign_data(curve, private_key, data):
    e = int_from_hash(gost_hash(data)) % curve.field.n
    while True:
        k = random.randint(1, curve.field.n - 1)
        r = (k * curve.g).x % curve.field.n
        if r == 0:
            continue
        s = (private_key * r - k * e) % curve.field.n
        if s == 0:
            continue
        return r, s

def verify_signature(curve, public_key, data, signature):
    r, s = signature
    e = int_from_hash(gost_hash(data)) % curve.field.n
    v = pow(e, -1, curve.field.n)
    z1 = (s * v) % curve.field.n
    z2 = (-r * v) % curve.field.n
    R = z1 * curve.g + z2 * public_key
    return R.x % curve.field.n == r

def main():
    curve = registry.get_curve("brainpoolP256r1")
    data = b'Test message for digital signature'
    private_key, public_key = generate_key_pair(curve)
    signature = sign_data(curve, private_key, data)
    print(f'Signature: {signature}')
    is_valid = verify_signature(curve, public_key, data, signature)
    print(f'Is signature valid? {is_valid}')

if __name__ == '__main__':
    main()