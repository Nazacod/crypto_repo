# SHA-3 hash function constants
r = 1600
c = 2
n = 24
b = r // 8
w = b // 8
l = int(w * 8 / 2)

# Round constants
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

# Theta function
def theta(A):
    C = [0] * 5
    D = [0] * 5
    for x in range(5):
        C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
    for x in range(5):
        D[x] = C[(x - 1) % 5] ^ rotate_left(C[(x + 1) % 5], 1)
    for x in range(5):
        for y in range(5):
            A[x][y] ^= D[x]
    return A

# Bit rotation function
def rot(x, y):
    return ((x << y) | (x >> (w - y))) % (1 << w)

# Rho function
def rho(A):
    for i in range(1, 25):
        x, y = P[i]
        A[x][y] = rot(A[x][y], r[i])
    return A

# Rho and Pi functions
def rho_and_pi(A):
    B = [[0] * 5 for i in range(5)]
    for x in range(5):
        for y in range(5):
            B[y][(2*x + 3*y) % 5] = rotate_left(A[x][y], rho[x][y])
    return B

# Chi function
def chi(A):
    B = [[0] * 5 for i in range(5)]
    for x in range(5):
        for y in range(5):
            B[x][y] = A[x][y] ^ ((A[(x + 1) % 5][y] ^ 1) & A[(x + 2) % 5][y])
    return B

# Iota function
def iota(A, i):
    A[0][0] ^= RC[i]
    return A

# Rotation function
def rotate_left(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

# SHA-3 hash function
def sha3_256(message):
    # Padding
    message += b'\x06'
    while len(message) % b != b - 1:
        message += b'\x00'
    message += b'\x80'

    # Initialization
    S = [[0] * 5 for i in range(5)]

    # Absorbing phase
    for i in range(0, len(message), b):
        M = message[i:i+b]
        for x in range(5):
            for y in range(5):
                if x + 5*y < len(M)//w:
                    S[x][y] ^= int.from_bytes(M[w*(x+5*y):w*(x+5*y)+w], 'little')

        S = rho_and_pi(S)
        S = theta(S)
        for i in range(n):
            S = chi(S)
            S[0][0] ^= RC[i]
        S = iota(S, i)

    # Squeezing phase
    hash_value = b''
    while len(hash_value) < 32:
        output = b''
        for x in range(5):
            for y in range(5):
                if len(output) < b:
                    output += int.to_bytes(S[x][y], w, 'little')
        hash_value += output
        if len(hash_value) < 32:
            S = rho_and_pi(S)
            S = theta(S)
            for i in range(n):
                S = chi(S)
                S[0][0] ^= RC[i]
            S = iota(S, i)

    return hash_value[:32]

msg = str.encode(input())
print(msg)

print(sha3_256(msg))