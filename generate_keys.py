import ecdsa

def get_curve(name):
    if name == 'SECP112r1':
        return ecdsa.SECP112r1
    if name == 'SECP112r2':
        return ecdsa.SECP112r2
    if name == 'SECP128r1':
        return ecdsa.SECP128r1
    if name == 'SECP160r1':
        return ecdsa.SECP160r1
    if name == 'NIST192p':
        return ecdsa.NIST192p
    if name == 'NIST224p':
        return ecdsa.NIST224p
    if name == 'NIST256p':
        return ecdsa.NIST256p
    if name == 'NIST384p':
        return ecdsa.NIST384p
    if name == 'NIST521p':
        return ecdsa.NIST521p
    if name == 'SECP256k1':
        return ecdsa.SECP256k1
    if name == 'BRAINPOOLP160r1':
        return ecdsa.BRAINPOOLP160r1
    if name == 'BRAINPOOLP192r1':
        return ecdsa.BRAINPOOLP192r1
    if name == 'BRAINPOOLP224r1':
        return ecdsa.BRAINPOOLP224r1
    if name == 'BRAINPOOLP256r1':
        return ecdsa.BRAINPOOLP256r1
    if name == 'BRAINPOOLP320r1':
        return ecdsa.BRAINPOOLP320r1
    if name == 'BRAINPOOLP384r1':
        return ecdsa.BRAINPOOLP384r1
    if name == 'BRAINPOOLP512r1':
        return ecdsa.BRAINPOOLP512r1


def main():
    print("""Available curves:
    "SECP112r1",
    "SECP112r2",
    "SECP128r1",
    "SECP160r1",
    "NIST192p",
    "NIST224p",
    "NIST256p",
    "NIST384p",
    "NIST521p",
    "SECP256k1",
    "BRAINPOOLP160r1",
    "BRAINPOOLP192r1",
    "BRAINPOOLP224r1",
    "BRAINPOOLP256r1",
    "BRAINPOOLP320r1",
    "BRAINPOOLP384r1",
    "BRAINPOOLP512r1",
    """)

    name = input('select curve for keys generation: ')

    curve = get_curve(name)

    signingKey = ecdsa.SigningKey.generate(curve=curve)
    print("signing key: " + signingKey.to_string().hex())
    print("verify key: " + signingKey.verifying_key.to_string().hex())

if __name__ == '__main__':
    main()