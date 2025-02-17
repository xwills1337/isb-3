import json

settings = {
    'initial_file': 'files/initial_file.txt',
    'encrypted_file': 'files/encrypted_file.txt',
    'decrypted_file': 'files/decrypted_file.txt',
    'symmetric_key': 'files/symmetric_key.txt',
    'nonce': 'files/nonce.txt',
    'public_key': 'files/public_key.pem',
    'private_key': 'files/private_key.pem'
}


if __name__ == "__main__":
    with open('settings.json', 'w') as fp:
        json.dump(settings, fp)
