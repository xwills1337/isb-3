import logging
from os import urandom
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

logger = logging.getLogger()
logger.setLevel('INFO')


def symmetric_generate_keys() -> tuple:
    """
    функция генерирует ключ и nonce для симметричного шифрования
    :return: ключ и nonce
    """
    key = urandom(32)
    nonce = urandom(16)
    logging.info(f'Сгенерированы ключи для симметричного шифрования')
    return key, nonce


def symmetric_encrypt(text: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    функция шифрует текст алгоритмом симметричного шифрования ChaCha20, с помощью ключа и nonce
    :param text: текст, который шифруем
    :param key: ключ
    :param nonce: nonce
    :return: зашифрованный текст
    """
    padder = padding.ANSIX923(64).padder()
    text_padded = padder.update(text) + padder.finalize()
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    text_encrypted = encryptor.update(text_padded) + encryptor.finalize()
    logging.info(f'Текст зашифрован алгоритмом симметричного шифрования ChaCha20')
    return text_encrypted


def symmetric_decrypt(text: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    функция расшифровывает симметрично зашифрованный текст, с помощью ключа и nonce
    :param text: зашифрованный текст
    :param key: ключ
    :param nonce: nonce
    :return: возвращает расшифрованный текст
    """
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    text_decrypted = decryptor.update(text) + decryptor.finalize()
    unpadder = padding.ANSIX923(64).unpadder()
    text_unpadded_decrypted = unpadder.update(text_decrypted) + unpadder.finalize()
    logging.info(f'Текст, зашифрованный алгоритмом симметричного шифрования ChaCha20, расшифрован')
    return text_unpadded_decrypted
