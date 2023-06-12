import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger()
logger.setLevel('INFO')


def asymmetric_generate_keys() -> tuple:
    """
    функция генерирует ключи для асимметричного шифрования
    :return: приватный ключ и публичный ключ
    """
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_private = keys
    key_public = keys.public_key()
    logging.info(f'Сгенерированы ключи асимметричного шифрования')
    return key_private, key_public


def asymmetric_encrypt(text: bytes, key_public) -> bytes:
    """
    функция производит асимметричное шифрование по публичному ключу
    :param text: текст, который шифруем
    :param key_public: публичный ключ
    :return: зашифрованный текст
    """
    text_encrypted = key_public.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                           algorithm=hashes.SHA256(), label=None))
    logging.info(f'Текст зашифрован алгоритмом асимметричного шифрования')
    return text_encrypted


def asymmetric_decrypt(text: bytes, key_private) -> bytes:
    """
    функция расшифровывает асимметрично зашифрованный текст, с помощью приватного ключа
    :param text: зашифрованный текст
    :param key_private: приватный ключ
    :return: расшифрованный текст
    """
    text_decrypted = key_private.decrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(), label=None))
    logging.info(f'Текст, зашифрованный алгоритмом асимметричного шифрования, расшифрован')
    return text_decrypted
