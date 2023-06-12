import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


class FileManager:
    @staticmethod
    def read_settings(file_name: str = 'settings.json') -> dict:
        """
        метод считывает файл настроек
        :param file_name: название файла с настройками
        :return: настройки
        """
        settings = None
        try:
            with open(file_name) as json_file:
                settings = json.load(json_file)
            logging.info(f'Настройки считаны из файла {file_name}')
        except OSError as err:
            logging.warning(f'{err} - ошибка при чтении настроек из файла {file_name}')
        return settings

    def __init__(self, settings_file_name: str = 'settings.json'):
        settings = self.read_settings(settings_file_name)
        self.__initial_file_path = settings['initial_file']
        self.__encrypted_file_path = settings['encrypted_file']
        self.__decrypted_file_path = settings['decrypted_file']
        self.__symmetric_key_path = settings['symmetric_key']
        self.__nonce_path = settings['nonce']
        self.__public_key_path = settings['public_key']
        self.__private_key_path = settings['private_key']

    @property
    def get_initial_file_path(self) -> str:
        return self.__initial_file_path

    @property
    def get_encrypted_file_path(self) -> str:
        return self.__encrypted_file_path

    @property
    def get_decrypted_file_path(self) -> str:
        return self.__decrypted_file_path

    @property
    def get_symmetric_key_path(self) -> str:
        return self.__symmetric_key_path

    @property
    def get_nonce_path(self) -> str:
        return self.__nonce_path

    @property
    def get_public_key_path(self) -> str:
        return self.__public_key_path

    @property
    def get_private_key_path(self) -> str:
        return self.__private_key_path

    def save_asymmetric_private_key(self, private_key) -> None:
        """
        метод сохраняет приватный ключ для ассиметричного шифрования
        :param private_key: приватный ключ
        :return: ничего
        """
        try:
            with open(self.__private_key_path, 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))
            logging.info(f'Приватный ключ сохранён в файл {self.__private_key_path}')
        except OSError as err:
            logging.warning(f'{err} - ошибка при сохранении приватного ключа {self.__private_key_path}')

    def read_asymmetric_private_key(self):
        """
        метод считывает сохранённый ранее приватный ключ для ассиметричного шифрования
        :return: приватный ключ
        """
        private_key = None
        try:
            with open(self.__private_key_path, 'rb') as pem_in:
                private_bytes = pem_in.read()
            private_key = load_pem_private_key(private_bytes, password=None)
            logging.info(f'Приватный ключ считан из файла {self.__private_key_path}')
        except OSError as err:
            logging.warning(f'{err} - ошибка при чтении приватного ключа из файла {self.__private_key_path}')
        return private_key

    def save_asymmetric_public_key(self, public_key) -> None:
        """
        метод сохраняет публичный ключ для ассиметричного шифрования
        :param public_key: публичный ключ
        :return: ничего
        """
        try:
            with open(self.__public_key_path, 'wb') as public_out:
                public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
            logging.info(f'Публичный ключ сохранён в файл {self.__public_key_path}')
        except OSError as err:
            logging.warning(f'{err} - ошибка при чтении публичного ключа из файла {self.__public_key_path}')

    def read_asymmetric_public_key(self):
        """
        метод считывает сохранённый ранее публичный ключ для ассиметричного шифрования
        :return: публичный ключ
        """
        public_key = None
        try:
            with open(self.__public_key_path, 'rb') as pem_in:
                private_bytes = pem_in.read()
            public_key = load_pem_public_key(private_bytes)
            logging.info(f'Публичный ключ считан из файла {self.__public_key_path}')
        except OSError as err:
            logging.warning(f'{err} - ошибка при чтении публичного ключа из файла {self.__public_key_path}')
        return public_key

    @staticmethod
    def read_text(file_path: str) -> bytes:
        """
        метод считывает текстовый файл
        :param file_path: путь к файлу
        :return: текст из файла
        """
        text = None
        try:
            with open(file_path, mode='rb') as text_file:
                text = text_file.read()
            logging.info(f'Файл {file_path} прочитан')
        except OSError as err:
            logging.warning(f'{err} - ошибка при чтении файла {file_path}')
        return text

    @staticmethod
    def write_text(text: bytes, file_path: str) -> None:
        """
        метод записывает текст в файл
        :param text: текст
        :param file_path: путь к файлу
        :return: ничего
        """
        try:
            with open(file_path, mode='wb') as text_file:
                text_file.write(text)
            logging.info(f'Текст записан в файл {file_path}')
        except OSError as err:
            logging.warning(f'{err} - ошибка при записи в файл {file_path}')
