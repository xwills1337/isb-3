from asymmetric import asymmetric_generate_keys, asymmetric_encrypt, asymmetric_decrypt
from symmetric import symmetric_generate_keys, symmetric_encrypt, symmetric_decrypt
import argparse
from file_manager import FileManager


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', type=str,
                        help='Использовать собственный файл с настройками (Указать путь к файлу)')
    program_mode_group = parser.add_mutually_exclusive_group(required=True)
    program_mode_group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
    program_mode_group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
    program_mode_group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
    args = parser.parse_args()
    if args.settings:
        file_manager = FileManager(args.settings)
    else:
        file_manager = FileManager()
    if args.generation:
        symmetric_key, nonce = symmetric_generate_keys()
        private_key, public_key = asymmetric_generate_keys()
        file_manager.save_asymmetric_private_key(private_key)
        file_manager.save_asymmetric_public_key(public_key)
        encrypted_symmetric_key = asymmetric_encrypt(symmetric_key, public_key)
        encrypted_nonce = asymmetric_encrypt(nonce, public_key)
        file_manager.write_text(encrypted_symmetric_key, file_manager.get_symmetric_key_path)
        file_manager.write_text(encrypted_nonce, file_manager.get_nonce_path)
    elif args.encryption:
        private_key = file_manager.read_asymmetric_private_key()
        encrypted_symmetric_key = file_manager.read_text(file_manager.get_symmetric_key_path)
        encrypted_nonce = file_manager.read_text(file_manager.get_nonce_path)
        symmetric_key = asymmetric_decrypt(encrypted_symmetric_key, private_key)
        nonce = asymmetric_decrypt(encrypted_nonce, private_key)
        text = file_manager.read_text(file_manager.get_initial_file_path)
        encrypted_text = symmetric_encrypt(text, symmetric_key, nonce)
        file_manager.write_text(encrypted_text, file_manager.get_encrypted_file_path)
    elif args.decryption:
        private_key = file_manager.read_asymmetric_private_key()
        encrypted_symmetric_key = file_manager.read_text(file_manager.get_symmetric_key_path)
        encrypted_nonce = file_manager.read_text(file_manager.get_nonce_path)
        symmetric_key = asymmetric_decrypt(encrypted_symmetric_key, private_key)
        nonce = asymmetric_decrypt(encrypted_nonce, private_key)
        encrypted_text = file_manager.read_text(file_manager.get_encrypted_file_path)
        decrypted_text = symmetric_decrypt(encrypted_text, symmetric_key, nonce)
        file_manager.write_text(decrypted_text, file_manager.get_decrypted_file_path)
