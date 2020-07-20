from typing import Union

from .message_wrapper import initialize, save_public_key, get_challenge, get_challenge_response, finalize_challenge, encrypt, decrypt


class MessageWrapper(object):

    def __init__(self, identity_file: str, authorized_keys_folder: str):
        initialize(identity_file, authorized_keys_folder)

    def save_public_key(self, path: str) -> bool:
        return save_public_key(path)

    def get_challenge(self) -> bytes:
        return bytes(bytearray(get_challenge()))

    def get_challenge_response(self, challenge: bytes) -> bytes:
        return bytes(bytearray(get_challenge_response(challenge)))

    def finalize_handshake(self, challenge_response: bytes) -> Union[bytes, None]:
        response_array = finalize_challenge(challenge_response)
        if len(response_array):
            return bytes(bytearray(response_array))

    def encrypt(self, message: bytes) -> bytes:
        return bytes(bytearray(encrypt(message)))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return bytes(bytearray(decrypt(ciphertext)))