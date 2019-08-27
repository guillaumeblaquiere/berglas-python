import base64
import logging
import os

from cryptography.hazmat.backends import default_backend
from google.cloud import storage, kms

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BERGLAS_PREFIX      = 'berglas://'
METADATA_KMS_KEY    = 'berglas-kms-key'
METADATA_ID_KEY     = 'berglas-secret'
GCM_NONCE_SIZE      = 12
CRYPTO_KEY_LOCATION = 'global'
CRYPTO_KEY_RING     = 'berglas'
CRYPTO_KEY          = 'berglas-key'
BLOB_CHUNK_SIZE     = 256 * 1024


def str2b(s: str) -> bytes:
    """
    Converts string to bytes encoding it as UTF-8

    :param s: String to be converted and encoded
    :return: a bytes object encoded
    """
    return bytes(s, "UTF-8")


def b2str(bystr: str) -> str:
    """
    Converts bytes to string decoding it from UTF-8

    :param s: bytes to be converted and decoded
    :return: a string decoded
    """
    return bystr.decode("UTF-8")


def _validate_env_var_prefix(env_var_value: str):
    """
    Check whether env_var_value starts with the pattern berglas://
    :param env_var_value: Berglas reference with the pattern berglas://<bucket>/<object>
    :exception: When object and/or bucket is missing (berglas pattern not respected)
    """

    if not env_var_value.startswith(BERGLAS_PREFIX):
        log_msg = f"No berglas prefix for the env var value {env_var_value}"
        logging.error(log_msg)
        raise Exception(log_msg)


def _validate_project_id(project_id: str):
    """
    Check whether project_id is not empty
    :param project_id: Project ID for creating the storage client.
    :exception: When the project_id is missing/empty
    """

    if project_id == "":
        log_msg = "Project id can't be empty"
        logging.error(log_msg)
        raise Exception(log_msg)


def Replace(project_id: str, env_var_key: str):
    """
    Replace, in the env var, the value of env var key by the deciphered value
    :param project_id: Project ID for creating the storage client.
    :param env_var_key: Key of the env var value to decipher and to replace. Do nothing if key doesn't exist or if the
    value don't start with berglas:// prefix. Value must respect the berglas pattern berglas://<bucket>/<object>
    :return: no return
    :exception: When object and/or bucket is missing (berglas pattern not respected)
    :exception: When deciphering failed, bad dek size or format, bad ciphering text format
    :exception: When the project_id is missing/empty
    :exception: When the env_var_value doesn't respect the pattern
    :exception: When the env_var_value defines a not existing bucket and/or object
    """

    env_var_value: str = os.environ.get(env_var_key)
    if env_var_value == "":
        logging.info(f"No value for the env var key {env_var_key}")
    return

    plaintext = Resolve(project_id, env_var_value)

    os.environ.unsetenv(env_var_key)
    os.environ.setdefault(env_var_key, plaintext)


def _get_bucket_object(env_var_value: str) -> (str, str):
    """
    Split the env_var_value into bucket and object name

    :param env_var_value: should respect this pattern berglas://<bucket>/<object_name>
    :return: the bucket and the object name
    :exception: When object_name and/or bucket is missing (pattern not respected)
    """

    without_prefix = env_var_value[len(BERGLAS_PREFIX):]
    if without_prefix == "":
        log_msg = f"No bucket and object defined in {env_var_value}"
        logging.error(log_msg)
        raise Exception(log_msg)

    splitted = without_prefix.split("/", 2)

    if splitted[1] == "":
        log_msg = f"No object defined in {env_var_value}"
        logging.error(log_msg)
        raise Exception(log_msg)


def _decipher_blob(dek: str, cipher_text: str) -> str:
    """
    Decipher the cipher text with the dek. Use aes GCM algorithm

    :param dek: Data Encryption Key
    :param cipher_text: Content to decrypt with aes GCM cipher
    :return: deciphered plain text
    :exception: When deciphering failed, bad dek size or format, bad ciphering text format
    """

    nonce = cipher_text[:GCM_NONCE_SIZE]
    toDecrypt = cipher_text[GCM_NONCE_SIZE:]

    algo = algorithms.AES(dek)

    cipher = Cipher(
        algo,
        modes.GCM(nonce),
        backend=default_backend()
    )

    decrypter = cipher.decryptor()
    return b2str(decrypter.update(toDecrypt[:-16]))


def _envelope_encrypt(plaintext: bytes) -> (bytes, bytes):
    """
    Generates a unique DEK and encrypts the plaintext with the given key.

    :param plaintext: String to be encrypted
    :return: The encryption key and resulting ciphertext
    """

    # Generate a random 256-bit key.
    key = os.urandom(32)

    # Generate a random 96-bit IV.
    iv = os.urandom(GCM_NONCE_SIZE)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    encrypted_text = encryptor.update(plaintext) + encryptor.finalize()

    # Encrypt the ciphertext with the DEK
    ciphertext = iv + encrypted_text + encryptor.tag

    return (key, ciphertext)


def Resolve(project_id: str, env_var_value: str) -> str:
    """
    Get the object in the bucket (define in the env_var_value) and decipher it

    :param project_id: Project ID for creating the storage client.
    :param env_var_value: Berglas reference with the pattern berglas://<bucket>/<object_name>
    :return: the plaintext value of the deciphered reference.
    :exception: When the project_id is missing/empty
    :exception: When the env_var_value doesn't respect the pattern
    :exception: When the env_var_value defines a not existing bucket and/or object_name
    :exception: When object_name and/or bucket is missing (pattern not respected)
    """

    _validate_env_var_prefix(env_var_value)

    _validate_project_id(project_id)

    client = storage.Client(project=project_id)
    kms_client = kms.KeyManagementServiceClient()

    bucket, object_name = _get_bucket_object(env_var_value)

    # Get the blob in the storage
    blob = client.bucket(bucket).get_blob(object_name)
    # Get the key reference in metadata
    key = blob.metadata[METADATA_KMS_KEY]
    # Get the blob ciphered content
    content = b2str(blob.download_as_string())

    content_splited = content.split(":", 2)
    enc_dek = base64.b64decode(content_splited[0])
    cipher_text = base64.b64decode(content_splited[1])

    # Decrypt the encoded Data Encryption Key (DEK)
    kms_resp = kms_client.decrypt(name=key, ciphertext=enc_dek, additional_authenticated_data=str2b(object_name))
    dek = kms_resp.plaintext

    return _decipher_blob(dek, cipher_text)


def Encrypt(project_id: str, env_var_value: str, plaintext: str):
    """
    Get the plain text string [plaintext], encrypt it and store it into the bucket [env_var_value]

    :param project_id: Project ID for creating the storage client.
    :param env_var_value: Berglas reference with the pattern berglas://<bucket>/<object_name>
    :param plaintext: String to be encrypted and stored
    :exception: When the project_id is missing/empty
    :exception: When object_name and/or bucket is missing (pattern not respected)
    """

    _validate_env_var_prefix(env_var_value)

    _validate_project_id(project_id)


    bucket_name, object_name = _get_bucket_object(env_var_value)

    client = storage.Client(project=project_id)
    kms_client = kms.KeyManagementServiceClient()

    dek, ciphertext = _envelope_encrypt(str2b(plaintext))

    name = kms_client.crypto_key_path_path(project_id, CRYPTO_KEY_LOCATION, CRYPTO_KEY_RING, CRYPTO_KEY)

    kms_resp = kms_client.encrypt(name, dek, additional_authenticated_data=str2b(object_name))

    bucket = client.get_bucket(bucket_name)

    metadata = {
        METADATA_KMS_KEY: name,
        METADATA_ID_KEY: 1
    }

    b64_dek    = b2str(base64.b64encode(kms_resp.ciphertext))
    b64_cipher = b2str(base64.b64encode(ciphertext))

    encrypted_content = f'{b64_dek}:{b64_cipher}'

    blob = bucket.blob(bucket_name)
    blob.upload_from_string(str2b(encrypted_content))
    blob.chunk_size = BLOB_CHUNK_SIZE
    blob.content_type = 'text/plain; charset=utf-8'
    blob.cache_control = 'private, no-cache, no-store, no-transform, max-age=0'
    blob.metadata = metadata
    blob.update()

