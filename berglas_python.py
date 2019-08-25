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
    Split the env_var_value into bucket and object

    :param env_var_value: should respect this pattern berglas://<bucket>/<object>
    :return: the bucket and the object
    :exception: When object and/or bucket is missing (pattern not respected)
    """

    without_prefix = env_var_value[len(BERGLAS_PREFIX):]
    if without_prefix == "":
        logging.error(f"No bucket and object defined in {env_var_value}")
        raise Exception(f"No bucket and object defined in {env_var_value}")

    splitted = without_prefix.split("/", 2)

    if splitted[1] == "":
        logging.error(f"No object defined in {env_var_value}")
        raise Exception(f"No object defined in {env_var_value}")

    return splitted[0], splitted[1]


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
    return decrypter.update(toDecrypt[:-16]).decode('UTF-8')


def _cipher_blob(plaintext: bytes) -> (bytes, bytes):

    # Generate a random 256-bit IV.
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
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (key, iv + ciphertext + encryptor.tag)


def Resolve(project_id: str, env_var_value: str) -> str:
    """
    Get the object in the bucket (define in the env_var_value) and decipher it

    :param project_id: Project ID for creating the storage client.
    :param env_var_value: Berglas reference with the pattern berglas://<bucket>/<object>
    :return: the plaintext value of the deciphered reference.
    :exception: When the project_id is missing/empty
    :exception: When the env_var_value doesn't respect the pattern
    :exception: When the env_var_value defines a not existing bucket and/or object
    """

    if not env_var_value.startswith(BERGLAS_PREFIX):
        env_var_value = f'{BERGLAS_PREFIX}{env_var_value}'

    if project_id == "":
        logging.error("Project id can't be empty")
        raise Exception("Project id can't be empty")

    client = storage.Client(project=project_id)
    kms_client = kms.KeyManagementServiceClient()

    bucket, object = _get_bucket_object(env_var_value)

    # Get the blob in the storage
    blob = client.bucket(bucket).get_blob(object)
    # Get the key reference in metadata
    key = blob.metadata[METADATA_KMS_KEY]
    # Get the blob ciphered content
    content = blob.download_as_string().decode('UTF-8')

    content_splited = content.split(":", 2)
    enc_dek = base64.b64decode(content_splited[0])
    cipher_text = base64.b64decode(content_splited[1])

    # Decrypt the encoded Data Encryption Key (DEK)
    kms_resp = kms_client.decrypt(name=key, ciphertext=enc_dek, additional_authenticated_data=bytes(object, 'UTF-8'))
    dek = kms_resp.plaintext

    return _decipher_blob(dek, cipher_text)


def Encrypt(project_id: str, env_var_value: str, plaintext: str):
    """
    Get the plain text string [plaintext], encrypt it and store it into the bucket [env_var_value]

    :param project_id: Project ID for creating the storage client.
    :param env_var_value: Berglas reference with the pattern berglas://<bucket>/<object>
    :param plaintext: String to be encrypted and stored
    :exception: When the project_id is missing/empty
    """

    if not env_var_value.startswith(BERGLAS_PREFIX):
        env_var_value = f'{BERGLAS_PREFIX}{env_var_value}'

    if project_id == "":
        logging.error("Project id can't be empty")
        raise Exception("Project id can't be empty")

    bucket_name, object = _get_bucket_object(env_var_value)

    client = storage.Client(project=project_id)
    kms_client = kms.KeyManagementServiceClient()

    dek, ciphertext = _cipher_blob(plaintext.encode('utf-8'))

    name = kms_client.crypto_key_path_path(project_id, CRYPTO_KEY_LOCATION, CRYPTO_KEY_RING, CRYPTO_KEY)

    kms_resp = kms_client.encrypt(name, dek, additional_authenticated_data=bytes(object, 'UTF-8'))

    bucket = client.get_bucket(bucket_name)

    metadata = {
        METADATA_KMS_KEY: name,
        METADATA_ID_KEY: 1
    }

    b64_dek    = base64.b64encode(kms_resp.ciphertext).decode()
    b64_cipher = base64.b64encode(ciphertext).decode()

    encrypted_content = f'{b64_dek}:{b64_cipher}'

    blob = bucket.blob(object)
    blob.upload_from_string(encrypted_content.encode('utf-8'))
    blob.chunk_size = BLOB_CHUNK_SIZE
    blob.content_type = 'text/plain; charset=utf-8'
    blob.cache_control = 'private, no-cache, no-store, no-transform, max-age=0'
    blob.metadata = metadata
    blob.update()

