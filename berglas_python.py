import base64
import logging
import os

from cryptography.hazmat.backends import default_backend
from google.cloud import storage, kms_v1
from google.api_core import iam

from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

BERGLAS_PREFIX           = "berglas://"
METADATA_KMS_KEY         = "berglas-kms-key"
METADATA_ID_KEY          = "berglas-secret"
METADATA_CONTENT_TYPE    = "text/plain; charset=utf-8"
METADATA_CACHE_CONTROL   = "private, no-cache, no-store, no-transform, max-age=0"
BLOB_CHUNK_SIZE          = 256 * 1024
GCM_NONCE_SIZE           = 12
GCM_TAG_SIZE             = 16
DATA_ENCRYPTION_KEY_SIZE = 32

LOCATION                 = "global"
KEY_RING                 = "berglas"
CRYPTO_KEY               = "berglas-key"


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


def copy_blob_iam_policy(blob):
    """
    Copy any IAM permissions from the old object over to the new object.

    :param blob: the blob object
    :return: na google.api_core.iam.Policy containing a copy of the current IAM policies
    """

    new_policy = iam.Policy()
    blob_iam_policies = blob.get_iam_policy()

    for role_name, entity in blob_iam_policies.items():
        new_policy[role_name] = list(entity)

    return new_policy


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

    os.environ[env_var_key] = plaintext


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

    splitted = without_prefix.split("/", 1)

    if splitted[1] == "":
        log_msg = f"No object defined in {env_var_value}"
        logging.error(log_msg)
        raise Exception(log_msg)

    return splitted[0], splitted[1]


def _envelope_decrypt(data_encryption_key: str, data: str) -> str:
    """
    Decipher the cipher text with the dek. Use aes GCM algorithm

    :param data_encryption_key: Data Encryption Key
    :param data: Content to decrypt with aes GCM cipher
    :return: deciphered plain text
    :exception: When deciphering failed, bad dek size or format, bad ciphering text format
    """

    nonce      = data[:GCM_NONCE_SIZE]
    ciphertext = data[GCM_NONCE_SIZE:-GCM_TAG_SIZE]
    tag        = data[-GCM_TAG_SIZE:]

    algo = algorithms.AES(data_encryption_key)

    cipher = Cipher(
        algo,
        modes.GCM(nonce, tag),
        backend=default_backend()
    )

    decrypter = cipher.decryptor()
    return b2str(decrypter.update(ciphertext))


def _envelope_encrypt(plaintext: bytes) -> (bytes, bytes):
    """
    Generates a unique Data Encryption Key and encrypts the plaintext with the given key.

    :param plaintext: String to be encrypted
    :return: The encryption key and resulting ciphertext
    """

    # Generate a random 256-bit key.
    data_encryption_key = os.urandom(DATA_ENCRYPTION_KEY_SIZE)

    # Generate a random 96-bit IV.
    initialization_vector = os.urandom(GCM_NONCE_SIZE)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    cipher = Cipher(
        algorithms.AES(data_encryption_key),
        modes.GCM(initialization_vector),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Encrypt the ciphertext with the DEK
    # Masking the ciphertext by adding the initialization vector (12 chars) + ciphered text +
    # and the encryptor_tag as additional data (16 chars).
    # The encryptor_tag will be discarded by Berglas as it auto places this field with a nil value.
    # But it is required for adding 16 chars at the end of the ciphered text
    data = initialization_vector + ciphertext + encryptor.tag

    return (data_encryption_key, data)


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

    gcs_client = storage.Client(project=project_id)
    kms_client = kms_v1.KeyManagementServiceClient()

    bucket, object_name = _get_bucket_object(env_var_value)

    # Get the blob in the storage
    blob = gcs_client.bucket(bucket).get_blob(object_name)
    # Get the key reference in metadata
    crypto_key_path = blob.metadata[METADATA_KMS_KEY]
    # Get the blob ciphered content
    blob_content = b2str(blob.download_as_string())

    blob_content_splited = blob_content.split(":", 2)
    decoded_data_encryption_key  = base64.b64decode(blob_content_splited[0])
    decoded_data                 = base64.b64decode(blob_content_splited[1])

    # Decrypt the encoded Data Encryption Key (DEK)
    # Initialize request argument(s)
    request = kms_v1.DecryptRequest(
        name=crypto_key_path,
        ciphertext=decoded_data_encryption_key,
        additional_authenticated_data=str2b(object_name)
    )

    kms_resp = kms_client.decrypt(request=request)
    data_encryption_key = kms_resp.plaintext

    return _envelope_decrypt(data_encryption_key, decoded_data)


def Encrypt(project_id: str, env_var_value: str, plaintext: str,
            location: str = LOCATION, key_ring: str = KEY_RING, crypto_key: str = CRYPTO_KEY):
    """
    Get the plain text string [plaintext], encrypt it and store it into the bucket [env_var_value]

    :param project_id: Project ID for creating the storage client.
    :param env_var_value: Berglas reference with the pattern berglas://<bucket>/<object_name>
    :param plaintext: String to be encrypted and stored
    :param location: Keyring location. Default: global
    :param key_ring: KMS keyring name to be used to encrypt your secrets
    :param crypto_key: Cryptographic key name to be used to encrypt your secrets
    :exception: When the project_id is missing/empty
    :exception: When object_name and/or bucket is missing (pattern not respected)
    """

    # It's a flag to ensure the IAM policy for the blob object will be updated only
    # if the file exists.
    blob_iam_policy = None

    _validate_env_var_prefix(env_var_value)

    _validate_project_id(project_id)


    bucket_name, object_name = _get_bucket_object(env_var_value)

    gcs_client = storage.Client(project=project_id)
    kms_client = kms_v1.KeyManagementServiceClient()

    data_encryption_key, ciphertext = _envelope_encrypt(str2b(plaintext))

    crypto_key_path = kms_client.crypto_key_path_path(project_id, location, key_ring, crypto_key)

    kms_resp = kms_client.encrypt(crypto_key_path, data_encryption_key,
                                  additional_authenticated_data=str2b(object_name))

    bucket = gcs_client.get_bucket(bucket_name)

    metadata = {
        METADATA_KMS_KEY: crypto_key_path,
        METADATA_ID_KEY: 1
    }

    encoded_data_encryption_key = b2str(base64.b64encode(kms_resp.ciphertext))
    encoded_ciphertext          = b2str(base64.b64encode(ciphertext))

    blob_content = f'{encoded_data_encryption_key}:{encoded_ciphertext}'

    blob = bucket.blob(object_name)

    # If the object doesn't exist we don't need to copy the IAM policy
    if blob.exists():
        blob_iam_policy = copy_blob_iam_policy(blob)

    blob.upload_from_string(str2b(blob_content))

    # If the object doesn't exist we don't need to copy the IAM policy
    if blob_iam_policy is not None:
        blob.set_iam_policy(blob_iam_policy)

    blob.chunk_size = BLOB_CHUNK_SIZE
    blob.content_type = METADATA_CONTENT_TYPE
    blob.cache_control = METADATA_CACHE_CONTROL
    blob.metadata = metadata
    blob.update()

