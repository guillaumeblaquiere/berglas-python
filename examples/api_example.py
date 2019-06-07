import os

import berglas_python as berglas

project_id = os.environ.get("MY-PROJECT")

# This higher-level API parses the secret reference at the specified
# environment variable, downloads and decrypts the secret, and replaces the
# contents of the given environment variable with the secret result.

berglas.Replace(project_id, "MY-SECRET")

# This lower-level API parses the secret reference, downloads and decrypts
# the secret, and returns the result. This is useful if you need to mutate
# the result.
my_secret = os.environ.get("MY-SECRET")
plaintext = berglas.Resolve(project_id, my_secret)
os.environ.unsetenv("MY-SECRET")
os.environ.setdefault("MY-SECRET", plaintext)
