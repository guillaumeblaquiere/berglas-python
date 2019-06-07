# Overview

Python library help to use [Berglas](https://github.com/GoogleCloudPlatform/berglas) and to decrypt the secrets stored in a GCP storage.

See [Berglas](https://github.com/GoogleCloudPlatform/berglas) for details about bucket bootstrapping and secret creation

# Library Usage

You have to get the library
```
pip install berglas-python
```

Then use it in the same way as [Go library](https://github.com/GoogleCloudPlatform/berglas/blob/master/README.md#library-usage)

The library berglas_python library is able to:

- Download and decrypt any secrets that match the [Berglas environment variable reference syntax](https://github.com/GoogleCloudPlatform/berglas/blob/master/doc/reference-syntax.md)
- Replace the value for the environment variable with the decrypted secret

Here an example of usage
```
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
```

# License

This library is licensed under Apache 2.0. Full license text is available in
[LICENSE](https://github.com/guillaumeblaquiere/berglas-python/tree/master/LICENSE).

