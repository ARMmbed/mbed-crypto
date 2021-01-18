#!/bin/sh

set -eu

usage () {
  cat <<EOF
Usage: $0 PATH_TO_PSA_CRYPTO_API_TREE
Update the rendered copy of the PSA Cryptography API specification.

1. Check out the desired version of the PSA Crypto API specification.
    git clone https://github.com/ARMmbed/psa-crypto-api
    git checkout <TAG>
2. Build the specification.
    cd psa-crypto-api
    sudo docker build -t psa_api - <psa-crypto-api/scripts/Dockerfile
    sudo docker run -i -t -u \$(id -u):\$(id -g) -v \$PWD:/var/lib/builds psa_api make
    cd ..
3. Copy the rendered files.
    $0 psa-crypto-api
4. Commit the changes.
    git commit docs/html docs/PSA_Cryptography_API_Specification.pdf
EOF
}

if [ $# -ne 1 ] || [ "$1" = "--help" ]; then
  usage
  exit $(($# != 1))
fi

rsync -a --delete "$1/sphinx-build/html" docs/
rsync -a "$1/sphinx-build/latex/psa_crypto_api.pdf" docs/PSA_Cryptography_API_Specification.pdf
