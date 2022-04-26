#!/bin/sh

set -eu

usage () {
  cat <<EOF
Usage: $0 PATH_TO_PSA_CRYPTO_API_TREE
Update the rendered copy of the PSA Cryptography API specification.

1. Check out the desired version of the PSA Crypto API specification.
    git clone https://github.com/ARMmbed/psa-crypto-api
    git checkout <TAG>
2. Build the specification and extensions.
    cd psa-crypto-api
    sudo docker build -t psa_api - <psa-crypto-api/scripts/Dockerfile
    sudo docker run -i -t -u \$(id -u):\$(id -g) -v \$PWD:/var/lib/builds psa_api -c make
    for d in ext-*; do
      sudo docker run -i -t -u \$(id -u):\$(id -g) -v \$PWD:/var/lib/builds psa_api -c "make -C $d";
    done
    cd ..
3. Copy the rendered files.
    $0 psa-crypto-api
4. If this is a new numbered version:
    edit docs/psa/index.md # Add the new version
    make
    ln -snf <VERSION> docs/latest
5. Commit the changes.
    git add docs/html docs/PSA_Cryptography_API_Specification.pdf
    git add docs
    git commit
EOF
}

if [ $# -ne 1 ] || [ "$1" = "--help" ]; then
  usage
  exit $(($# != 1))
fi

# get_version DIRECTORY [EXTENSION_NAME]
# --> $version
get_version () {
    version=$(sed -n 's/^\(Version[^0-9A-Za-z][^0-9A-Za-z]*\)//; T; y/ /_/; p; q' "$1/sphinx-build/html/index.html")
    if [ -z "$version" ]; then
        suffix=
        if [ -n "$2" ]; then
            suffix=" in $2"
        fi
        echo >&2 "Fatal error: unable to determine the version$suffix."
        exit 1
    fi
    if [ ! -d "docs/$version" ]; then
        mkdir "docs/$version"
        cat <<EOF
NOTE: Please update "Past versions" in docs/psa/index.md to add $version
      then run make.
EOF
        if [ -z "$2" ]; then
            cat <<EOF
NOTE: You may need to update the "latest" symbolic link.
    ln -snf "$version" docs/latest
EOF
        fi
    fi
}

get_version "$1" ""
rsync -a --delete "$1/sphinx-build/html" "docs/$version/"
rsync -a "$1/sphinx-build/latex/psa_crypto_api.pdf" "docs/$version/PSA_Cryptography_API_Specification.pdf"

for d in "$1"/ext-*; do
    get_version "$d" "${d##*/}"
    rsync -a --delete --include='psa_*.pdf' --exclude='*' "$d/sphinx-build/latex/" "docs/$version/"
    rsync -a --delete "$d/sphinx-build/html" "docs/$version/"
done
