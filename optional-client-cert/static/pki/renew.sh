#!/bin/bash

set -e

cd $(dirname ${BASH_SOURCE[0]})

workdir=$PWD

config=$workdir/x509.cnf

md=sha256
ec_algo=ec
# curve names can be queried with command 'openssl ecparam -list_curves'
# secp256k1 isn't supported by rustls
#curve=secp256k1
curve=P-256

echo "generate CA key and cert ..."

for app in server client; do
  echo "generating key and self-signed cert for $app"

  # -nodes: omits the password or passphrase so you can examine the certificate.
  #   It's a really bad idea to omit the password or passphrase.
  openssl req                         \
    -batch                            \
    -config $config                   \
    -days 366                         \
    -keyout $app.key                  \
    -newkey $ec_algo                  \
    -nodes                            \
    -out $app.crt                     \
    -pkeyopt ec_paramgen_curve:$curve \
    -$md                              \
    -x509

  #echo ""
  #echo "-------------------"
  #echo "certificate goes as"
  #openssl x509 -noout -text -in $app.crt

  #echo ""
  #echo "-------------------"
  #echo "private key goes as"
  #openssl ec -in $app.key -noout -text

done
