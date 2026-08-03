#!/usr/bin/env bash
# Generate ephemeral mutual-auth test PKI for private Wi-Fi Host tests.
# Exact profile: ECDSA P-256 keys/certs (ADR-0018 TLS1.3 P-256).
# Embeds ADR-0018 §14.2 leaf OID SAN GeneralNames (112B) with runtime/authority.
# Secrets stay under a caller-provided temp directory; never logged.
set -euo pipefail
OUT_DIR="${1:?usage: wifi_v1_gen_test_certs.sh OUT_DIR}"
mkdir -p "${OUT_DIR}"
if [[ -z "${OPENSSL_BIN:-}" && -n "${OPENSSL_ROOT:-}" && -x "${OPENSSL_ROOT}/bin/openssl" ]]; then
  OPENSSL_BIN="${OPENSSL_ROOT}/bin/openssl"
else
  OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
fi

# Build exact 112-byte GeneralNames DER + OpenSSL conf for a role.
# binding fields match e2e fill_peer_inputs / exporter KAT layout.
make_san_conf() {
  local role="$1" # client|server
  local conf="$2"
  local key="$3"
  local variant="${4:-valid}"
  python3 - "$role" "$conf" "$key" "${OPENSSL_BIN}" "$variant" <<'PY'
import hashlib
import subprocess
import sys
role = sys.argv[1]
conf_path = sys.argv[2]
key_path = sys.argv[3]
openssl_bin = sys.argv[4]
variant = sys.argv[5]
# OID content (20B) for 2.25.259582855280982876264288537151153425322
oid = bytes([
    0x69, 0x83, 0x86, 0xc9, 0xeb, 0xb8, 0xe4, 0xe2, 0x9a, 0xe6,
    0xed, 0x96, 0xe5, 0xfe, 0xd9, 0xa1, 0xfd, 0x83, 0x97, 0x2a,
])
role_b = 0x01 if role == "client" else 0x02
# runtime_id: client 0x31..0x40, server 0x32..0x41 (e2e fill_peer_inputs)
if role == "client":
    runtime = bytes([(0x31 + i) & 0xFF for i in range(16)])
else:
    runtime = bytes([(0x32 + i) & 0xFF for i in range(16)])
# authorized_attachment_binding_digest: non-zero fixed
bind_dig = bytes([0xb1] * 32)
# authority_id: 0xd0.. with last 0xdf
auth = bytes([0xd0] * 15 + [0xdf])
term = 7
cred_gen = 1
rev_gen = 1

def be_u64(v):
    return v.to_bytes(8, "big")

def be_u32(v):
    return v.to_bytes(4, "big")

binding = bytearray(82)
binding[0] = 0x01  # version
binding[1] = role_b
binding[2:18] = runtime
binding[18:50] = bind_dig
binding[50:66] = auth
binding[66:74] = be_u64(term)
binding[74:78] = be_u32(cred_gen)
binding[78:82] = be_u32(rev_gen)

# GeneralNames 112B: 30 6e a0 6c 06 14 <oid20> a0 54 04 52 <82>
gn = bytearray()
gn += bytes([0x30, 0x6e, 0xa0, 0x6c, 0x06, 0x14])
gn += oid
gn += bytes([0xa0, 0x54, 0x04, 0x52])
gn += binding
assert len(gn) == 112, len(gn)
hex_gn = gn.hex()
spki = subprocess.check_output(
    [openssl_bin, "pkey", "-in", key_path, "-pubout", "-outform", "DER"],
    stderr=subprocess.DEVNULL,
)
assert len(spki) == 91
assert spki[:27] == bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
)
ski = hashlib.sha256(spki).digest()[:20]
ski_text = ":".join(f"{b:02X}" for b in ski)
eku = "clientAuth" if role == "client" else "serverAuth"
ku = "digitalSignature"
san_critical = "critical,"
aki_value = "keyid:always"
if variant == "bad-ku":
    ku = "digitalSignature,keyAgreement"
elif variant == "bad-eku":
    eku = "clientAuth,serverAuth"
elif variant == "bad-san":
    san_critical = ""
elif variant == "bad-ski":
    # OpenSSL's hash form is SHA-1 over the subjectPublicKey bits, not the
    # required first_20(SHA-256(SubjectPublicKeyInfo DER)).
    ski_text = "hash"
elif variant == "bad-aki":
    aki_value = "keyid:always,issuer:always"
elif variant != "valid":
    raise ValueError(f"unknown fixture variant: {variant}")

# Exact six-extension leaf profile from ADR-0018 §14.2.
with open(conf_path, "w", encoding="utf-8") as f:
    f.write("[req]\n")
    f.write("distinguished_name=dn\n")
    f.write("x509_extensions=v3\n")
    f.write("[dn]\n")
    f.write("[v3]\n")
    f.write("basicConstraints=critical,CA:FALSE\n")
    f.write(f"keyUsage=critical,{ku}\n")
    f.write(f"extendedKeyUsage=critical,{eku}\n")
    f.write(f"subjectAltName={san_critical}DER:{hex_gn}\n")
    f.write(f"subjectKeyIdentifier={ski_text}\n")
    f.write(f"authorityKeyIdentifier={aki_value}\n")
PY
}

# CA: ECDSA P-256 with the exact self-signed root extension profile.
"${OPENSSL_BIN}" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "${OUT_DIR}/ca.key.pem" >/dev/null 2>&1
python3 - "${OUT_DIR}/ca.key.pem" "${OUT_DIR}/ca.ext.cnf" "${OPENSSL_BIN}" <<'PY'
import hashlib
import subprocess
import sys
key_path, conf_path, openssl_bin = sys.argv[1:]
spki = subprocess.check_output(
    [openssl_bin, "pkey", "-in", key_path, "-pubout", "-outform", "DER"],
    stderr=subprocess.DEVNULL,
)
assert len(spki) == 91
ski = hashlib.sha256(spki).digest()[:20]
ski_text = ":".join(f"{b:02X}" for b in ski)
with open(conf_path, "w", encoding="utf-8") as f:
    f.write("[req]\n")
    f.write("distinguished_name=dn\n")
    f.write("x509_extensions=v3_ca\n")
    f.write("[dn]\n")
    f.write("[v3_ca]\n")
    f.write("basicConstraints=critical,CA:TRUE,pathlen:1\n")
    f.write("keyUsage=critical,keyCertSign,cRLSign\n")
    f.write(f"subjectKeyIdentifier={ski_text}\n")
    f.write("authorityKeyIdentifier=keyid:always\n")
PY
"${OPENSSL_BIN}" req -new -x509 -key "${OUT_DIR}/ca.key.pem" \
  -out "${OUT_DIR}/ca.cert.pem" -days 1 -subj "/CN=ninlil-wifi-test-ca" \
  -sha256 -config "${OUT_DIR}/ca.ext.cnf" -extensions v3_ca >/dev/null 2>&1

for role in server client; do
  "${OPENSSL_BIN}" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "${OUT_DIR}/${role}.key.pem" >/dev/null 2>&1
  "${OPENSSL_BIN}" req -new -key "${OUT_DIR}/${role}.key.pem" \
    -out "${OUT_DIR}/${role}.csr.pem" \
    -subj "/CN=ninlil-wifi-test-${role}" -sha256 \
    -config /dev/null >/dev/null 2>&1
  make_san_conf \
    "${role}" "${OUT_DIR}/${role}.ext.cnf" "${OUT_DIR}/${role}.key.pem"
  "${OPENSSL_BIN}" x509 -req -in "${OUT_DIR}/${role}.csr.pem" \
    -CA "${OUT_DIR}/ca.cert.pem" -CAkey "${OUT_DIR}/ca.key.pem" -CAcreateserial \
    -out "${OUT_DIR}/${role}.cert.pem" -days 1 -sha256 \
    -extfile "${OUT_DIR}/${role}.ext.cnf" -extensions v3 >/dev/null 2>&1
  rm -f "${OUT_DIR}/${role}.csr.pem" "${OUT_DIR}/${role}.ext.cnf"
  # Fail closed if not EC P-256 (text form varies by OpenSSL version).
  txt="$("${OPENSSL_BIN}" x509 -in "${OUT_DIR}/${role}.cert.pem" -noout -text)"
  echo "${txt}" | grep -Eqi "id-ecPublicKey|Public Key Algorithm:.*id-ecPublicKey"
  echo "${txt}" | grep -Eqi "prime256v1|secp256r1|NIST CURVE: P-256"
  # SAN / otherName present (OID nest must exist for leaf binding).
  echo "${txt}" | grep -Eqi "X509v3 Subject Alternative Name|Subject Alternative Name"
done

# Negative leaf fixtures. Each mutates exactly one profile rule while keeping
# the same CA, role binding, key, and all other extensions valid.
"${OPENSSL_BIN}" req -new -key "${OUT_DIR}/client.key.pem" \
  -out "${OUT_DIR}/invalid-client.csr.pem" \
  -subj "/CN=ninlil-wifi-test-client" -sha256 \
  -config /dev/null >/dev/null 2>&1
for variant in bad-ku bad-eku bad-san bad-ski bad-aki; do
  make_san_conf \
    client \
    "${OUT_DIR}/${variant}.ext.cnf" \
    "${OUT_DIR}/client.key.pem" \
    "${variant}"
  "${OPENSSL_BIN}" x509 -req -in "${OUT_DIR}/invalid-client.csr.pem" \
    -CA "${OUT_DIR}/ca.cert.pem" -CAkey "${OUT_DIR}/ca.key.pem" -CAcreateserial \
    -out "${OUT_DIR}/client.${variant}.cert.pem" -days 1 -sha256 \
    -extfile "${OUT_DIR}/${variant}.ext.cnf" -extensions v3 >/dev/null 2>&1
  rm -f "${OUT_DIR}/${variant}.ext.cnf"
done
rm -f "${OUT_DIR}/invalid-client.csr.pem"
rm -f "${OUT_DIR}/ca.ext.cnf"

# Definitely-expired client certificate (year 2000 window), still ECDSA P-256.
# No leaf OID required — rejected at local notAfter before handshake identity.
"${OPENSSL_BIN}" req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${OUT_DIR}/expired.key.pem" -out "${OUT_DIR}/expired.csr.pem" \
  -subj "/CN=ninlil-wifi-test-expired" -sha256 \
  -config /dev/null >/dev/null 2>&1
python3 - "${OUT_DIR}" <<'PY'
from pathlib import Path
import sys

out_dir = Path(sys.argv[1])
(out_dir / "expired-ca-index.txt").write_text("", encoding="ascii")
(out_dir / "expired-ca-serial").write_text("10000001\n", encoding="ascii")
(out_dir / "expired-ca.cnf").write_text(
    """[ca]
default_ca=ninlil_test_ca
[ninlil_test_ca]
database=$ENV::NINLIL_EXPIRED_CA_DIR/expired-ca-index.txt
new_certs_dir=$ENV::NINLIL_EXPIRED_CA_DIR
certificate=$ENV::NINLIL_EXPIRED_CA_DIR/ca.cert.pem
private_key=$ENV::NINLIL_EXPIRED_CA_DIR/ca.key.pem
serial=$ENV::NINLIL_EXPIRED_CA_DIR/expired-ca-serial
default_md=sha256
default_days=1
policy=policy_any
unique_subject=no
[policy_any]
commonName=supplied
""",
    encoding="ascii",
)
PY
# `openssl x509` only gained notBefore/notAfter setters after OpenSSL 3.0.
# `openssl ca` supports explicit validity dates across the supported host range.
NINLIL_EXPIRED_CA_DIR="${OUT_DIR}" "${OPENSSL_BIN}" ca -batch \
  -config "${OUT_DIR}/expired-ca.cnf" \
  -in "${OUT_DIR}/expired.csr.pem" \
  -out "${OUT_DIR}/expired.cert.pem" -notext \
  -startdate 20000101000000Z -enddate 20000102000000Z >/dev/null 2>&1
rm -f "${OUT_DIR}/expired.csr.pem" "${OUT_DIR}/"*.srl 2>/dev/null || true
rm -f "${OUT_DIR}/10000001.pem" "${OUT_DIR}/expired-ca-"* 2>/dev/null || true
# Do not print key material.
echo "wifi_v1_gen_test_certs: ok ecdsa-p256 dir=${OUT_DIR}"
