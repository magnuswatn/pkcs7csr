"""Tests for the pkcs7csr package"""
import datetime
import os
import subprocess
import unittest

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2314

import pkcs7csr


def _generate_self_signed_cert(key_type):
    """Generates a self signed certificate"""
    if key_type == "rsa":
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
    elif key_type == "ecdsa":
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    else:
        raise Exception("what")

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, "State or Province Name"
            ),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Locality name"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization Name"),
            x509.NameAttribute(NameOID.COMMON_NAME, "commonName"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("testulf")]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    return cert, key


def _verify_pkcs7_signature(pkcs7):
    """Verifies a PKCS7 file with OpenSSL"""

    # OpenSSL does not like the original PEM header
    pkcs7 = pkcs7.replace("NEW CERTIFICATE REQUEST", "PKCS7")

    with open("./TEMP_csr", "w") as open_file:
        open_file.write(pkcs7)

    verify_result = subprocess.call(
        [
            "openssl",
            "cms",
            "-verify",
            "-in",
            "./TEMP_csr",
            "-inform",
            "PEM",
            "-noverify",
            "-out",
            "./TEMP_innercsr",
        ]
    )

    with open("./TEMP_innercsr", "rb") as open_file:
        inner_csr = open_file.read()

    os.remove("./TEMP_csr")
    os.remove("./TEMP_innercsr")

    return verify_result, inner_csr


class Pkcs7csrTestCase(unittest.TestCase):
    """Tests for pkcs7csr"""

    def test_rsa_cert(self):
        """Generates a PKCS#7 renewal request from an rsa certificate"""
        cert, key = _generate_self_signed_cert("rsa")
        csr = pkcs7csr.create_pkcs7csr(cert, key)

        verify_result, raw_inner_csr = _verify_pkcs7_signature(csr)

        inner_csr = x509.load_der_x509_csr(raw_inner_csr, default_backend())

        decoded_inner_csr = decoder.decode(
            raw_inner_csr, asn1Spec=rfc2314.CertificationRequest()
        )
        encoded_inner_csr = encoder.encode(
            decoded_inner_csr[0]["certificationRequestInfo"]["attributes"][0]["vals"][0]
        )

        self.assertEqual(verify_result, 0)
        self.assertEqual(inner_csr.is_signature_valid, True)
        self.assertEqual(
            key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            inner_csr.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
        )
        self.assertEqual(cert.public_bytes(Encoding.DER), encoded_inner_csr)

    def test_ecdsa_cert(self):
        """Generates a PKCS#7 renewal request from an ecdsa certificate"""
        cert, key = _generate_self_signed_cert("ecdsa")
        csr = pkcs7csr.create_pkcs7csr(cert, key)

        verify_result, raw_inner_csr = _verify_pkcs7_signature(csr)

        inner_csr = x509.load_der_x509_csr(raw_inner_csr, default_backend())

        decoded_inner_csr = decoder.decode(
            raw_inner_csr, asn1Spec=rfc2314.CertificationRequest()
        )
        encoded_inner_csr = encoder.encode(
            decoded_inner_csr[0]["certificationRequestInfo"]["attributes"][0]["vals"][0]
        )

        self.assertEqual(verify_result, 0)
        self.assertEqual(inner_csr.is_signature_valid, True)
        self.assertEqual(
            key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            inner_csr.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
        )
        self.assertEqual(cert.public_bytes(Encoding.DER), encoded_inner_csr)

    def test_rsa_cert_new_key(self):
        """Generates a PKCS#7 renewal request from an rsa certificate with a new key"""
        cert, key = _generate_self_signed_cert("rsa")
        new_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        csr = pkcs7csr.create_pkcs7csr(cert, key, new_key)

        verify_result, raw_inner_csr = _verify_pkcs7_signature(csr)

        inner_csr = x509.load_der_x509_csr(raw_inner_csr, default_backend())

        decoded_inner_csr = decoder.decode(
            raw_inner_csr, asn1Spec=rfc2314.CertificationRequest()
        )
        encoded_inner_csr = encoder.encode(
            decoded_inner_csr[0]["certificationRequestInfo"]["attributes"][0]["vals"][0]
        )

        self.assertEqual(verify_result, 0)
        self.assertEqual(inner_csr.is_signature_valid, True)
        self.assertEqual(
            new_key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            inner_csr.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
        )
        self.assertEqual(cert.public_bytes(Encoding.DER), encoded_inner_csr)

    def test_ecdsa_cert_new_key(self):
        """Generates a PKCS#7 renewal request from an ecdsa certificate with a new key"""
        cert, key = _generate_self_signed_cert("ecdsa")
        new_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        csr = pkcs7csr.create_pkcs7csr(cert, key, new_key)

        verify_result, raw_inner_csr = _verify_pkcs7_signature(csr)

        inner_csr = x509.load_der_x509_csr(raw_inner_csr, default_backend())

        decoded_inner_csr = decoder.decode(
            raw_inner_csr, asn1Spec=rfc2314.CertificationRequest()
        )
        encoded_inner_csr = encoder.encode(
            decoded_inner_csr[0]["certificationRequestInfo"]["attributes"][0]["vals"][0]
        )

        self.assertEqual(verify_result, 0)
        self.assertEqual(inner_csr.is_signature_valid, True)
        self.assertEqual(
            new_key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            inner_csr.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
        )
        self.assertEqual(cert.public_bytes(Encoding.DER), encoded_inner_csr)

    def test_rsa_cert_new_ecdsa_key(self):
        """Generates a PKCS#7 renewal request from an rsa certificate with a new ecdsa key"""
        cert, key = _generate_self_signed_cert("rsa")
        new_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        csr = pkcs7csr.create_pkcs7csr(cert, key, new_key)

        verify_result, raw_inner_csr = _verify_pkcs7_signature(csr)

        inner_csr = x509.load_der_x509_csr(raw_inner_csr, default_backend())

        decoded_inner_csr = decoder.decode(
            raw_inner_csr, asn1Spec=rfc2314.CertificationRequest()
        )
        encoded_inner_csr = encoder.encode(
            decoded_inner_csr[0]["certificationRequestInfo"]["attributes"][0]["vals"][0]
        )

        self.assertEqual(verify_result, 0)
        self.assertEqual(inner_csr.is_signature_valid, True)
        self.assertEqual(
            new_key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            inner_csr.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
        )
        self.assertEqual(cert.public_bytes(Encoding.DER), encoded_inner_csr)

    def test_ecdsa_cert_new_rsa_key(self):
        """Generates a PKCS#7 renewal request from an ecdsa certificate with a new rsa key"""
        cert, key = _generate_self_signed_cert("ecdsa")
        new_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        csr = pkcs7csr.create_pkcs7csr(cert, key, new_key)

        verify_result, raw_inner_csr = _verify_pkcs7_signature(csr)

        inner_csr = x509.load_der_x509_csr(raw_inner_csr, default_backend())

        decoded_inner_csr = decoder.decode(
            raw_inner_csr, asn1Spec=rfc2314.CertificationRequest()
        )
        encoded_inner_csr = encoder.encode(
            decoded_inner_csr[0]["certificationRequestInfo"]["attributes"][0]["vals"][0]
        )

        self.assertEqual(verify_result, 0)
        self.assertEqual(inner_csr.is_signature_valid, True)
        self.assertEqual(
            new_key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            inner_csr.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
        )
        self.assertEqual(cert.public_bytes(Encoding.DER), encoded_inner_csr)

    def test_unsupported_key_type(self):
        with pytest.raises(pkcs7csr.UnsupportedKeyTypeError):
            pkcs7csr._sign("not a key", b"payload")
