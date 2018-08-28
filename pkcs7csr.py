"""
Creates a Microsoft style "PKCS #7 renewal request"

(This is actually a sort of mix between PKCS #7 and CMS, as it includes ECDSA support)

https://github.com/magnuswatn/pkcs7csr

Magnus Watn <magnus@watn.no>
"""

import base64
import binascii

from pyasn1_modules import rfc2314, rfc2315
from pyasn1.codec.der import encoder, decoder

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

__version__ = '1.0.2'

class UnsupportedKeyTypeError(Exception):
    """Signifies that the key was of an unsupported type"""
    pass

def _create_csr(cert, private_key):
    """Creates a CSR with the RENEWAL_CERTIFICATE extension"""

    subject_public_key_info = decoder.decode(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ), asn1Spec=rfc2314.SubjectPublicKeyInfo())[0]

    subject = cert[0]['tbsCertificate']['subject']

    # Microsoft OID: szOID_RENEWAL_CERTIFICATE
    renewal_certificate_type = rfc2314.AttributeType((1, 3, 6, 1, 4, 1, 311, 13, 1))
    renewal_certificate_value = rfc2314.univ.SetOf().setComponents(cert[0])

    renewal_certificate = rfc2314.Attribute()
    renewal_certificate.setComponentByName('type', renewal_certificate_type)
    renewal_certificate.setComponentByName('vals', renewal_certificate_value)

    attributes = rfc2314.Attributes().subtype(
        implicitTag=rfc2314.tag.Tag(rfc2314.tag.tagClassContext,
                                    rfc2314.tag.tagFormatConstructed, 0))
    attributes.setComponents(renewal_certificate)

    certification_request_info = rfc2314.CertificationRequestInfo()
    certification_request_info.setComponentByName('version', 0)
    certification_request_info.setComponentByName('subject', subject)
    certification_request_info.setComponentByName('subjectPublicKeyInfo', subject_public_key_info)
    certification_request_info.setComponentByName('attributes', attributes)

    raw_signature, signature_algorithm = _sign(private_key,
                                               encoder.encode(certification_request_info))

    signature = rfc2314.univ.BitString(hexValue=binascii.hexlify(raw_signature).decode('ascii'))

    certification_request = rfc2314.CertificationRequest()
    certification_request.setComponentByName('certificationRequestInfo', certification_request_info)
    certification_request.setComponentByName('signatureAlgorithm', signature_algorithm)
    certification_request.setComponentByName('signature', signature)

    return encoder.encode(certification_request)

def _sign(key, payload):
    """Signs the payload with the specified key"""

    signature_algorithm = rfc2314.AlgorithmIdentifier()

    if isinstance(key, rsa.RSAPrivateKey):
        # sha256WithRSAEncryption. MUST have ASN.1 NULL in the parameters field
        signature_algorithm.setComponentByName('algorithm', (1, 2, 840, 113549, 1, 1, 11))
        signature_algorithm.setComponentByName('parameters', '\x05\x00')
        signature = key.sign(
            payload,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        # ecdsaWithSHA256. MUST omit the parameters field
        signature_algorithm.setComponentByName('algorithm', (1, 2, 840, 10045, 4, 3, 2))
        signature = key.sign(
            payload,
            ec.ECDSA(hashes.SHA256())
        )
    else:
        raise UnsupportedKeyTypeError

    return signature, signature_algorithm

def _create_pkcs7(cert, csr, private_key):
    """Creates the PKCS7 structure and signs it"""

    content_info = rfc2315.ContentInfo()
    content_info.setComponentByName('contentType', rfc2315.data)
    content_info.setComponentByName('content', encoder.encode(rfc2315.Data(csr)))

    issuer_and_serial = rfc2315.IssuerAndSerialNumber()
    issuer_and_serial.setComponentByName('issuer', cert[0]['tbsCertificate']['issuer'])
    issuer_and_serial.setComponentByName('serialNumber', cert[0]['tbsCertificate']['serialNumber'])

    raw_signature, _ = _sign(private_key, csr)
    signature = rfc2314.univ.OctetString(hexValue=binascii.hexlify(raw_signature).decode('ascii'))

    # Microsoft adds parameters with ASN.1 NULL encoding here,
    # but according to rfc5754 they should be absent:
    # "Implementations MUST generate SHA2 AlgorithmIdentifiers with absent parameters."
    sha2 = rfc2315.AlgorithmIdentifier()
    sha2.setComponentByName('algorithm', (2, 16, 840, 1, 101, 3, 4, 2, 1))

    alg_from_cert = cert[0]['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']
    digest_encryption_algorithm = rfc2315.AlgorithmIdentifier()
    digest_encryption_algorithm.setComponentByName('algorithm', alg_from_cert)
    digest_encryption_algorithm.setComponentByName('parameters', '\x05\x00')

    signer_info = rfc2315.SignerInfo()
    signer_info.setComponentByName('version', 1)
    signer_info.setComponentByName('issuerAndSerialNumber', issuer_and_serial)
    signer_info.setComponentByName('digestAlgorithm', sha2)
    signer_info.setComponentByName('digestEncryptionAlgorithm', digest_encryption_algorithm)
    signer_info.setComponentByName('encryptedDigest', signature)

    signer_infos = rfc2315.SignerInfos().setComponents(signer_info)

    digest_algorithms = rfc2315.DigestAlgorithmIdentifiers().setComponents(sha2)

    extended_cert_or_cert = rfc2315.ExtendedCertificateOrCertificate()
    extended_cert_or_cert.setComponentByName('certificate', cert[0])

    extended_certs_and_cert = rfc2315.ExtendedCertificatesAndCertificates().subtype(
        implicitTag=rfc2315.tag.Tag(rfc2315.tag.tagClassContext,
                                    rfc2315.tag.tagFormatConstructed, 0))
    extended_certs_and_cert.setComponents(extended_cert_or_cert)

    signed_data = rfc2315.SignedData()
    signed_data.setComponentByName('version', 1)
    signed_data.setComponentByName('digestAlgorithms', digest_algorithms)
    signed_data.setComponentByName('contentInfo', content_info)
    signed_data.setComponentByName('certificates', extended_certs_and_cert)
    signed_data.setComponentByName('signerInfos', signer_infos)

    outer_content_info = rfc2315.ContentInfo()
    outer_content_info.setComponentByName('contentType', rfc2315.signedData)
    outer_content_info.setComponentByName('content', encoder.encode(signed_data))

    return encoder.encode(outer_content_info)

def _pem_encode_csr(csr):
    """Encodes the CSR in PEM format"""
    b64_csr = base64.b64encode(csr).decode('ascii')
    b64rn_csr = '\r\n'.join(b64_csr[pos:pos+64] for pos in range(0, len(b64_csr), 64))
    pem_csr = '-----BEGIN NEW CERTIFICATE REQUEST-----\r\n'
    pem_csr += b64rn_csr
    pem_csr += '\r\n-----END NEW CERTIFICATE REQUEST-----'
    return pem_csr

def create_pkcs7csr(cert, key, new_key=None):
    """
    Creates a Microsoft style "PKCS #7 renewal request"

    Args:
        cert: The certificate to renew (cryptography.x509.Certificate)
        key: The private key belonging to the certificate
             (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey OR
             cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey)
        new_key: The key to use in the CSR (optional)
    Returns:
        A PEM encoded PKCS #7 CSR
    Raises:
        UnsupportedKeyTypeError: If one of the keys is an unsupported type
    """

    if not new_key:
        new_key = key

    decoded_cert = decoder.decode(cert.public_bytes(serialization.Encoding.DER),
                                  asn1Spec=rfc2315.Certificate())

    csr = _create_csr(decoded_cert, new_key)
    pkcs7csr = _create_pkcs7(decoded_cert, csr, key)

    return _pem_encode_csr(pkcs7csr)
