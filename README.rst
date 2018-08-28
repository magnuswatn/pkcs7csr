pkcs7csr
========

.. image:: https://travis-ci.org/magnuswatn/pkcs7csr.svg?branch=master
    :target: https://travis-ci.org/magnuswatn/pkcs7csr

.. image:: https://codecov.io/gh/magnuswatn/pkcs7csr/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/magnuswatn/pkcs7csr

.. image:: https://badge.fury.io/py/pkcs7csr.svg
    :target: https://badge.fury.io/py/pkcs7csr

Python module for creating Microsoft style "PKCS #7 renewal request" for use with Active Directory Certificate Services.

This allows non-IIS web servers to automatically renew their certificates from an ADCS server.

About PKCS #7 renewal requests
------------------------------

The point of a PKCS#7 renewal request is that you prove that you possess an existing valid certificate, and therefore is authorized to get a new one with the same subject.

They consist of a normal PKCS #10 CSR with a special RENEWAL_CERTIFICATE extension containing the original certificate. This in then placed in a PKCS #7 structure and signed with the private key beloinging to the original certificate, and thus proving you are the rightful owner of the original certificate. You are then allowed a certificate with the same subject (and extensions) as the original.

ADCS configuration
------------------
For this to work smoothly your template should have the option to require "CA certificate manager approval" enabled, but allow reenrollment with "valid existing certificate". The service account used for reenrollment must have permission to enroll.

The first certificate then needs to be approved by a CA manager, but renewals can go automatically. It is obviously important to verify the first certificate thorough as it can be used, in practice, forever. Also, it is important to revoke all unexpired certificate if the relevant key is ever compromised.


Installation
------------

.. code-block:: bash

    $ pipenv install pkcs7csr



Example usage
-------------

Renew a certificate, using pkcs7csr and `certsrv <https://github.com/magnuswatn/certsrv>`_:

.. code-block:: python

    import pkcs7csr
    from certsrv import Certsrv
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    # Read the certificate and key from file
    with open('/etc/pki/tls/certs/my_adcs_cert.pem', 'r') as open_file:
        cert = x509.load_pem_x509_certificate(open_file.read(), default_backend())

    with open('/etc/pki/tls/private/my_adcs_key.pem', 'r') as open_file:
        key = serialization.load_pem_private_key(
            open_file.read(),
            password=None,
            backend=default_backend()
        )

    # Create an PKCS #7 renewal request
    csr = pkcs7csr.create_pkcs7csr(cert, key)

    # Submit to the CA server using certsrv
    certsrv = Certsrv('my-adcs-server.example.net', 'myUser', 'myPassword')
    pem_cert = certsrv.get_cert(csr, 'myTemplate')

    # Write the new cert to the file
    with open('/etc/pki/tls/certs/my_adcs_cert.pem', 'w') as open_file:
        open_file.write(pem_cert)

    # Reload apache or whatever here
