try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='pkcs7csr',
    description='A Python module for creating Microsoft style "PKCS #7 renewal requests"',
    author='Magnus Watn',
    license='MIT',
    url='https://github.com/magnuswatn/pkcs7csr',
    keywords='ad adcs certsrv pki certificate csr iis renewal',
    version='1.0.0',
    py_modules=['pkcs7csr'],
    install_requires=[
        'pyasn1',
        'pyasn1-modules',
        'cryptography',
        ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Systems Administration',
        ],
)
