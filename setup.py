import os
import re
import codecs

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

def read_file(filename, encoding='utf8'):
    """Read unicode from given file."""
    with codecs.open(filename, encoding=encoding) as fd:
        return fd.read()

here = os.path.abspath(os.path.dirname(__file__))

module = read_file(os.path.join(here, 'pkcs7csr.py'))
meta = dict(re.findall(r"""__([a-z]+)__ = '([^']+)""", module))

readme = read_file(os.path.join(here, 'README.rst'))
version = meta['version']


setup(
    name='pkcs7csr',
    description='A Python module for creating Microsoft style "PKCS #7 renewal requests"',
    long_description=readme,
    author='Magnus Watn',
    license='MIT',
    url='https://github.com/magnuswatn/pkcs7csr',
    keywords='ad adcs certsrv pki certificate csr iis renewal',
    version=version,
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
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Systems Administration',
        ],
)
