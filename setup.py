#!/usr/bin/env python2

from setuptools import setup, find_packages

# to set __version__
exec(open('blockstack_gpg/version.py').read())

setup(
    name='blockstack-gpg',
    version=__version__,
    url='https://github.com/blockstack/blockstack-gpg',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='GPG integration for Blockstack client applications',
    keywords='blockchain git crypography name key value store data',
    packages=find_packages(),
    download_url='https://github.com/blockstack/gitsec/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'blockstack-client>=0.14.0',
        'gnupg>=2.2.0'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
