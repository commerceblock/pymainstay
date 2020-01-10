from setuptools import setup, find_packages
from codecs import open
from os import path
from mst import __version__

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pymainstay',

    version=__version__,

    description='Tool to attest state and verify Mainstay sequence proofs',
    long_description=long_description,
    long_description_content_type='text/markdown',

    # The project's main homepage.
    url='https://github.com/commerceblock/pymainstay',
    download_url='https://github.com/commerceblock/pymainstay/archive/0.1.1.tar.gz',

    # Author details
    author='CommerceBlock',
    author_email='tom@commerceblock.com',

    # Choose your license
    license='MIT',

    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3 :: Only',
    ],

    packages=find_packages(exclude=['docs', 'tests']),

    install_requires=['appdirs>=1.3.0',
                      'GitPython>=2.0.8'],
    extras_require={},
    package_data={},
    data_files=[],

    entry_points={
        'console_scripts': [
            'msc = mst.mainstay:main',
        ],
    },
)
