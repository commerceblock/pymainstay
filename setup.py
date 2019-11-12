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
    url='https://github.com/commerceblock/py-mainstay',

    # Author details
    author='CommerceBlock',
    author_email='tom@commerceblock.com',

    # Choose your license
    license='LGPL3',

    packages=find_packages(exclude=['docs', 'tests']),

    install_requires=[],
    extras_require={},
    package_data={},
    data_files=[],

    entry_points={
        'console_scripts': [
            'msc = mst.mainstay:main',
        ],
    },
)
