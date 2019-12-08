# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path
import sys
import subprocess

PYTHON_PATH = sys.executable

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()
        
open('./pymerang/__init__.py', 'a').close()
# Generate python grpc stubs from proto files

print('Generation of python gRPC stubs')
args = "-I. --proto_path=./pymerang --python_out=. --grpc_python_out=. pymerang/*.proto"
result = subprocess.call("%s -m grpc_tools.protoc %s" % (PYTHON_PATH, args), shell=True)
if result != 0:
    exit(-1)

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.
setup(
    name='pymerang',  
    version='1.0-beta',
    description='Pymerang',  # Required
    long_description=long_description,
    long_description_content_type='text/markdown',  # Optional (see note above)
    url='',  # Optional
    packages=['pymerang'],  # Required
    install_requires=['setuptools']
)