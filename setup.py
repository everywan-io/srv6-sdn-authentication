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

# Read version from VERSION file
with open(path.join(here, 'VERSION')) as version_file:
    version = version_file.read().strip()

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.
setup(
    name='pymerang',  
    version=version,
    description='Pymerang',  # Required
    long_description=long_description,
    long_description_content_type='text/markdown',  # Optional (see note above)
    url='',  # Optional
    packages=['pymerang'],  # Required
    install_requires=[
        'setuptools',
        'netifaces>=0.10.9',
        'grpcio>=1.19.0',
        'grpcio-tools>=1.19.0',
        'python-pytun>=2.3.0',
        'tornado>=6.0.3',
        'websocket-client>=0.56.0',
        'ping3>=2.4.0',
        'pynat',
        'pyroute2'
    ]
)
