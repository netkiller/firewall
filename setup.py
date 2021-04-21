import setuptools
from netkiller import __version__, name, __author__

with open("README.md", "r") as fh:
  long_description = fh.read()

setuptools.setup(
  name=name,
  version=__version__,
  author=__author__,
  author_email="netkiller@msn.com",
  description="Netkiller Python firewall",
  long_description=long_description,
  long_description_content_type="text/markdown",
  url="https://github.com/netkiller/firewall",
  license='MIT',
  # py_modules = ['firewall'],
  packages=setuptools.find_packages(),
  # packages=[''],
  # packages=setuptools.find_packages('packages'),
  # package_dir = {'':'package'},
  classifiers=[
  "Programming Language :: Python :: 3",
  "License :: OSI Approved :: MIT License",
  "Operating System :: OS Independent",
  ],
)