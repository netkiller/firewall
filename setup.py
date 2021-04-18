import setuptools
# from firewall import __version__, __author__

with open("README.md", "r") as fh:
  long_description = fh.read()

setuptools.setup(
  name="netkiller-firewall",
  version="0.0.1",
  author="Neo Chen",
  author_email="netkiller@msn.com",
  description="Python firewall(iptables)",
  long_description=long_description,
  long_description_content_type="text/markdown",
  url="https://github.com/netkiller/firewall",
  license='BSD',
  # py_modules = ['firewall'],
  # packages=setuptools.find_packages(),
  packages=[''],
  # packages=setuptools.find_packages('packages'),
  # package_dir = {'':'packages'},
  classifiers=[
  "Programming Language :: Python :: 3",
  "License :: OSI Approved :: MIT License",
  "Operating System :: OS Independent",
  ],
)