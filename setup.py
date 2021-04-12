import setuptools

with open("README.md", "r") as fh:
  long_description = fh.read()

setuptools.setup(
  name="python-firewall",
  version="0.0.1",
  author="Neo Chen",
  author_email="netkiller@msn.com",
  description="Python firewall(iptables)",
  long_description=long_description,
  long_description_content_type="text/markdown",
  url="https://github.com/netkiller/firewall",
  packages=setuptools.find_packages(),
  classifiers=[
  "Programming Language :: Python :: 3",
  "License :: OSI Approved :: MIT License",
  "Operating System :: OS Independent",
  ],
)