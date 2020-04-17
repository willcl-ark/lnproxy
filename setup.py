import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="lnproxy",
    version="0.3.1",
    author="Will Clark",
    author_email="will8clark@gmail.com",
    description="A C-Lightning transport proxy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/willcl-ark/lnproxy",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "trio>=0.13.0",
        "pyln.client>=0.8.0",
        "secp256k1>=0.13.2",
        "hkdf>=0.0.3",
        "coincurve>=13.0.0",
        "eciespy>=0.3.5",
    ],
    python_requires=">=3.7",
)
