import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="lnproxy",
    version="0.5.2",
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
    python_requires=">=3.7",
)
