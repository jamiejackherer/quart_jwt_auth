import os
import re

from setuptools import setup

with open("README.md", "r") as f:
    long_description = f.read()

with open(os.path.join("quart_jwt_auth", "__init__.py"), "r") as f:
    try:
        version = re.findall(r"^__version__ = \"([^']+)\"\r?$", f.read(), re.M)[0]
    except IndexError:
        raise RuntimeError("Unable to determine version.")


setup(
    name="Quart-JWT-Auth",
    version=version,
    url="https://gitlab.com/jamieoglindsey0/quart_jwt_auth",
    license="MIT",
    author="Jamie Lindsey",
    author_email="jamieoglindsey0@gmail.com",
    keywords=["jwt", "auth", "quart"],
    description="JWT library for Quart",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=["quart_jwt_auth"],
    install_requires=["PyJWT", "quart", "quart_login"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)