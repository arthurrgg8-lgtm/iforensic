from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="iforensic",
    version="1.0.0",
    author="Antigravity Digital Forensics",
    description="Cross-Platform Enterprise iOS Digital Forensics Acquisition & Artifact Decoding Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    py_modules=["cli"],
    include_package_data=True,
    install_requires=[
        "rich>=13.0.0",
        "python-docx>=1.0.0",
        "cryptography>=3.4.0"
    ],
    entry_points={
        "console_scripts": [
            "iforensic=cli:main"
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Operating System :: OS Independent",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12"
    ],
    python_requires=">=3.8",
)
