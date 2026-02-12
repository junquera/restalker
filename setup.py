from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="restalker",
    version="2.1.1",
    description="Text analyzer package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/junquera/stalker",
    author="Javier Junquera Sánchez",
    author_email="javier@junquera.io",
    license="MIT",
    packages=["restalker"],
    install_requires=[
        "based58",
        "bech32ref",
        "bip-utils",
        "bs4",
        "gliner2",
        "monero",
        "web3",
        "lxml",
        "phonenumbers",
        "pyexifinfo",
        "python-magic",
        "PyPDF2",
        "olefile",
    ],
    extras_require={
        # NVIDIA GPU support (CUDA)
        # Install with: pip install restalker[gpu]
        "gpu": [
            "torch>=2.0.0",  # Will install CUDA variant from PyTorch index
        ],
        # AMD GPU support (ROCm)
        # Install with: pip install restalker[amd-gpu]
        "amd-gpu": [
            "torch>=2.0.0",  # Will install ROCm variant from PyTorch index
        ],
        # CPU-only (default)
        # Install with: pip install restalker or pip install restalker[cpu]
        "cpu": [
            "torch>=2.0.0",  # Will install CPU-only variant
        ],
    },
    entry_points={"console_scripts": ["restalker=restalker.restalker:main"]},
)
