from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bughound",
    version="0.1.0",
    author="BugHound Team",
    description="AI-powered bug bounty MCP agent",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bughound",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    install_requires=[
        "mcp>=0.1.0",
        "pydantic>=2.0.0",
        "asyncio-throttle>=1.0.2",
        "python-nmap>=0.7.1",
        "dnspython>=2.4.0",
        "pyyaml>=6.0",
        "aiofiles>=23.0.0",
        "python-dotenv>=1.0.0",
        "structlog>=23.1.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "pylint>=3.0.0",
            "mypy>=1.5.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "bughound-recon=bughound.mcp_servers.recon_server:main",
            "bughound-analyze=bughound.mcp_servers.analyze_server:main",
        ],
    },
)