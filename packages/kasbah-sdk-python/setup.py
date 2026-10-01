from setuptools import setup, find_packages

setup(
    name="kasbah-sdk",
    version="0.1.0",
    description="KasbahOS Python SDK — govern raw OpenAI and Anthropic Python SDK calls via the Kasbah /v1/govern endpoint.",
    long_description=open("README.md").read() if __name__ == "__main__" else "",
    long_description_content_type="text/markdown",
    author="Kasbah Guard",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "openai": ["openai>=1.0.0"],
        "anthropic": ["anthropic>=0.25.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
