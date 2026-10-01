from setuptools import setup, find_packages

setup(
    name='kasbah-core',
    version='3.0.0',
    description='Kasbah Core - Complete detection engine with ALL novel features (13 moats, spatial intelligence, authority protocol, quantum crypto, content passport, ML-based AI detection)',
    long_description=open('README.md').read() if __import__('os').path.exists('README.md') else '',
    long_description_content_type='text/markdown',
    author='Kasbah Guard Team',
    author_email='support@bekasbah.com',
    url='https://github.com/kasbah-guard/kasbah-core',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=[
        'numpy>=1.20.0',
        'scipy>=1.7.0',
        'scikit-learn>=1.0.0',
        'transformers>=4.30.0',
        'onnxruntime>=1.15.0',
        'torch>=2.0.0',
        'librosa>=0.10.0',
        'opencv-python>=4.8.0',
        # 'face-recognition>=1.3.0',  # Requires cmake - install separately if needed
        'psutil>=5.9.0',
        'requests>=2.31.0',
        'Pillow>=10.0.0'
    ],
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'black>=23.0.0',
            'mypy>=1.5.0',
            'ruff>=0.1.0'
        ]
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Scientific/Engineering :: Artificial Intelligence'
    ],
    keywords='kasbah ai-detection security moats quantum-safe deepfake voice-detection',
    include_package_data=True,
    zip_safe=False
)
