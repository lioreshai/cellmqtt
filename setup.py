import setuptools

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name='cellmqtt',
    author='Liore Shai',
    description='Lightweight IoT MQTT library for mobile network chips.',
    keywords='MQTT, iot, cellular, gsm, gprs, sim800c',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/lioreshai/cellmqtt',
    project_urls={
        'Documentation': 'https://github.com/lioreshai/cellmqtt',
        'Bug Reports':
        'https://github.com/lioreshai/cellmqtt/issues',
        'Source Code': 'https://github.com/lioreshai/cellmqtt',
        # 'Funding': '',
        # 'Say Thanks!': '',
    },
    package_dir={'': 'src'},
    packages=setuptools.find_packages(where='src'),
    classifiers=[
        # see https://pypi.org/classifiers/
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',

        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
    # install_requires=['Pillow'],
    extras_require={
        'dev': ['check-manifest'],
        # 'test': ['coverage'],
    },
    # entry_points={
    #     'console_scripts': [  # This can provide executable scripts
    #         'run=examplepy:main',
    # You can execute `run` in bash to run `main()` in src/examplepy/__init__.py
    #     ],
    # },
)