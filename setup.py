from setuptools import setup, find_packages

setup(
    name='getTLSInformationToTable',
    version='1.0.1',
    description='Private package to getTLSInformationToTable, a tool to convert Nmap and Censys scans to a table',
    url='git@github.com:JavaliMZ/getTLSInformationToTable.git',
    author='Sylvain Júlio',
    author_email='syjulio123@gmail.com',
    license='unlicense',
    packages=find_packages(),  # Automatically finds all packages in the directory
    zip_safe=False,
    install_requires=[
        'tabulate',  # Ensures that the tabulate library is installed
        'termcolor',  # Ensures that the termcolor library is installed
        'pwntools'  # Ensures that the pwntools library is installed
    ],
    entry_points={
        'console_scripts': [
            'getTLSInformationToTable=getTLSInformationToTable:main'
        ]
    }
)
