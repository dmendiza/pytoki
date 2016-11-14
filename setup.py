from setuptools import setup

setup(
    name='pytoki',
    version='0.0',
    py_modules=['pytoki'],
    install_requires=[
        'cffi',
        'click'
    ],
    entry_points='''
        [console_scripts]
        pytoki=pytoki:cli
    ''',
)
