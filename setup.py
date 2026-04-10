from setuptools import setup

setup(
    name="flask-currency-utils",
    version="2.3.2",
    py_modules=["currency_utils", "_rates"],
    install_requires=["requests"],
)
