from setuptools import setup, find_packages

setup(
    name="slither-detector-generic-slippage",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["slither-analyzer"],
    entry_points={
        "slither_analyzer.plugin": [
            "generic_slippage = generic_slippage.plugin:make_plugin",
        ],
    },
)
