from setuptools import setup, find_packages

setup(
    name="self-auditor",
    version="1.0.0",
    description="SELF — Smart Contract Auditing Tool",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["click>=8.0", "rich>=13.0"],
    entry_points={
        "console_scripts": [
            "self=self_tool.self:cli",
        ],
    },
    python_requires=">=3.8",
)
