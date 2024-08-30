from setuptools import setup, find_packages

setup(
    name="redis-diagnose-tool",
    version="0.1.1",
    url="https://github.com/tair-opensource/tair-tools/tree/main/redis-diagnose-tool",
    description="redis-diagnose-tool is a tool for diagnosing Redis/Tair client connection errors.",
    long_description=open("pypi_desp.md").read().strip(),
    long_description_content_type="text/markdown",
    packages=find_packages(
        include=[
            "diagnose",
        ]
    ),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "diag=diagnose.diag:start_diagnose",
        ],
    },
    include_package_data=True,
    package_data={
        "diagnose": ["arguments.yaml"],
    },
    license="MIT",
    python_requires=">=3.6",
    install_requires=[
        "PyYAML>=6.0.1",
        "redis>=4.3.0",
        "psutil>=6.0.0",
        "distro>=1.9.0",
        "requests>=2.27.1",
        "python-dateutil>=2.9.0",
        "colorlog>=6.8.2",
        "alibabacloud-r-kvstore20150101>=4.2.0",
        "alibabacloud-ecs20140526>=4.1.8",
        "tqdm>=4.63.0",
    ],
)