import os
import setuptools


# Declare your non-python data files:
# Files underneath shell/ will be copied into the build preserving the
# subdirectory structure if they exist.
data_files = []
for root, dirs, files in os.walk('shell'):
    data_files.append((os.path.relpath(root, 'shell'),
                       [os.path.join(root, f) for f in files]))

setuptools.setup(
    name='VpnMcast',
    version='0.0.1',
    author='Daniel Kucera',
    author_email='root@mail.danman.eu',
    description='https://blog.danman.eu/multicast-over-stupid-networks/',
    # packages=setuptools.find_packages('src', exclude=['.tox', 'test']),
    packages=["."],
    package_dir={"": "."},
    package_data={".": ["vpnmcast.py"]},
    data_files=data_files,
    install_requires=[
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    zip_safe=False,
    python_requires='>=3.6',
    entry_points={
        "console_scripts": [
            "vpnmcast = vpnmcast:main",
        ],
    }
)


