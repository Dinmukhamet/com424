# Port Scan Detection tool

This project was developed during the Information Security course and its objective is to detect port scans of various types in provided PCAP files.

# Table of Contents

- [Usage](#usage)
  - [Local](#local)
  - [In Docker](#in-docker)
- [Example](#example)

## Usage

### Local

To run this program you need to have python 3.8 installed (other 3.x versions might as well work, but it is untested).

With python you can install [pip](https://pip.pypa.io/en/stable/installation/).

```
python get-pip.py
```

It is needed to install [pipenv](https://pipenv.pypa.io/en/latest/).

```
pip install pipenv
```

After successfull installation of pipenv, run this command to install other dependencies:

```
pipenv install
```

Finally, you can run the script as follows.

```
pipenv run <python_executable> main.py <your_pcap_file>
```

### In Docker

If you are experienced with Docker, feel free to run it this way:

1) Build image
```
docker build -t scan-detector .
```

2) Run image
```
docker run --rm scans <your_pcap_file>
```

## Example

The "scan_types" directory stores examples of pcap files.

For instance, we need to check ports for XMAS scan. Then you need to run the script in the following way:

```
pipenv run python3 main.py scan_types/xmas_scan.pcap
```

or in Docker (after build)

```
docker run --rm scans scan_types/xmas_scan.pcap
```

The output will be the following:

```
Searching for XMAS scans.
XMAS scans were detected!
+---------------+-------------------+-----------------+
|      host     | number of attacks | number of ports |
+---------------+-------------------+-----------------+
| 192.168.1.103 |        1668       |       1663      |
+---------------+-------------------+-----------------+
Searching for UDP scans.
UDP scans not detected!
Searching for Half Open scans.
Half Open scans not detected!
Searching for NULL scans.
NULL scans not detected!
Searching for ICMP echo scans.
ICMP echo scans not detected!
```