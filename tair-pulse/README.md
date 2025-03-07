# tair-pulse

tair-pulse is a tool for visualizing the latency and availability of Tair/Redis instances.

![image.png](https://s2.loli.net/2025/03/06/fdOBVr9DGRWKycb.png)

## Installation

tair-pulse requires `Python 3.8` or later.

Install it using `pip` or your preferred PyPI package manager.

```bash
pip install tair-pulse
```

## Usage

```bash
usage: tair-pulse [-h] [--host HOST] [--port PORT] [--password PASSWORD]
                  [--cluster] [--max-rt MAX_RT]
```

### Optional Arguments:

- `-h, --help`: Show the help message and exit.
- `--host HOST`: Specify the server hostname (default is 127.0.0.1).
- `--port PORT`: Specify the server port (default is 6379).
- `--password PASSWORD`: Specify the password for Tair/Redis authentication.
- `--cluster`: Specify if the server is a node of the Tair/Redis cluster.
- `--max-rt MAX_RT`: Print the key that exceeds the specified maximum response time (default is 0).
- `--fork`: Use `save` to trigger fork(2) in order to test latency.

### Examples:

Run tair-pulse with the default configuration against 127.0.0.1:6379:

```bash
$ tair-pulse
```

Test an Aliyun Tair instance without a password:

```bash
$ tair-pulse --host r-bp1qf8wio5zkp01pzt.redis.rds.aliyuncs.com
```

Test a cluster instance with a password, where one of the nodes is 192.168.10.1:7000:

```bash
$ tair-pulse --host 192.168.10.1 --port 7000 --password 123456 --cluster
```

Note: Replace the values in the examples with your actual server hostname, port, and password if applicable.