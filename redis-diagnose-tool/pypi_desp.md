# redis-diagnose-tool
[![Python - Version](https://img.shields.io/badge/python-%3E%3D3.6-brightgreen)](https://www.python.org/doc/versions/)
[![PyPI - Version](https://img.shields.io/pypi/v/redis-diagnose-tool)](https://pypi.org/project/redis-diagnose-tool/)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

`redis-diagnose-tool` is a tool for diagnosing `Redis/Tair` client connection errors and supports detecting the response rtt of the DB Server in the `Redis/Tair` instance.

**This diagnostic tool is only applicable to clients connecting to Alibaba Cloud's Redis and Tair instances**

**Process:**

1. The client attempts to establish a TCP connection with the `Redis/Tair` instance
2. Execute the `AUTH` command to verify the username and password. If no password is specified, execute the `PING` command to verify whether the password-free function is enabled
3. Use the `INFO` command and Alibaba Cloud [proxy](https://help.aliyun.com/zh/tair/developer-reference/in-house-commands-for-tair-instances-in-proxy-mode?spm=a2c4g.11174283.0.0.6484137doOGYo5) self-developed `IINFO` command and `RIINFO` command to detect the response rtt of the DB Server

<img src="https://github.com/tair-opensource/tair-tools/blob/main/redis-diagnose-tool/assets/diagnostic_process_en.png" width="35%" height="35%" />

****

## Installation

**Install from pip, requires Python 3.6 or higher**

```bash
# 1. Install from pypi
pip install redis-diagnose-tool

# 2. Intall from source
git clone https://github.com/tair-opensource/tair-tools.git
cd redis-diagnose-tool
pip install .
```

the executable program `diag` will be installed in the bin directory of the Python interpreter. 

Use `pip show redis-diagnose-tool` to find the installation path of the redis-diagnose-tool package. The argument template `arguments.yaml` is stored in the diagnose directory under the installation path.



## Usage

The tool supports basic mode and advanced mode.

The basic mode can only detect whether the client can establish a TCP connection with the `Redis/Tair` instance and give an error message if the connection fails.

In advanced mode, you can use the [OpenAPI](https://help.aliyun.com/zh/tair/developer-reference/openapi-sdk?spm=a2c4g.11186623.0.0.42447a9eQX2LVu) of `Redis/Tair` to obtain basic information, network information, whitelist, and other information about the instance. If the client is on ECS, it can also use the [ECS OpenAPI](https://help.aliyun.com/zh/ecs/developer-reference/api-reference-ecs/?spm=a2c4g.11186623.0.0.6ada2e55g69huQ) to obtain information about the ECS instance. Therefore, advanced mode can diagnose specific problems that cause connection failures, including incorrect connection information, connecting to the instance through the instance's intranet address in a public network environment, incorrect configuration of the whitelist or instance security group, and ECS security group interception.

Both basic mode and advanced mode support verifying user passwords and detecting the response of the DB Server inside the instance.

**Arguments Description:**

```
Redis diagnose tool configuration

optional arguments:
  --help                        Help information
  -c CONFIG, --config CONFIG    Configuration file path (YAML format). If the configuration file is specified, the command arguments won't work.

Tool options:
  -A, --advanced                   Enable advanced mode, default off
  -d, --detect_server              Detect server, default off
  -l {zh,en}, --language {zh,en}   Language, zh for Chinese and en for English, default zh

Redis instance connection information:
  -h HOST, --host HOST                Connection hostname
  -p PORT, --port PORT                Connection port, default 6379
  -t TIMEOUT, --timeout TIMEOUT       Connection timeout, second, default 2s
  -u USER, --user USER                Username
  -a PASSWORD, --password PASSWORD    Password

Redis instance information:
  Following arguments should be specified in advanced mode. You only need to specify one of redis_region_id and redis_endpoint.

  -r REDIS, --redis REDIS                                  Redis instance id
  -g REDIS_REGION_ID, --redis_region_id REDIS_REGION_ID    Redis instance region id
  -o REDIS_ENDPOINT, --redis_endpoint REDIS_ENDPOINT       Redis instance endpoint

ECS instance information:
  Following arguments should be specified in advanced mode if the client is on ECS. You only need to specify one of ecs_region_id and ecs_endpoint.

  -e ECS, --ecs ECS                                  ECS instance id
  -G ECS_REGION_ID, --ecs_region_id ECS_REGION_ID    ECS instance region id
  -O ECS_ENDPOINT, --ecs_endpoint ECS_ENDPOINT       ECS instance endpoint

SDK information:
  Following arguments should be specified in advanced mode.

  -k AK, --ak AK        Access key id
  -s SK, --sk SK        Access key secret
```

**Usage Examples:**

```bash
# Installed from pip, you can run diag directly when the bin directory is added to the environment path

diag --help
```

run in basic mode

```bash
diag -h "connection_address" -p 6379 -u "user" -a "password"
```

run in advanced mode

```bash
diag -h "connection_address" -p 6379 -u "user" -a "password" -k "ak" -s "sk" -r "redis_instance_id" -g "redis_region_id" -A
```

Use argument template `arguments.yaml`

In advanced mode, you need to set multiple optional arguments in the command line, which is cumbersome and error-prone, so an argument template is provided

```bash
diag --config "arguments.yaml"
```

If the argument template is used, the command line arguments will be invalid.

## Log Description

- diagnose.log: diagnostic logs, which record the diagnostic process, detailed connection diagnostic reports, and DB Server diagnostic reports

- sdk.log: record the call log of Open API, including interface, return value, and error
- error.log: record exception information and exception throwing links

## License

[MIT](https://github.com/tair-opensource/tair-tools/blob/main/LICENSE)