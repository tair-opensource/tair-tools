import argparse
import os
import sys
import yaml
from typing import Mapping, Optional, Any

from diagnose.logger_config import logger
from diagnose.notification_template import NotificationTemplate, ArgumentsNotification


def parse_cmd_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Redis diagnose tool configuration", add_help=False)
    parser.add_argument("--help", default=False, action="store_true", help="Help information")

    parser.add_argument("-c", "--config", type=str, help="Configuration file path (YAML format). If the configuration "
                                                         "file is specified, the command arguments won't work.")
    tool_options = parser.add_argument_group("Tool options")
    tool_options.add_argument("-A", "--advanced", default=False, action="store_true", help="Enable advanced mode, default off")
    tool_options.add_argument("-d", "--detect_server", default=False, action="store_true", help="Detect server, default off")
    tool_options.add_argument("-l", "--language", default="zh", choices=["zh", "en"], help="Language, zh for Chinese and en for English, default zh")

    connect_info = parser.add_argument_group("Redis instance connection information")
    connect_info.add_argument("-h", "--host", type=str, help="Connection hostname")
    connect_info.add_argument("-p", "--port", default=6379, type=int, help="Connection port, default 6379")
    connect_info.add_argument("-t", "--timeout", default=2, type=int, help="Connection timeout, second, default 2s")
    connect_info.add_argument("-u", "--user", type=str, help="Username")
    connect_info.add_argument("-a", "--password", type=str, help="Password")

    instance_info = parser.add_argument_group("Redis instance information", ("Following arguments "
                                                                             "should be specified in advanced mode. "
                                                                             "You only need to specify one of "
                                                                             "redis_region_id and redis_endpoint."))
    instance_info.add_argument("-r", "--redis", type=str, help="Redis instance id")
    instance_info.add_argument("-g", "--redis_region_id", type=str, help="Redis instance region id")
    instance_info.add_argument("-o", "--redis_endpoint", type=str, help="Redis instance endpoint")

    ecs_info = parser.add_argument_group("ECS instance information", "Following arguments "
                                                                     "should be specified in advanced "
                                                                     "mode if the client is on ECS. "
                                                                     "You only need to specify one of "
                                                                     "ecs_region_id and ecs_endpoint.")
    ecs_info.add_argument("-e", "--ecs", type=str, help="ECS instance id")
    ecs_info.add_argument("-G", "--ecs_region_id", type=str, help="ECS instance region id")
    ecs_info.add_argument("-O", "--ecs_endpoint", type=str, help="ECS instance endpoint")

    sdk_info = parser.add_argument_group("SDK information", "Following arguments "
                                                            "should be specified in advanced mode.")
    sdk_info.add_argument("-k", "--ak", type=str, help="Access key id")
    sdk_info.add_argument("-s", "--sk", type=str, help="Access key secret")

    cmd_args = parser.parse_args()
    if cmd_args.help:
        parser.print_help()
        sys.exit(0)
    return cmd_args


def load_config(config_file_path: str) -> Optional[Mapping[str, Any]]:
    if not os.path.exists(config_file_path):
        logger.error(ArgumentsNotification.config_file_not_exist_error())
        return None
    _, extension = os.path.splitext(config_file_path)
    if extension != ".yaml":
        logger.error(ArgumentsNotification.config_file_extension_error())
        return None

    # load config file
    with open(config_file_path, "r") as file:
        config = yaml.safe_load(file)

        str_key = ["language", "host", "user", "password", "redis", "redis_region_id", "redis_endpoint", "ecs",
                   "ecs_region_id", "ecs_endpoint", "ak", "sk"]
        int_key = ["port", "timeout"]
        bool_key = ["advanced", "detect_server"]

        # check value type
        for key in str_key:
            if config.get(key) is not None and not isinstance(config.get(key), str):
                logger.error(ArgumentsNotification.config_file_value_type_error(key, "string"))
                return None
        for key in int_key:
            if config.get(key) is not None and not isinstance(config.get(key), int):
                logger.error(ArgumentsNotification.config_file_value_type_error(key, "integer"))
                return None
        for key in bool_key:
            if config.get(key) is not None and not isinstance(config.get(key), bool):
                logger.error(ArgumentsNotification.config_file_value_type_error(key, "bool"))
                return None

        # add key and set default value
        for key in str_key:
            if config.get(key) is None or len(config.get(key)) == 0:
                config[key] = None
        if config.get("language") is None or len(config.get("language")) == 0:
            config["language"] = "zh"
        if config.get("advanced") is None:
            config["advanced"] = False
        if config.get("detect_server") is None:
            config["detect_server"] = False
        if config.get("port") is None:
            config["port"] = 6379
        if config.get("timeout") is None:
            config["timeout"] = 2

        return config


def get_and_validate_args() -> argparse.Namespace:
    # get args either from cmd or config file
    cmd_args = parse_cmd_args()
    if cmd_args.config is not None:
        config_dict = load_config(cmd_args.config)
        if config_dict is None:
            sys.exit(1)
        cmd_args = argparse.Namespace(**config_dict)
    NotificationTemplate.set_language(cmd_args.language)
    if not validate_args(cmd_args):
        logger.error(ArgumentsNotification.error_args_hint())
        sys.exit(1)
    return cmd_args


def validate_args(args: argparse.Namespace) -> bool:
    if args.host is None:
        logger.error(ArgumentsNotification.connection_address_empty_error())
        return False
    if args.language not in ["zh", "en"]:
        logger.error(ArgumentsNotification.language_error())
        return False
    if args.port <= 0 or args.port > 65535:
        logger.error(ArgumentsNotification.connection_port_error())
        return False
    if args.timeout <= 0:
        logger.error(ArgumentsNotification.connection_timeout_error())
        return False

    if args.redis is not None and not args.advanced:
        logger.warning(ArgumentsNotification.redis_instance_id_warning())
    if (args.ak is not None or args.sk is not None) and not args.advanced:
        logger.warning(ArgumentsNotification.ak_sk_warning())
    if (args.redis_region_id is not None or args.redis_endpoint is not None) and not args.advanced:
        logger.warning(ArgumentsNotification.region_id_endpoint_warning())
    if args.advanced:
        if args.ak is None or args.sk is None:
            logger.error(ArgumentsNotification.ak_sk_empty_error())
            return False
        if args.redis is None:
            logger.error(ArgumentsNotification.redis_instance_id_empty_error())
            return False
        if args.redis_region_id is None and args.redis_endpoint is None:
            logger.error(ArgumentsNotification.region_id_endpoint_empty_error)
            return False
        if args.ecs is not None and args.ecs_region_id is None and args.ecs_endpoint is None:
            logger.error(ArgumentsNotification.ecs_region_id_endpoint_empty_error())
            return False
    return True
