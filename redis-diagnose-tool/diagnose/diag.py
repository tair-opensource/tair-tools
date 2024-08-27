import warnings
warnings.filterwarnings("ignore", category=Warning)

import sys
import time
import traceback
import socket

from typing import Tuple, Optional

import diagnose.diagnostic_report
from diagnose.client import Client
from diagnose.redis_instance import RedisInstance
from diagnose import utils
import diagnose.arguments as arguments
from diagnose.sdk import SDKFactory, SDKType
from diagnose.logger_config import logger, error_log
from diagnose.diagnostic_report import ConnectionDiagnosticReport, ServerDiagnosticReport, ProcessReport, Check
from diagnose.exceptions import (
    DiagnosisError,
    SDKError,
    InternalError,
    EcsSecurityGroupError,
    NameserverError,
    ConnectInfoError,
)
from diagnose.notification_template import (
    InitializationNotification,
    ArgumentsNotification,
    TCPConnectionNotification,
    DNSResolutionNotification,
    ConnectionTimeoutNotification,
    NetworkUnreachableNotification,
    AuthenticationNotification,
    ServerDetectionNotification,
)


def start_diagnose():
    # Output banner
    logger.info(diagnose.diagnostic_report.BANNER)

    # Get and validate args
    try:
        args = arguments.get_and_validate_args()
    except Exception as e:
        error_log.error(traceback.format_exc())
        logger.error(ArgumentsNotification.get_args_error(print_trace=True).format(str(e)))
        return

    # Configure sdk
    if args.advanced:
        region_id_map = {SDKType.REDIS: args.redis_region_id, SDKType.ECS: args.ecs_region_id}
        endpoint_map = {SDKType.REDIS: args.redis_endpoint, SDKType.ECS: args.ecs_endpoint}
        SDKFactory.config_sdk(access_key_id=args.ak, access_key_secret=args.sk, endpoint_map=endpoint_map,
                              region_id_map=region_id_map)

    diagnose_connection(args)


def diagnose_connection(args):
    # Output process title
    logger.info(ProcessReport.title_line)
    logger.info(ProcessReport.title())
    logger.info(ProcessReport.title_line)

    # Get connection info
    redis_connection_info = {"host": args.host, "port": args.port, "username": args.user, "password": args.password,
                             "socket_connect_timeout": args.timeout, "socket_timeout": args.timeout,
                             "retry_on_timeout": True, "decode_responses": True}

    # Initialize client and redis instance
    logger.info(ProcessReport.get_task_name(0))
    local_client, redis_instance = initialize(args)
    while local_client is None or redis_instance is None:
        if not args.advanced:  # Initialization failed in basic mode, exit
            logger.info(ProcessReport.gen_process_rectangle(ProcessReport.finish))
            logger.info(ProcessReport.title_line)
            logger.info(ProcessReport.title_end())
            logger.info(ProcessReport.title_line)

            ConnectionDiagnosticReport.output_report()
            sys.exit(1)

        # Initialization failed in advanced mode, retry in basic mode
        args.advanced = False
        local_client, redis_instance = initialize(args)

    # 1. Try to establish a TCP connection between the client and the redis instance
    logger.info(ProcessReport.split_line)
    logger.info(ProcessReport.get_task_name(1) + ProcessReport.arrow_head)
    connected = False
    ConnectionDiagnosticReport.add_check(Check(TCPConnectionNotification.check_name()))
    tcp_connection_check = ConnectionDiagnosticReport.get_last_check()
    try:
        # Establish a TCP connection and perform targeted diagnostics based on the type of exception
        logger.info(ProcessReport.gen_process_rectangle(ProcessReport.get_step_name("tcp_connection")))
        start = time.time()
        client_socket = utils.establish_tcp_connection(args.host, args.port, args.timeout)
        end = time.time()
        rt_ms = (end - start) * 1000
        connected = client_socket is not None
        if connected:
            logger.info(ProcessReport.get_arrow_line(yes=True, message=f"{rt_ms:.3f} ms"))
            tcp_connection_check.success()
            tcp_connection_check.set_detail(TCPConnectionNotification.check_success_detail())
        else:
            logger.error(ProcessReport.get_arrow_line(yes=False))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            tcp_connection_check.fail()
            tcp_connection_check.set_detail(TCPConnectionNotification.fail_no_exception_detail())
            ConnectionDiagnosticReport.add_issue(TCPConnectionNotification.no_exception_issue())
    except socket.timeout:
        # Connection timeout
        logger.error(ProcessReport.get_arrow_line(yes=False, message="Timeout"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        tcp_connection_check.fail()
        tcp_connection_check.set_detail(TCPConnectionNotification.connection_timeout_detail())
        diagnose_connection_timeout(local_client, redis_instance)
    except socket.gaierror:
        # DNS domain name resolution failure
        logger.error(ProcessReport.get_arrow_line(yes=False, message="DNS Error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        tcp_connection_check.fail()
        tcp_connection_check.set_detail(TCPConnectionNotification.domain_name_resolution_fail_detail())
        diagnose_dns_domain_name_resolution(local_client, redis_instance)
    except ConnectionRefusedError:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="Connection Refused"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        tcp_connection_check.fail()
        tcp_connection_check.set_detail(TCPConnectionNotification.connection_refused_detail())
        ConnectionDiagnosticReport.add_issue(TCPConnectionNotification.fail_issue())
    except socket.error as e:
        error_log.error(traceback.format_exc())
        tcp_connection_check.fail()
        if "Network is unreachable" in str(e):  # Network unreachable
            logger.error(ProcessReport.get_arrow_line(yes=False, message="Network Unreachable"))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            tcp_connection_check.set_detail(TCPConnectionNotification().network_unreachable_detail())
            diagnose_connection_network_unreachable(local_client, redis_instance)
        else:  # Unknown socket error
            logger.error(ProcessReport.get_arrow_line(yes=False, message="Socket Error"))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            tcp_connection_check.set_detail(TCPConnectionNotification.socket_error_detail(print_trace=True).format(e))
            ConnectionDiagnosticReport.add_issue(TCPConnectionNotification.fail_issue())
    except Exception as e:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="Unexpected Error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        error_log.error(traceback.format_exc())
        tcp_connection_check.fail()
        tcp_connection_check.set_detail(TCPConnectionNotification.error_detail(print_trace=True).format(e))
        ConnectionDiagnosticReport.add_issue(TCPConnectionNotification.fail_issue())
    if not connected:
        logger.info(ProcessReport.gen_process_rectangle(ProcessReport.finish))
        logger.info(ProcessReport.title_line)
        logger.info(ProcessReport.title_end())
        logger.info(ProcessReport.title_line)

        ConnectionDiagnosticReport.output_report()
        if args.detect_server:
            logger.warning(TCPConnectionNotification.fail_warning())
        return

    # 2. Username and password authentication
    logger.info(ProcessReport.split_line)
    logger.info(ProcessReport.get_task_name(2) + ProcessReport.arrow_head)
    ConnectionDiagnosticReport.add_check(Check(AuthenticationNotification.check_name()))
    password_auth_check = ConnectionDiagnosticReport.get_last_check()
    auth_success = False
    try:
        logger.info(ProcessReport.gen_process_rectangle(ProcessReport.get_step_name("auth")))
        auth_success, error = Client.auth(client_socket, args.user, args.password)
        if auth_success:
            logger.info(ProcessReport.get_arrow_line(yes=True))
            if not args.detect_server:
                logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
            password_auth_check.success()
            password_auth_check.set_detail(AuthenticationNotification.success_detail())
        else:
            password_auth_check.fail()
            if error == "Invalid Password":
                logger.error(ProcessReport.get_arrow_line(yes=False, message="Invalid Password"))
                logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
                ConnectionDiagnosticReport.add_issue(AuthenticationNotification.invalid_password_issue())
                desensitized_password = "*" * len(args.password) if args.password is not None else None
                password_auth_check.set_detail(AuthenticationNotification.invalid_password_detail().format(
                    args.user, desensitized_password))
            elif error == "No Authentication":
                logger.error(ProcessReport.get_arrow_line(yes=False, message="No AUTH"))
                logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
                ConnectionDiagnosticReport.add_issue(AuthenticationNotification.no_auth_issue())
                password_auth_check.set_detail(AuthenticationNotification.no_auth_detail())
            elif error == "Invalid Username-password Pair":
                logger.error(ProcessReport.get_arrow_line(yes=False, message="Invalid User-Password Pair"))
                logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
                ConnectionDiagnosticReport.add_issue(AuthenticationNotification.invalid_username_password_pair_issue())
                password_auth_check.set_detail(AuthenticationNotification.invalid_username_password_pair_detail())
            else:
                logger.error(ProcessReport.get_arrow_line(yes=False))
                logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
                password_auth_check.set_detail(AuthenticationNotification.fail_detail().format(error))
                ConnectionDiagnosticReport.add_issue(AuthenticationNotification.fail_issue())
    except socket.timeout:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="Timeout"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        password_auth_check.fail()
        password_auth_check.set_detail(AuthenticationNotification.timeout_detail())
        diagnose_authentication_timeout(local_client, redis_instance)
    except socket.error as e:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="Socket Error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        error_log.error(traceback.format_exc())
        password_auth_check.fail()
        password_auth_check.set_detail(AuthenticationNotification.socket_error_detail(print_trace=True).format(e))
        ConnectionDiagnosticReport.add_issue(AuthenticationNotification.fail_issue())
    except Exception as e:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="Unexpected Error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        error_log.error(traceback.format_exc())
        password_auth_check.fail()
        password_auth_check.set_detail(AuthenticationNotification.unexpected_error(print_trace=True).format(e))
        ConnectionDiagnosticReport.add_issue(AuthenticationNotification.fail_issue())
    finally:
        if client_socket is not None:
            client_socket.close()
    if not auth_success:
        logger.info(ProcessReport.gen_process_rectangle(ProcessReport.finish))
        logger.info(ProcessReport.title_line)
        logger.info(ProcessReport.title_end())
        logger.info(ProcessReport.title_line)

        ConnectionDiagnosticReport.output_report()
        if args.detect_server:
            logger.warning(AuthenticationNotification.fail_warning())
        return

    # 3. Detect redis servers
    if args.detect_server:
        logger.info(ProcessReport.split_line)
        logger.info(ProcessReport.get_task_name(3) + ProcessReport.arrow_head)
        success = False
        exp = None
        try:
            logger.info(ProcessReport.gen_process_rectangle(ProcessReport.get_step_name("detect_server")))
            avg_rt_ms = redis_instance.detect_servers(redis_connection_info)
            success = True
            logger.info(ProcessReport.get_arrow_line(yes=True, message=f"avg_rt: {avg_rt_ms:.3f} ms"))
            logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
        except Exception as e:
            exp = e
            logger.error(ProcessReport.get_arrow_line(yes=False))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            error_log.error(traceback.format_exc())
        logger.info(ProcessReport.gen_process_rectangle(ProcessReport.finish))
        logger.info(ProcessReport.title_line)
        logger.info(ProcessReport.title_end())
        logger.info(ProcessReport.title_line)
        if success:
            logger.info(ServerDiagnosticReport.generate_report())
        elif exp is not None:
            logger.error(ServerDetectionNotification.fail_log(print_trace=True).format(exp))
    else:
        logger.info(ProcessReport.gen_process_rectangle(ProcessReport.finish))
        logger.info(ProcessReport.title_line)
        logger.info(ProcessReport.title_end())
        logger.info(ProcessReport.title_line)


def initialize(args) -> Tuple[Optional[Client], Optional[RedisInstance]]:
    if args.advanced:
        logger.info(ProcessReport.gen_process_rectangle(ProcessReport.get_step_name("advanced_init")))
        ConnectionDiagnosticReport.add_check(Check(InitializationNotification.advanced_check_name()))
        init_check = ConnectionDiagnosticReport.get_last_check()
    else:
        logger.info(ProcessReport.gen_process_rectangle(ProcessReport.get_step_name("basic_init")))
        ConnectionDiagnosticReport.add_check(Check(InitializationNotification.basic_check_name()))
        init_check = ConnectionDiagnosticReport.get_last_check()
    try:
        local_client = Client(connection_address=args.host, connection_port=args.port,
                              ecs_instance_id=args.ecs, advanced_mode=args.advanced)
        redis_instance = RedisInstance(args.redis, args.advanced)
        logger.info(ProcessReport.get_arrow_line(yes=True))
        init_check.success()
        return local_client, redis_instance
    except SDKError:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="sdk error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        error_log.error(traceback.format_exc())
        init_check.fail()
        init_check.set_detail(InitializationNotification.init_sdk_error(print_trace=True))
    except InternalError:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="internal error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        error_log.error(traceback.format_exc())
        init_check.fail()
        init_check.set_detail(InitializationNotification.init_internal_error(print_trace=True))
    except Exception:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="unexpected error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        error_log.error(traceback.format_exc())
        init_check.fail()
        init_check.set_detail(InitializationNotification.init_error(print_trace=True))
    if args.advanced:
        ConnectionDiagnosticReport.add_issue(InitializationNotification.init_fail_log_in_advanced_mode())
    else:
        ConnectionDiagnosticReport.add_issue(InitializationNotification.init_fail_log_in_basic_mode())
    return None, None


def diagnose_dns_domain_name_resolution(client: Client, redis_instance: RedisInstance):
    try:
        client.diagnose_dns(redis_instance.get_connection_address())
    except (NameserverError, EcsSecurityGroupError, ConnectInfoError):
        pass
    except Exception as e:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="unexpected error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        error_log.error(traceback.format_exc())
        ConnectionDiagnosticReport.add_warning(DNSResolutionNotification.unexpected_error(print_trace=True).format(e))


def diagnose_connection_timeout(client: Client, redis_instance: RedisInstance):
    try:
        redis_instance.diagnose_connection_info(client)
        redis_instance.diagnose_whitelist(client)
        redis_instance.diagnose_instance_status()
        client.diagnose_connection_interception()
        ConnectionDiagnosticReport.add_issue(TCPConnectionNotification.fail_issue())
    except DiagnosisError:
        pass
    except InternalError as e:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="internal error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        ConnectionDiagnosticReport.add_issue(TCPConnectionNotification.fail_issue())
        error_log.error(traceback.format_exc())
        ConnectionDiagnosticReport.add_warning(ConnectionTimeoutNotification.internal_error(print_trace=True).format(e))
    except Exception as e:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="unexpected error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        ConnectionDiagnosticReport.add_issue(TCPConnectionNotification.fail_issue())
        error_log.error(traceback.format_exc())
        ConnectionDiagnosticReport.add_warning(
            ConnectionTimeoutNotification.unexpected_error(print_trace=True).format(e))


def diagnose_connection_network_unreachable(local_client: Client, redis_instance: RedisInstance):
    # 1. Wrong connection address, but resolved by dns
    # 2. The server is not listening on the port
    try:
        redis_instance.diagnose_connection_info(local_client)
        # Connection info is correct or did not diagnose connection info
        ConnectionDiagnosticReport.add_issue(TCPConnectionNotification.fail_issue())
    except DiagnosisError:
        pass
    except Exception as e:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="unexpected error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        ConnectionDiagnosticReport.add_issue(TCPConnectionNotification.fail_issue())
        error_log.error(traceback.format_exc())
        ConnectionDiagnosticReport.add_warning(
            NetworkUnreachableNotification.unexpected_error(print_trace=True).format(e))


def diagnose_authentication_timeout(local_client: Client, redis_instance: RedisInstance):
    # 1. Maybe successfully establish a tcp connection, but fail to execute command for whitelist
    # 2. Redis server is busy
    try:
        redis_instance.diagnose_whitelist(local_client)
        ConnectionDiagnosticReport.add_issue(AuthenticationNotification.fail_issue())
    except DiagnosisError:
        pass
    except Exception as e:
        logger.error(ProcessReport.get_arrow_line(yes=False, message="unexpected error"))
        logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
        error_log.error(traceback.format_exc())
        ConnectionDiagnosticReport.add_warning(
            AuthenticationNotification.timeout_diagnosis_error(print_trace=True).format(e))
        ConnectionDiagnosticReport.add_issue(AuthenticationNotification.fail_issue())


if __name__ == "__main__":
    start_diagnose()
