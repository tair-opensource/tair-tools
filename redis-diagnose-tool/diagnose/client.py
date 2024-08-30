from typing import List, Tuple, Optional

from diagnose import utils
from diagnose.ecs import ECS
from diagnose.logger_config import logger
from diagnose.exceptions import NameserverError, EcsSecurityGroupError, ConnectInfoError, InternalError
from diagnose.diagnostic_report import ConnectionDiagnosticReport, ProcessReport, ClientInfo, Check
from diagnose.notification_template import (
    NotificationTemplate,
    ClientNotification,
    ConnectionInfoNotification,
    DNSResolutionNotification,
    ConnectionInterceptionNotification,
)


class Client:
    def __init__(
            self,
            connection_address: str,
            connection_port: int,
            ecs_instance_id: str = None,
            advanced_mode: bool = False,
    ):
        self._connection_port = connection_port
        self._connection_address = connection_address
        self._system_type = None
        self._private_ips = []
        self._public_ips = []
        self._advanced_mode = advanced_mode

        # Get ecs info
        self._ecs = ECS(ecs_instance_id) if (ecs_instance_id is not None and advanced_mode) else None

        # Resolve connection address
        self._connect_ip = utils.resolve_host(connection_address)

        self.get_client_detail()

    @property
    def connection_port(self) -> int:
        return self._connection_port

    @property
    def connection_address(self) -> str:
        return self._connection_address

    @property
    def private_ips(self) -> List[str]:
        return self._private_ips

    @property
    def public_ips(self) -> List[str]:
        return self._public_ips

    @property
    def ecs(self) -> ECS:
        return self._ecs

    @property
    def connect_ip(self) -> str:
        return self._connect_ip

    def get_client_detail(self):
        logger.info(ProcessReport.get_arrow_line(yes=True))
        logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
        logger.info(ProcessReport.gen_process_rectangle(ClientNotification.client_detail_log()))

        # Get system info
        system_type, system_detail = utils.get_system_info()
        self._system_type = system_type

        # Get public ip
        get_public_ip_times = 3
        for _ in range(get_public_ip_times):
            public_ip = utils.get_public_ip_address()
            if public_ip is not None:
                self._public_ips.append(public_ip)
        self._public_ips = list(set(self._public_ips))

        # Get private ip
        self._private_ips = list(map(lambda interface: interface["ip_address"], utils.get_ipv4_interfaces()))

        if self.ecs is not None:
            self._private_ips = self.ecs.private_ips
            self._public_ips = self.ecs.public_ips

        ConnectionDiagnosticReport.set_client_info(ClientInfo(system_detail, self.public_ips, self.private_ips))

        # check public ip and private ip
        if len(self.public_ips) > 1:
            ConnectionDiagnosticReport.add_warning(ClientNotification.multiple_public_ips_warning())
        if len(self._private_ips) > 1:
            ConnectionDiagnosticReport.add_warning(ClientNotification.multiple_private_ips_warning())

    @staticmethod
    def auth(client_socket, user: Optional[str], password: Optional[str]) -> Tuple[bool, str]:
        if password is None:  # password-free
            command = "*1\r\n$4\r\nPING\r\n"
        elif user is not None:
            command = f"*3\r\n$4\r\nAUTH\r\n${len(user)}\r\n{user}\r\n${len(password)}\r\n{password}\r\n"
        else:
            command = f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n"

        client_socket.sendall(command.encode("utf-8"))
        response = client_socket.recv(1024).decode("utf-8")
        if "invalid password" in response:
            return False, "Invalid Password"
        if "NOAUTH" in response:
            return False, "No Authentication"
        if "invalid username-password pair" in response:
            return False, "Invalid Username-password Pair"
        return (response in ["+OK\r\n", "+PONG\r\n"]), response[:-2] if response.endswith("\r\n") else response

    def diagnose_ecs_security_group(
            self,
            direction: str,
            protocol: str,
            target_ip: str,
            target_port: int = None,
    ):
        if direction not in ["in", "out"]:
            raise InternalError(f"unknown ecs security group direction {direction}, expected 'in' or 'out'")
        if protocol not in ["TCP", "UDP", "ICMP", "GRE"]:
            raise InternalError(f"unknown ecs security group protocol {protocol}, "
                                f"expected one of ['TCP', 'UDP', 'ICMP', 'GRE']")
        self._ecs.diagnose_security_group("ingress" if direction == "in" else "egress", protocol, target_ip,
                                          target_port)

    def diagnose_dns(self, redis_connection_address: List[str]):
        ConnectionDiagnosticReport.add_check(Check(DNSResolutionNotification.check_name()))
        dns_resolution_check = ConnectionDiagnosticReport.get_last_check()
        dns_resolution_check_detail = DNSResolutionNotification.check_fail_detail()
        dns_resolution_issue = dns_resolution_check_detail

        # Check connection address
        if self._advanced_mode and len(redis_connection_address) != 0:
            logger.info(ProcessReport.gen_process_rectangle(DNSResolutionNotification.check_connection_address_log()))
            comma = "，" if NotificationTemplate.language == "zh" else ", "
            dns_resolution_check_detail += comma
            if self.connection_address not in redis_connection_address:
                logger.error(ProcessReport.get_arrow_line(yes=False))
                logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
                dns_resolution_check_detail += ConnectionInfoNotification.wrong_connection_address_detail().format(
                    ",".join(redis_connection_address), self.connection_address)
                dns_resolution_check.fail()
                dns_resolution_check.set_detail(dns_resolution_check_detail)
                ConnectionDiagnosticReport.add_issue(dns_resolution_issue)
                raise ConnectInfoError("address", self.connection_address, self.connection_port)
            else:
                logger.info(ProcessReport.get_arrow_line(yes=True))
                logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
                dns_resolution_check_detail += DNSResolutionNotification.check_connection_address_success_detail()

        # Retry
        resolved_ip = utils.resolve_host(self.connection_address)
        if resolved_ip is not None:
            logger.info(ProcessReport.gen_process_rectangle(DNSResolutionNotification.retry_resolving_log()))
            logger.info(ProcessReport.get_arrow_line(yes=True))
            logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
            self._connect_ip = resolved_ip
            dns_resolution_check.success()
            dns_resolution_check.set_detail(DNSResolutionNotification.check_success_detail())
            return

        # Set check info and add issue
        ConnectionDiagnosticReport.add_issue(dns_resolution_issue)
        dns_resolution_check.fail()

        # Check nameserver configuration
        if self._system_type not in ["Linux", "MacOS"]:
            ConnectionDiagnosticReport.add_warning(DNSResolutionNotification.no_exception_warning())
            return
        logger.info(ProcessReport.gen_process_rectangle(DNSResolutionNotification.check_nameserver_log()))
        nameservers = utils.read_resolve_config()
        nameservers = list(filter(lambda ip: utils.get_ip_address_type(ip) == "IPv4", nameservers))
        nameservers = list(set(nameservers))
        if len(nameservers) == 0:
            logger.error(ProcessReport.get_arrow_line(yes=False))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            dns_resolution_check_detail += DNSResolutionNotification.check_nameserver_fail_detail()
            dns_resolution_check.set_detail(dns_resolution_check_detail)
            raise NameserverError
        else:
            logger.info(ProcessReport.get_arrow_line(yes=True))
            logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
            dns_resolution_check_detail += DNSResolutionNotification.check_nameserver_success_detail().format(
                nameservers)
            dns_resolution_check.set_detail(dns_resolution_check_detail)
        ConnectionDiagnosticReport.add_warning(DNSResolutionNotification.no_exception_warning())

    def diagnose_connection_interception(self):
        if not self._advanced_mode or self._ecs is None:
            ConnectionDiagnosticReport.add_warning(ConnectionInterceptionNotification.not_check_warning())
            return

        logger.info(
            ProcessReport.gen_process_rectangle(ConnectionInterceptionNotification.check_ecs_security_group_log()))
        ConnectionDiagnosticReport.add_check(Check(ConnectionInterceptionNotification.check_name()))
        connection_interception_check = ConnectionDiagnosticReport.get_last_check()

        # Retry
        if utils.can_establish_tcp_connection(self.connection_address, self.connection_port):
            logger.info(ProcessReport.get_arrow_line(yes=True))
            logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
            connection_interception_check.success()
            connection_interception_check.set_detail(ConnectionInterceptionNotification.check_success_detail())
            return

        # Check ecs security group
        try:
            self.diagnose_ecs_security_group("out", "TCP", self.connect_ip, self.connection_port)
        except EcsSecurityGroupError as e:
            ConnectionDiagnosticReport.add_issue(ConnectionInterceptionNotification.
                                                 ecs_security_group_interception_issue())
            logger.error(ProcessReport.get_arrow_line(yes=False))
            logger.error(ProcessReport.step_indentation + ProcessReport.arrow_head)
            connection_interception_check.fail()
            connection_interception_check.set_detail(ConnectionInterceptionNotification.
                                                     ecs_security_group_interception_detail().format(e.protocol,
                                                                                                     e.ip, e.port, e))
            raise e

        logger.info(ProcessReport.get_arrow_line(yes=True))
        logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
        connection_interception_check.success()
        connection_interception_check.set_detail(ConnectionInterceptionNotification.ecs_security_group_passed_detail())
