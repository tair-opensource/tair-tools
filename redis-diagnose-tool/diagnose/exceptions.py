from typing import Optional
from diagnose.notification_template import ErrorNotification


class InternalError(Exception):
    def __init__(self, message: str):
        super().__init__(ErrorNotification.internal_error().format(message))


class SDKError(Exception):
    pass


class DiagnosisError(Exception):
    pass


class InstanceError(DiagnosisError):
    pass


class ServerError(DiagnosisError):
    pass


class ConfigurationError(DiagnosisError):
    pass


class ConnectInfoError(ConfigurationError):
    # 用户连接信息错误
    def __init__(self, type: str, host: str, port: int):
        self.type = type
        self.host = host
        self.port = port
        super().__init__(ErrorNotification.connection_info_error().format(type, host, port))


class AuthError(ConfigurationError):
    def __init__(self, user: str, password):
        super().__init__(ErrorNotification.auth_error().format(user, password))


class WhiteListError(ConfigurationError):
    def __init__(self, ip: str):
        super().__init__(ErrorNotification.whitelist_error().format(ip))


class EnvironError(DiagnosisError):
    pass


class SystemTypeError(EnvironError):
    def __init__(self, system: str):
        super().__init__(ErrorNotification.system_type_error().format(system))


class NetworkError(EnvironError):
    pass


class NameLookupError(NetworkError):
    def __init__(self, hostname: str):
        super().__init__(ErrorNotification.name_lookup_error().format(hostname))


class NameserverError(NetworkError):
    def __init__(self, message: str = None):
        if message is None:
            message = ErrorNotification.name_server_error()
        super().__init__(message)


class EcsSecurityGroupError(NetworkError):
    def __init__(
        self,
        direction: str,
        ip: str, protocol: str,
        port: Optional[int] = None,
        security_group_rule: Optional[str] = None
    ):
        self.security_group_rule = security_group_rule
        self.direction = direction
        self.ip = ip
        self.protocol = protocol
        self.port = port
        if self.security_group_rule is not None:
            message = repr(self.security_group_rule)
        else:
            message = ErrorNotification.ecs_security_group_default_policy_interception_error()

        super().__init__(message)