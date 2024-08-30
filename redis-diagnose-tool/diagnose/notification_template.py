class NotificationTemplate:
    language = "zh"
    check_error_trace_hint_zh = "，请在 error.log 日志中查看具体的异常链路"
    check_error_trace_hint_en = ", please check the error.log for the exception trace"

    @classmethod
    def set_language(cls, language: str):
        cls.language = language


class InitializationNotification(NotificationTemplate):
    @classmethod
    def advanced_check_name(cls):
        if cls.language == "zh":
            return "高级模式初始化"
        return "Advanced mode initialization"

    @classmethod
    def basic_check_name(cls):
        if cls.language == "zh":
            return "基础模式初始化"
        return "Basic mode initialization"

    @classmethod
    def init_sdk_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "客户端或 Redis 实例初始化失败，发生 SDK 错误"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Initialize client or Redis instance failed, SDK error occurred"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def init_internal_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "客户端或 Redis 实例初始化失败，发生内部错误"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Initialize client or Redis instance failed, internal error occurred"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def init_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "客户端或 Redis 实例初始化失败，发生未知错误"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Initialize client or Redis instance failed, unexpected error occurred"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def init_fail_log_in_advanced_mode(cls) -> str:
        if cls.language == "zh":
            return ("高级模式下初始化失败，可能的原因："
                    "a. 本地防火墙或 ecs 安全组拦截 http/https 请求，导致 open api 调用失败以及无法获取公网 ip；"
                    "b. DNS nameserver 未配置 或 nameserver 的 DNS 连接被拦截，导致无法解析域名；"
                    "c. sdk 配置错误，如 access key id、 access secret advanced、地域 id 或服务接入点错误、实例 id；"
                    "d. 网络抖动， 请重新运行")
        return ("Initialization failed in advanced mode, possible reasons: "
                "a. Local firewall or ecs security group intercept, causing open api calls to fail"
                " and unable to obtain public ip; "
                "b. DNS nameserver not configured or nameserver's DNS connection intercepted, unable to resolve"
                " domain name; "
                "c. SDK configuration error, such as access key id, access key secret, region id or service "
                "endpoint, instance id; "
                "d. Network jitter, please retry;")

    @classmethod
    def init_fail_log_in_basic_mode(cls) -> str:
        if cls.language == "zh":
            return "基础模式下初始化失败"
        return "Initialization failed in advanced mode"


# get arguments and validation
class ArgumentsNotification(NotificationTemplate):
    @classmethod
    def error_args_hint(cls) -> str:
        if cls.language == "zh":
            return "提示: 请使用 --help 获取参数及用法"
        return "Hint: Please use --help to get arguments and usage"

    @classmethod
    def get_args_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "获取参数失败，错误: {}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Failed to get arguments, Error: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def config_file_not_exist_error(cls) -> str:
        if cls.language == "zh":
            return "配置文件不存在，请检查配置文件路径是否正确"
        return "Config file not exist, please check the config file path"

    @classmethod
    def config_file_extension_error(cls) -> str:
        if cls.language == "zh":
            return "配置文件后缀错误，必须为 yaml"
        return "Config file extension error, must be yaml"

    @classmethod
    def config_file_value_type_error(cls, key: str, val_type: str) -> str:
        if cls.language == "zh":
            return f"配置文件中的`{key}`字段必须为 {val_type}"
        return f"`{key}` from config file must be {val_type}"

    @classmethod
    def connection_address_empty_error(cls) -> str:
        if cls.language == "zh":
            return "连接地址不能为空"
        return "Connection address cannot be empty"

    @classmethod
    def language_error(cls) -> str:
        if cls.language == "zh":
            return "语言仅支持zh（中文）和en（英文）"
        return "Language only support zh for Chinese and en for English"

    @classmethod
    def connection_port_error(cls) -> str:
        if cls.language == "zh":
            return "无效的连接端口，端口必须为1-65535之间的整数"
        return "Invalid connection port, port must be between 1 and 65535"

    @classmethod
    def connection_timeout_error(cls) -> str:
        if cls.language == "zh":
            return "无效的连接超时时间，超时时间必须为正数"
        return "Invalid connection timeout, timeout must be positive"

    @classmethod
    def redis_instance_id_warning(cls) -> str:
        if cls.language == "zh":
            return "指定了 Redis 实例 ID，但禁用了高级模式，以基础模式运行"
        return "Redis instance id is specified but advanced mode disabled, running in basic mode"

    @classmethod
    def redis_instance_id_empty_error(cls) -> str:
        if cls.language == "zh":
            return "启用高级模式时，Redis 实例 ID 不能为空"
        return "Redis instance id can not be empty when advanced mode enabled"

    @classmethod
    def ak_sk_warning(cls) -> str:
        if cls.language == "zh":
            return "指定了 Access Key ID 或 Access Key Secret，但禁用了高级模式，以基础模式运行"
        return "Access Key ID or Access Key Secret is specified but advanced mode disabled, running in basic mode"

    @classmethod
    def ak_sk_empty_error(cls) -> str:
        if cls.language == "zh":
            return "启用高级模式时，Access Key ID 和 Access Key Secret 都不能为空"
        return "Neither Access Key ID nor Access Key Secret can be empty when advanced mode enabled"

    @classmethod
    def region_id_endpoint_warning(cls) -> str:
        if cls.language == "zh":
            return "指定了 Redis 地域ID 或服务接入点，但禁用了高级模式，以基础模式运行"
        return "Redis region id or Redis endpoint is specified but advanced mode disabled, running in basic mode"

    @classmethod
    def region_id_endpoint_empty_error(cls) -> str:
        if cls.language == "zh":
            return "启用高级模式时，Redis 地域ID 和服务接入点不能都为空"
        return "Redis region id and Redis endpoint can not be both empty when advanced mode enabled"

    @classmethod
    def ecs_region_id_endpoint_empty_error(cls) -> str:
        if cls.language == "zh":
            return "启用高级模式时，ECS 地域ID 和服务接入点不能都为空"
        return "ECS region id and ECS endpoint can not be both empty when advanced mode enabled"


class ECSNotification(NotificationTemplate):
    @classmethod
    def ecs_info_log(cls) -> str:
        if cls.language == "zh":
            return "获取 ECS 实例信息"
        return "Get ECS instance info"

    @classmethod
    def multiple_ecs_security_group_waning(cls) -> str:
        if cls.language == "zh":
            return "找到多个安全组，使用第一个，安全组ID：{}，地域ID：{}"
        return "Multiple security groups found, use the first one, security group id: {}, region id: {}"

    @classmethod
    def ecs_security_group_not_fount_error(cls) -> str:
        if cls.language == "zh":
            return "安全组未找到，安全组ID：{}，地域ID：{}"
        return "Security group not found, security group id: {}, region id: {}"

    @classmethod
    def ecs_security_group_port_check_error(cls) -> str:
        if cls.language == "zh":
            return "tcp 协议和 udp 协议必须指定端口"
        return "Port must be specified for tcp and udp protocol"

    @classmethod
    def ecs_security_group_src_port_no_validation_warning(cls) -> str:
        if cls.language == "zh":
            return "[诊断 ECS 安全组] 安全组规则指定了源端口但未验证，安全组规则信息：{}。"
        return "[Diagnose ECS Security Group] Source port is given but not validated, security group rule info: {}."


# get client detail
class ClientNotification(NotificationTemplate):
    @classmethod
    def client_detail_log(cls) -> str:
        if cls.language == "zh":
            return "获取系统和网络信息"
        return "Get system and network info"

    @classmethod
    def multiple_public_ips_warning(cls) -> str:
        if cls.language == "zh":
            return "找到多个客户端公网 IP，如果通过公网连接地址连接实例，建议在白名单中添加公网 IP 的 CIDR 地址。"
        return ("Found multiple client public ips, if connecting to Redis instance using a public connection address, "
                "it is recommended to add the cidr address in the whitelist.")

    @classmethod
    def multiple_private_ips_warning(cls) -> str:
        if cls.language == "zh":
            return "找到多个客户端私网 IP，如果通过内网连接地址连接实例，建议在白名单中添加所有私网 IP。"
        return ("Found multiple client private ips, if connecting to Redis instance using a private connection "
                "address, it is recommended to add all the private ips in the whitelist.")


class RedisInstanceNotification(NotificationTemplate):
    @classmethod
    def redis_instance_info_log(cls) -> str:
        if cls.language == "zh":
            return "获取Redis实例信息"
        return "Get Redis instance info"

    @classmethod
    def classic_network_not_support_warning(cls) -> str:
        if cls.language == "zh":
            return "该工具不支持经典网络的redis 实例，请使用 VPC 网络创建实例。"
        return "The tool does not support Redis instance of the classic network."


class TCPConnectionNotification(NotificationTemplate):
    @classmethod
    def check_name(cls) -> str:
        if cls.language == "zh":
            return "检查客户端和 Redis 实例建立 TCP 连接"
        return "Check the TCP connection establishment between the client and the Redis instance"

    @classmethod
    def check_success_detail(cls) -> str:
        if cls.language == "zh":
            return "成功建立 TCP 连接"
        return "Successfully establish a TCP connection"

    @classmethod
    def fail_no_exception_detail(cls) -> str:
        if cls.language == "zh":
            return "TCP 连接建立失败：未捕获到任何异常"
        return "Fail to establish a TCP connection: No exception was caught"

    @classmethod
    def no_exception_issue(cls) -> str:
        if cls.language == "zh":
            return "客户端和 Redis 实例的 TCP 连接建立失败：未发现明确的问题"
        return ("Fail to establish a TCP connection between the client and the Redis instance: No definite issue "
                "was found")

    @classmethod
    def connection_refused_detail(cls) -> str:
        if cls.language == "zh":
            return "TCP 连接建立失败：连接被拒绝, 连接可能被本地防火墙拦截"
        return ("Fail to establish a TCP connection: Connection refused, maybe the connection is intercepted by the"
                "local firewall")

    @classmethod
    def connection_timeout_detail(cls) -> str:
        if cls.language == "zh":
            return "TCP 连接建立失败：连接超时"
        return "Fail to establish a TCP connection: Connection timeout"

    @classmethod
    def network_unreachable_detail(cls):
        if cls.language == "zh":
            return "TCP 连接建立失败：网络不可达，可能连接地址错误但被 DNS 解析，或者服务器未监听端口"
        return ("Fail to establish a TCP connection: Network unreachable, maybe connection address is wrong but "
                "resolved by dns, or the server is not listening on the port")

    @classmethod
    def domain_name_resolution_fail_detail(cls) -> str:
        if cls.language == "zh":
            return "TCP 连接建立失败：DNS 域名解析失败"
        return "Fail to establish a TCP connection: DNS domain name resolution failed"

    @classmethod
    def socket_error_detail(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "TCP 连接建立失败：Socket 错误: {}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Fail to establish a TCP connection, Socket error: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def error_detail(cls, print_trace: bool) -> str:
        if cls.language == "zh":
            description = "TCP 连接建立失败：错误: {}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Fail to establish a TCP connection, Error: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def fail_issue(cls) -> str:
        if cls.language == "zh":
            return "客户端和 Redis 实例 TCP 连接建立失败"
        return "Fail to establish a TCP connection between the client and the Redis instance"

    @classmethod
    def fail_warning(cls):
        if cls.language == "zh":
            return "TCP 连接建立失败，跳过 Redis server 探查"
        return "Fail to establish a TCP connection, skip Redis server detection"


class NetworkUnreachableNotification(NotificationTemplate):
    @classmethod
    def unexpected_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "网络不可达诊断失败，未知错误：{}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Network unreachable diagnosis failed, unexpected error: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description


class DNSResolutionNotification(NotificationTemplate):
    @classmethod
    def check_name(cls) -> str:
        if cls.language == "zh":
            return "检查连接地址的 DNS 解析"
        return "Check DNS resolution of the connection address"

    @classmethod
    def check_success_detail(cls) -> str:
        if cls.language == "zh":
            return "连接地址被成功解析，无需再诊断，之前连接地址解析失败可能由网络抖动造成"
        return ("Connection address is successfully resolved, no need to diagnose. Previous error might have been "
                "caused by network jitter.")

    @classmethod
    def check_fail_detail(cls) -> str:
        if cls.language == "zh":
            return "连接地址的域名解析失败"
        return "Connection address domain name resolution failed"

    @classmethod
    def check_connection_address_log(cls) -> str:
        if cls.language == "zh":
            return "检查连接地址"
        return "Check connection address"

    @classmethod
    def retry_resolving_log(cls) -> str:
        if cls.language == "zh":
            return "重试解析连接地址"
        return "Retry resolving the connection address"

    @classmethod
    def check_connection_address_success_detail(cls) -> str:
        if cls.language == "zh":
            return "连接地址正确"
        return "correct connection address"

    @classmethod
    def check_nameserver_log(cls) -> str:
        if cls.language == "zh":
            return "检查nameserver配置"
        return "Check nameserver configuration"

    @classmethod
    def check_nameserver_fail_detail(cls) -> str:
        if cls.language == "zh":
            return "，/etc/resolv.conf中未配置 DNS nameserver"
        return ", DNS nameserver is not configured in /etc/resolv.conf"

    @classmethod
    def check_nameserver_success_detail(cls) -> str:
        if cls.language == "zh":
            return "，配置的 DNS nameservers ：{}"
        return ", configured DNS nameservers: {}"

    @classmethod
    def no_exception_warning(cls) -> str:
        if cls.language == "zh":
            return ("连接地址的域名解析失败，请检查连接地址是否正确，以及本地防火墙是否拦截了DNS连接。如果客户端在ECS上，请检查ECS安全组是"
                    "否拦截了 DNS 连接。")
        return ("The domain name resolution of the connection address failed. Please check whether the connection"
                " address is correct and whether the local firewall is intercepting the DNS connection. If your client"
                " is on ECS, please check whether the ECS security group is intercepting the DNS connection.")

    @classmethod
    def unexpected_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "DNS 域名解析诊断失败，未知错误：{}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "DNS domain name resolution diagnosis failed, unexpected error: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description


class ConnectionTimeoutNotification(NotificationTemplate):
    @classmethod
    def internal_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "连接超时诊断失败，内部错误：{}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Connection timeout diagnosis failed, Internal error: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def unexpected_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "连接超时诊断失败，未知错误：{}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Connection timeout diagnosis failed, unexpected error: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description


class ConnectionInterceptionNotification(NotificationTemplate):
    @classmethod
    def check_name(cls) -> str:
        if cls.language == "zh":
            return "检查 Redis 的 TCP 连接是否被 ECS 安全组拦截"
        return "Check whether the Redis TCP connection is intercepted by ECS security group"

    @classmethod
    def check_success_detail(cls) -> str:
        if cls.language == "zh":
            return "客户端和 Redis 实例成功建立 TCP 连接，无需再诊断，之前 TCP 连接建立失败可能由网络抖动造成。"
        return ("Successfully establish a TCP connection between the client and the Redis instance, no need to "
                "diagnose. Previous error might have been caused by network jitter.")

    @classmethod
    def check_ecs_security_group_log(cls) -> str:
        if cls.language == "zh":
            return "检查 ECS 安全组"
        return "Check ECS security group"

    @classmethod
    def ecs_security_group_interception_issue(cls) -> str:
        if cls.language == "zh":
            return "Redis 的 TCP 连接被 ECS 安全组拦截"
        return "Redis TCP connection is intercepted by ECS security group"

    @classmethod
    def ecs_security_group_interception_detail(cls) -> str:
        if cls.language == "zh":
            return "Redis 的 TCP 连接被 ECS 安全组拦截，协议：{}，连接 ip：{}，连接端口：{}，拦截规则：{}"
        return ("Redis TCP connection is intercepted by ECS security group, protocol: {}, connection ip: {}, "
                "connection port {}, interception rule: {}")

    @classmethod
    def ecs_security_group_passed_detail(cls) -> str:
        if cls.language == "zh":
            return "Redis 的 TCP 连接未被 ECS 安全组拦截，请检查本地防火墙是否拦截"
        return ("Redis TCP connection is not intercepted by ECS security group, please check whether the local firewall"
                " is intercepting the Redis TCP connection")

    @classmethod
    def not_check_warning(cls):
        if cls.language == "zh":
            return "未检查 ECS 安全组。如果客户端在ECS上，请检查 Redis 的 tcp 连接是否被 ECS 安全组拦截，或尝试高级模式并指定ECS实例ID。"
        return ("The ECS security group is not checked. If your client is on ECS, please check whether the Redis tcp "
                "connection is intercepted by ECS security group or try advanced mode with ECS instance id.")


class ConnectionInfoNotification(NotificationTemplate):
    @classmethod
    def diagnose_log(cls) -> str:
        if cls.language == "zh":
            return "检查连接地址和端口"
        return "Check connection address and port"

    @classmethod
    def check_name(cls) -> str:
        if cls.language == "zh":
            return "检查 Redis 实例的连接地址和端口"
        return "Check Redis instance connection address and port"

    @classmethod
    def intranet_access_issue(cls) -> str:
        if cls.language == "zh":
            return "内网连接地址不可达，只有和 Redis 实例同 VPC 的客户端才能通过内网地址连接。请使用公网连接地址"
        return ("Private connection address is forbidden, access is only allowed through the same VPC as the "
                "Redis instance. Please connect via public connection address")

    @classmethod
    def intranet_access_detail(cls) -> str:
        if cls.language == "zh":
            return "客户端和 Redis 实例的 VPC 不同，无法通过内网地址访问"
        return ("The client and Redis instances are not in the same vpc, instance cannot be accessed through "
                "the intranet")

    @classmethod
    def wrong_connection_port_issue(cls) -> str:
        if cls.language == "zh":
            return "连接端口错误"
        return "Wrong connection port"

    @classmethod
    def wrong_connection_port_detail(cls) -> str:
        if cls.language == "zh":
            return "连接端口错误， 期望端口 {}， 实际使用的端口 {}"
        return "Wrong connection port, expected {}, but got {}"

    @classmethod
    def wrong_connection_ip_issue(cls) -> str:
        if cls.language == "zh":
            return "连接 ip 错误，可能是 DNS 域名解析错误"
        return "Wrong connection ip, maybe DNS domain name resolution error"

    @classmethod
    def wrong_connection_ip_detail(cls) -> str:
        if cls.language == "zh":
            return "连接 ip 错误，期望 ip {}，实际 ip {}，可能是 DNS 域名解析错误"
        return "Wrong connection ip, expected {}, but got {}, maybe DNS domain name resolution error"

    @classmethod
    def wrong_connection_address_issue(cls) -> str:
        if cls.language == "zh":
            return "连接地址错误"
        return "Wrong connection address"

    @classmethod
    def wrong_connection_address_detail(cls) -> str:
        if cls.language == "zh":
            return "连接地址错误，期望地址 {}，实际地址 {}"
        return "Wrong connection address, expected one of {}, but got {}"

    @classmethod
    def success_detail(cls) -> str:
        if cls.language == "zh":
            return "连接地址和端口都正确"
        return "Connection address and port are correct"

    @classmethod
    def not_check_warning(cls) -> str:
        if cls.language == "zh":
            return "基础模式下未检查连接信息。请检查连接地址和端口是否正确，或开启高级模式自动检查。"
        return ("The connection information is not checked in the basic mode. Please check whether the connection "
                "address and port are correct or enable the advanced mode.")


class WhitelistNotification(NotificationTemplate):
    @classmethod
    def diagnose_log(cls) -> str:
        if cls.language == "zh":
            return "检查白名单"
        return "Check whitelist"

    @classmethod
    def check_name(cls) -> str:
        if cls.language == "zh":
            return "检查 Redis 实例的白名单"
        return "Check Redis instance whitelist"

    @classmethod
    def same_security_group_success_detail(cls) -> str:
        if cls.language == "zh":
            return "通过内网地址连接 Redis 实例，Redis 实例配置了和ECS相同的安全组"
        return ("Connect Redis instance via private connection address, Redis instance is configured with the same "
                "security group as the ecs")

    @classmethod
    def private_ip_success_detail(cls, part: bool) -> str:
        if cls.language == "zh":
            if part:
                return "通过内网地址连接 Redis 实例，只有部分客户端私网 IP（{}）在白名单中"
            else:
                return "通过内网地址连接 Redis 实例，所有客户端私网 IP（{}）都在白名单中"
        if part:
            return ("Connect Redis instance via private connection address, only some client private ips({}) are in "
                    "the whitelist")
        else:
            return "Connect Redis instance via private connection address, all client private ips({}) are in the whitelist"

    @classmethod
    def private_ip_fail_detail(cls) -> str:
        if cls.language == "zh":
            return "通过内网地址连接 Redis 实例，所有客户端私网 IP（{}）均不在白名单中"
        return "Connect Redis instance via private address, all client private ips({}) are not in the whitelist"

    @classmethod
    def public_ip_success_detail(cls, part: bool) -> str:
        if cls.language == "zh":
            if part:
                return "通过公网地址连接 Redis 实例，只有部分客户端公网 IP（{}）在白名单中"
            else:
                return "通过公网地址连接 Redis 实例, 所有客户端公网 IP（{}）在白名单中"
        if part:
            return ("Connect Redis instance via public connection address, only some client public ips ({}) are in "
                    "the whitelist")
        else:
            return "Connect Redis instance via public connection address, all client public ips({}) are in the whitelist"

    @classmethod
    def public_ip_fail_detail(cls) -> str:
        if cls.language == "zh":
            return "通过公网地址连接 Redis 实例，所有客户端公网 IP ({}) 均不在白名单中"
        return "Connect Redis instance via public connection address, all client public ips ({}) are not in the whitelist"

    @classmethod
    def fail_issue(cls) -> str:
        if cls.language == "zh":
            return "未正确配置白名单"
        return "Whitelist is not configured correctly"

    @classmethod
    def not_check_warning(cls) -> str:
        if cls.language == "zh":
            return "基础模式下未检查实例的白名单。请检查白名单是否正确配置，或开启高级模式自动检查。"
        return ("The instance whitelist is not checked in basic mode. Please check whether the whitelist is "
                "configured correctly or enable advanced mode.")


class InstanceStatusNotification(NotificationTemplate):
    @classmethod
    def diagnose_log(cls) -> str:
        if cls.language == "zh":
            return "检查实例状态"
        return "Check instance status"

    @classmethod
    def check_name(cls) -> str:
        if cls.language == "zh":
            return "检查 Redis 实例状态"
        return "Check Redis instance status"

    @classmethod
    def fail_detail(cls) -> str:
        if cls.language == "zh":
            return "Redis 实例状态为 {}，无法建立 tcp 连接"
        return "Redis instance status is {}, unable to accept tcp connection"

    @classmethod
    def success_detail(cls) -> str:
        if cls.language == "zh":
            return "Redis 实例状态为 {}，能够建立 tcp 连接"
        return "Redis instance status is {}, able to to accept tcp connection"

    @classmethod
    def not_check_warning(cls) -> str:
        if cls.language == "zh":
            return "基础模式下未检查实例的状态。请检查是否由实例状态导致连接超时，或开启高级模式自动检查。"
        return ("The instance status is not checked in basic mode. Please check whether the instance status "
                "causes the connection timeout or enable advanced mode.")


class AuthenticationNotification(NotificationTemplate):
    @classmethod
    def check_name(cls) -> str:
        if cls.language == "zh":
            return "验证密码"
        return "Check password authentication"

    @classmethod
    def success_detail(cls) -> str:
        if cls.language == "zh":
            return "密码验证成功"
        return "Successful password authentication"

    @classmethod
    def fail_detail(cls) -> str:
        if cls.language == "zh":
            return "密码验证失败，响应结果：{}"
        return "Authentication failed, response: {}"

    @classmethod
    def fail_issue(cls) -> str:
        if cls.language == "zh":
            return "密码验证失败"
        return "Authentication failed"

    @classmethod
    def timeout_detail(cls) -> str:
        if cls.language == "zh":
            return "密码验证超时, 可能未正确配置白名单或服务器响应超时"
        return "Authentication timeout, the whitelist may not be configured correctly, or the server response timed out"

    @classmethod
    def timeout_diagnosis_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "诊断密码验证超时问题发生错误: {}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Error occurred when diagnosing password authentication timeout: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def invalid_password_detail(cls) -> str:
        if cls.language == "zh":
            return "密码错误，用户名: {}, 密码: {}"
        return "Invalid password, username: {}, password: {}"

    @classmethod
    def invalid_password_issue(cls) -> str:
        if cls.language == "zh":
            return "密码验证失败：密码错误"
        return "Authentication failed, wrong password"

    @classmethod
    def no_auth_detail(cls) -> str:
        if cls.language == "zh":
            return "缺少认证信息，需要指定密码"
        return "No authentication, password should be specified!"

    @classmethod
    def no_auth_issue(cls) -> str:
        if cls.language == "zh":
            return "密码验证失败：缺少认证信息"
        return "Authentication failed, no authentication"

    @classmethod
    def invalid_username_password_pair_detail(cls):
        if cls.language == "zh":
            return "无效的用户名密码对，用户名错误或密码错误"
        return "Invalid username-password pair, wrong username or wrong password"

    @classmethod
    def invalid_username_password_pair_issue(cls):
        if cls.language == "zh":
            return "密码验证失败：无效的用户名密码对"
        return "Authentication failed, invalid username-password pair"

    @classmethod
    def socket_error_detail(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "密码验证失败, Socket错误: {}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Authentication failed, Socket error： {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def unexpected_error(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "密码验证失败,  未知错误: {}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Authentication failed, unexpected error: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def fail_warning(cls) -> str:
        if cls.language == "zh":
            return "密码验证失败，跳过 Redis server 探查"
        return "Password authentication failed, skip Redis server detection"


class ServerDetectionNotification(NotificationTemplate):
    @classmethod
    def fail_log(cls, print_trace: bool = False) -> str:
        if cls.language == "zh":
            description = "Redis server 探查失败, 错误: {}"
            if print_trace:
                description += cls.check_error_trace_hint_zh
        else:
            description = "Redis server detection failed, error: {}"
            if print_trace:
                description += cls.check_error_trace_hint_en
        return description

    @classmethod
    def info_error(cls) -> str:
        if cls.language == "zh":
            return "info命令执行失败，未获取到 Redis server 的信息，错误: {}。重试中 ..."
        return "Fail to get Redis server info by executing info command, error: {}. Retrying ..."

    @classmethod
    def info_reached_max_retry_times(cls) -> str:
        if cls.language == "zh":
            return "无法通过 info 命令获取 Redis server 的信息，已达到最大重试次数 10"
        return "Fail to get Redis server info by executing info command, reaching maximum retry count 10"

    @classmethod
    def rw_split_node_error(cls) -> str:
        if cls.language == "zh":
            return "读写分离架构的总节点数不大于1"
        return "Total node count is not greater than 1 for read/write split architecture"

    @classmethod
    def direct_cluster_node_error(cls) -> str:
        if cls.language == "zh":
            return "直连模式的集群架构总节点数为 0"
        return "Total node count is 0 for direct cluster architecture"

    @classmethod
    def proxy_cluster_node_error(cls) -> str:
        if cls.language == "zh":
            return "代理模式的集群架构总节点数为 0"
        return "Total node count is 0 for proxy cluster architecture"

    @classmethod
    def iinfo_parameter_error(cls) -> str:
        if cls.language == "zh":
            return "iinfo 命令的 db_idx 参数为空"
        return "The db_idx parameter of the iinfo command is empty"

    @classmethod
    def riinfo_parameter_error(cls) -> str:
        if cls.language == "zh":
            return "riinfo 命令的 db_idx 或 slave_idx 参数为空"
        return "The db_idx or slave_idx parameter of the riinfo command is empty"

    @classmethod
    def no_detect_results_error(cls) -> str:
        if cls.language == "zh":
            return "未获取到任何 Redis server 的探查结果"
        return "No Redis server detection results"

    @classmethod
    def server_down_hint(cls) -> str:
        if cls.language == "zh":
            return "没有 Redis server {} 的探查结果，server 无法响应"
        return "No detection result for server {}, it is unable to respond"

    @classmethod
    def server_fail_hint(cls) -> str:
        if cls.language == "zh":
            return "server {} 总共探查 {} 次，失败 {} 次"
        return "Server {} is detected {} times in total and failed {} times"

    @classmethod
    def proxy_runid_not_found_error(cls) -> str:
        if cls.language == "zh":
            return "proxy支持返回proxy run id，但未找到"
        return "Proxy run id is supported, but not found"


class ErrorNotification(NotificationTemplate):
    @classmethod
    def ecs_security_group_default_policy_interception_error(cls) -> str:
        if cls.language == "zh":
            return "被安全组默认策略拦截"
        return "intercepted by security group default policy"

    @classmethod
    def whitelist_error(cls) -> str:
        if cls.language == "zh":
            return "IP: {} 不在 Redis 实例白名单中"
        return "IP: {} is not in Redis instance whitelist"

    @classmethod
    def connection_info_error(cls):
        if cls.language == "zh":
            return "无效连接信息，错误类型：{}，连接地址：{}，连接端口：{}"
        return "Invalid connection info, error type: {}, connection address: {}, connection port: {}"

    @classmethod
    def auth_error(cls):
        if cls.language == "zh":
            return "无效账号信息，账号：{}，密码：{}"
        return "Invalid user: {} or password: {}"

    @classmethod
    def system_type_error(cls):
        if cls.language == "zh":
            return "不支持的系统：{}"
        return "Unsupported system:{}"

    @classmethod
    def name_lookup_error(cls):
        if cls.language == "zh":
            return "无法解析域名：{}"
        return "Unable to resolve hostname: {}"

    @classmethod
    def name_server_error(cls):
        if cls.language == "zh":
            return "DNS nameserver 未配置"
        return "DNS nameserver is not configured"

    @classmethod
    def internal_error(cls):
        if cls.language == "zh":
            return "内部错误：{}"
        return "Internal error: {}"

    @classmethod
    def sdk_invalid_ak_error(cls):
        if cls.language == "zh":
            return "无效的Access Key Id"
        return "Invalid Access Key Id"

    @classmethod
    def sdk_invalid_sk_error(cls):
        if cls.language == "zh":
            return "无效的 Access Key Secret"
        return "Invalid Access Key Secret"

    @classmethod
    def sdk_service_address_error(cls):
        if cls.language == "zh":
            return "无效的服务地址，地域 ID 或服务接入点错误"
        return "Invalid service address, wrong region id or service endpoint"

    @classmethod
    def sdk_service_forbidden_error(cls):
        if cls.language == "zh":
            return "禁止访问服务，无权限"
        return "Access to the service is forbidden, no permission"
