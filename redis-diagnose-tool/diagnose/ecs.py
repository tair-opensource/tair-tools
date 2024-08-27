from diagnose.sdk import SDKFactory, SDKType
from diagnose import utils
from diagnose.logger_config import logger
from diagnose.exceptions import InternalError, EcsSecurityGroupError
from diagnose.notification_template import ECSNotification
from diagnose.diagnostic_report import ConnectionDiagnosticReport, ProcessReport

from collections import defaultdict
from dateutil import parser


class ECS:
    def __init__(self, instance_id: str):
        self.instance_id = instance_id
        self.region_id = None
        self.zone_id = None
        self.network_type = None
        self.vpc_id = None
        self.v_switch_id = None
        self.public_ips = []
        self.private_ips = []
        self.security_groups = []
        self.in_security_group_rules = defaultdict(list)
        self.out_security_group_rules = defaultdict(list)
        self._get_instance_info()

    def _get_instance_info(self):
        logger.info(ProcessReport.get_arrow_line(yes=True))
        logger.info(ProcessReport.step_indentation + ProcessReport.arrow_head)
        logger.info(ProcessReport.gen_process_rectangle(ECSNotification.ecs_info_log()))
        ecs_sdk = SDKFactory.get_sdk(SDKType.ECS)
        instance_attribute = ecs_sdk.describe_instance_attribute(self.instance_id)
        self.region_id = instance_attribute["RegionId"]
        self.zone_id = instance_attribute["ZoneId"]
        self.public_ips.extend(instance_attribute["PublicIpAddress"]["IpAddress"])
        if (instance_attribute["EipAddress"]["IpAddress"] is not None and
                instance_attribute["EipAddress"]["IpAddress"] != ""):
            self.public_ips.append(instance_attribute["EipAddress"]["IpAddress"])
        self.network_type = instance_attribute["InstanceNetworkType"]
        if self.network_type == "vpc":
            self.vpc_id = instance_attribute["VpcAttributes"]["VpcId"]
            self.v_switch_id = instance_attribute["VpcAttributes"]["VSwitchId"]
            self.private_ips.extend(instance_attribute["VpcAttributes"]["PrivateIpAddress"]["IpAddress"])
        else:
            self.private_ips.extend(instance_attribute["InnerIpAddress"]["IpAddress"])

        security_group_ids = instance_attribute["SecurityGroupIds"]["SecurityGroupId"]
        self.security_groups = [SecurityGroup(self.region_id, security_group_id) for security_group_id in
                                security_group_ids]
        self._classify_and_sort_security_groups()

    def _classify_and_sort_security_groups(self):
        for security_group in self.security_groups:
            for security_group_rule in security_group.security_group_rules:
                if security_group_rule.direction == "ingress":
                    self.in_security_group_rules[security_group_rule.ip_protocol].append(security_group_rule)
                else:
                    self.out_security_group_rules[security_group_rule.ip_protocol].append(security_group_rule)
        for ip_protocol in self.in_security_group_rules:
            self.in_security_group_rules[ip_protocol].sort(key=lambda x: (x.priority, 0 if x.policy == "Drop" else 1,
                                                                          -x.create_time.timestamp()))
        for ip_protocol in self.out_security_group_rules:
            self.out_security_group_rules[ip_protocol].sort(key=lambda x: (x.priority, 0 if x.policy == "Drop" else 1,
                                                                           -x.create_time.timestamp()))

    def diagnose_security_group(
            self,
            direction: str,
            protocol: str,
            target_ip: str,
            target_port: int = None,
    ):
        # Not supported protocol: ICMPV6
        if direction == "ingress":
            security_group_rules = self.in_security_group_rules[protocol]
        else:
            security_group_rules = self.out_security_group_rules[protocol]
        for security_group_rule in security_group_rules:
            if not security_group_rule.validate_security_group_rule(direction, protocol, target_ip, target_port):
                continue
            if security_group_rule.policy == "Accept":
                return
            raise EcsSecurityGroupError("in" if direction == "ingress" else "out", target_ip,
                                        protocol, target_port, repr(security_group_rule))

        # No matched security group rule, apply default rule
        security_group_type = self.security_groups[0].security_group_type if len(self.security_groups) > 0 else None

        if security_group_type == "enterprise":
            raise EcsSecurityGroupError("in" if direction == "ingress" else "out", target_ip, protocol, target_port)
        else:  # Default normal security group
            if direction != "ingress":
                return
            raise EcsSecurityGroupError("in" if direction == "ingress" else "out", target_ip, protocol, target_port)


class SecurityGroup:
    def __init__(self, region_id: str, security_group_id: str):
        self.region_id = region_id
        self.security_group_id = security_group_id
        self.security_group_type = None
        self.inner_access_policy = None
        self.security_group_rules = []
        self.service_managed = None
        self._get_security_group_info()
        self._get_security_group_rules()

    def _get_security_group_info(self):
        ecs_sdk = SDKFactory.get_sdk(SDKType.ECS)
        security_group_attributes = ecs_sdk.describe_security_groups(self.region_id, [self.security_group_id])
        security_group_attributes = security_group_attributes["SecurityGroups"]["SecurityGroup"]
        if len(security_group_attributes) > 0:
            security_group_attribute = security_group_attributes[0]
            if len(security_group_attributes) > 1:
                ConnectionDiagnosticReport.add_warning(ECSNotification.multiple_ecs_security_group_waning().format(
                    self.security_group_id, self.region_id))
        else:
            raise InternalError(ECSNotification.ecs_security_group_not_fount_error().format(
                self.security_group_id, self.region_id))
        self.security_group_type = security_group_attribute["SecurityGroupType"]
        self.service_managed = security_group_attribute["ServiceManaged"]

    def _get_security_group_rules(self):
        ecs_sdk = SDKFactory.get_sdk(SDKType.ECS)
        security_group_attribute = ecs_sdk.describe_security_group_attribute(self.region_id, self.security_group_id)
        self.inner_access_policy = security_group_attribute["InnerAccessPolicy"]
        for rule_dict in security_group_attribute["Permissions"]["Permission"]:
            self.security_group_rules.append(SecurityGroupRule(self.security_group_id, **rule_dict))


class SecurityGroupRule:
    def __init__(self, security_group_id, **kwargs):
        self.priority = kwargs.get("Priority")
        self.policy = kwargs.get("Policy")
        self.direction = kwargs.get("Direction")
        self.ip_protocol = kwargs.get("IpProtocol")
        self.port_range = kwargs.get("PortRange")
        self.dest_cidr_ip = kwargs.get("DestCidrIp")
        self.source_port_range = kwargs.get("SourcePortRange")
        self.source_cidr_ip = kwargs.get("SourceCidrIp")
        self.create_time = parser.parse(kwargs.get("CreateTime"))
        self.security_group_id = security_group_id

    def validate_security_group_rule(
            self,
            direction: str,
            protocol: str,
            target_ip: str,
            target_port: int = None,
    ) -> bool:
        if direction != self.direction:
            return False
        if self.ip_protocol.upper() != "ALL" and protocol.upper() != self.ip_protocol.upper():
            return False
        port_lower_bound, port_upper_bound = list(map(lambda x: int(x), self.port_range.split("/")))
        if protocol.upper() in ["TCP", "UDP"] and target_port is None:
            raise InternalError(ECSNotification.ecs_security_group_port_check_error())
        if port_lower_bound != -1 and port_upper_bound != -1 and (
                target_port is None or target_port < port_lower_bound or target_port > port_upper_bound):
            return False
        if self.direction == "ingress":
            if not utils.is_ip_in_cidr(target_ip, self.source_cidr_ip):
                return False
        else:
            if not utils.is_ip_in_cidr(target_ip, self.dest_cidr_ip):
                return False
        # The source port is automatically assigned and uncertain, and it is not configured in most of the time,
        # so do not validate source port. If source port is given, print a warning and return False
        if self.source_port_range is not None and self.source_port_range != "" and self.source_port_range != "-1/-1":
            ConnectionDiagnosticReport.add_warning(ECSNotification.ecs_security_group_src_port_no_validation_warning()
                                                   .format(repr(self)))
            return False
        return True

    def __repr__(self):
        return ("direction: {}, policy: {}, priority: {}, protocol: {}, destination port range: {}, destination cidr "
                "ip: {}, source port range: {}, source cidr ip: {}, create time: {}, security group id: {}").format(
                self.direction, self.policy, self.priority, self.ip_protocol, self.port_range, self.dest_cidr_ip,
                self.source_port_range, self.source_cidr_ip, self.create_time, self.security_group_id)
