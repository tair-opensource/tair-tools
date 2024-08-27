from diagnose.ecs import ECS, SecurityGroup, SecurityGroupRule
from diagnose.exceptions import InternalError, EcsSecurityGroupError

import pytest
from unittest import mock
from unittest.mock import MagicMock


@pytest.fixture(autouse=True)
def mock_logger():
    with mock.patch("diagnose.ecs.logger") as logger:
        yield logger


class TestSecurityGroupRule:
    @pytest.fixture
    def in_rule(self):
        return SecurityGroupRule("sg-123456789",
                                 **{"Priority": "1",
                                    "Policy": "accept",
                                    "Direction": "ingress",
                                    "IpProtocol": "TCP",
                                    "PortRange": "80/80",
                                    "DestCidrIp": "0.0.0.0/0",
                                    "SourcePortRange": "-1/-1",
                                    "SourceCidrIp": "192.168.0.0/16",
                                    "CreateTime": "2024-08-02T01:45:06Z"})

    @pytest.fixture
    def out_rule(self):
        return SecurityGroupRule("sg-123456789",
                                 **{"Priority": "1",
                                    "Policy": "accept",
                                    "Direction": "egress",
                                    "IpProtocol": "TCP",
                                    "PortRange": "6379/6379",
                                    "DestCidrIp": "192.168.0.0/16",
                                    "SourcePortRange": "-1/-1",
                                    "SourceCidrIp": "0.0.0.0/0",
                                    "CreateTime": "2024-08-02T01:43:06Z"})

    def test_validate_security_group_rule_egress_valid(self, out_rule):
        hit = out_rule.validate_security_group_rule(
            direction="egress",
            protocol="TCP",
            target_ip="192.168.1.10",
            target_port=6379,
        )
        assert hit

    def test_validate_security_group_rule_egress_invalid_cidr(self, out_rule):
        hit = out_rule.validate_security_group_rule(
            direction="egress",
            protocol="TCP",
            target_ip="192.167.1.10",
            target_port=6379,
        )
        assert not hit

    def test_validate_security_group_rule_invalid_direction(self, out_rule):
        hit = out_rule.validate_security_group_rule(
            direction="ingress",
            protocol="TCP",
            target_ip="192.168.1.10",
            target_port=6379,
        )
        assert not hit

    def test_validate_security_group_rule_invalid_protocol(self, out_rule):
        hit = out_rule.validate_security_group_rule(
            direction="egress",
            protocol="UDP",
            target_ip="192.168.1.10",
            target_port=6379,
        )
        assert not hit

    def test_validate_security_group_rule_invalid_port(self, out_rule):
        hit = out_rule.validate_security_group_rule(
            direction="egress",
            protocol="TCP",
            target_ip="192.168.1.10",
            target_port=6380,
        )
        assert not hit

    def test_validate_security_group_rule_missing_dest_port(self, out_rule):
        with pytest.raises(InternalError):
            out_rule.validate_security_group_rule(
                direction="egress",
                protocol="TCP",
                target_ip="192.168.1.10",
            )

    def test_validate_security_group_rule_ingress_valid(self, in_rule):
        hit = in_rule.validate_security_group_rule(
            direction="ingress",
            protocol="TCP",
            target_ip="192.168.1.10",
            target_port=80,
        )
        assert hit

    def test_validate_security_group_rule_ingress_invalid_cidr(self, in_rule):
        hit = in_rule.validate_security_group_rule(
            direction="ingress",
            protocol="TCP",
            target_ip="192.167.1.10",
            target_port=80,
        )
        assert not hit

    def test_repr(self, out_rule):
        expected_repr = ("direction: egress, policy: accept, priority: 1, protocol: TCP, "
                         "destination port range: 6379/6379, destination cidr ip: 192.168.0.0/16, "
                         "source port range: -1/-1, source cidr ip: 0.0.0.0/0, "
                         "create time: 2024-08-02 01:43:06+00:00, security group id: sg-123456789")
        assert repr(out_rule) == expected_repr


class TestSecurityGroup:
    def test_security_group(self):
        mock_sdk = MagicMock()
        security_group_info_1 = {
            "Description": "security group",
            "SecurityGroupName": "sg-test",
            "VpcId": "vpc-id",
            "ServiceManaged": False,
            "ResourceGroupId": "",
            "SecurityGroupId": "sg-group-id1",
            "SecurityGroupType": "normal",
            "CreationTime": "2024-07-30T07:43:23Z",
            "Tags": {
                "Tag": []
            }
        }
        security_group_info_2 = {
            "Description": "security group",
            "SecurityGroupName": "sg-test",
            "VpcId": "vpc-id",
            "ServiceManaged": False,
            "ResourceGroupId": "",
            "SecurityGroupId": "sg-group-id2",
            "SecurityGroupType": "enterprise",
            "CreationTime": "2024-07-30T07:43:23Z",
            "Tags": {
                "Tag": []
            }
        }
        security_groups_info = {
            "SecurityGroups": {
                "SecurityGroup": []
            }
        }
        security_rules = {
            "Permissions": {
                "Permission": [
                    {
                        "SourceGroupId": "",
                        "Policy": "Accept",
                        "Description": "",
                        "SourcePortRange": "",
                        "Priority": 1,
                        "CreateTime": "2024-08-01T03:08:46Z",
                        "DestPrefixListName": "",
                        "Ipv6SourceCidrIp": "",
                        "NicType": "intranet",
                        "Direction": "egress",
                        "DestGroupId": "",
                        "SourceGroupName": "",
                        "PortRange": "6379/6379",
                        "DestGroupOwnerAccount": "",
                        "DestPrefixListId": "",
                        "SourceCidrIp": "",
                        "SourcePrefixListName": "",
                        "IpProtocol": "TCP",
                        "SecurityGroupRuleId": "sgr-id",
                        "DestCidrIp": "0.0.0.0/0",
                        "DestGroupName": "",
                        "Ipv6DestCidrIp": "",
                        "SourceGroupOwnerAccount": "",
                        "SourcePrefixListId": ""
                    }
                ]
            },
            "InnerAccessPolicy": "Accept",
        }
        mock_sdk.describe_security_groups.return_value = security_groups_info
        mock_sdk.describe_security_group_attribute.return_value = security_rules

        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=mock_sdk):
            # Security group not found
            with pytest.raises(InternalError):
                SecurityGroup("region-id", "sg-group-id")

            # Exact one security group with one rule
            security_groups_info["SecurityGroups"]["SecurityGroup"].append(security_group_info_1)
            security_group = SecurityGroup("region-id", "sg-group-id")
            assert security_group.security_group_type == "normal"
            assert len(security_group.security_group_rules) == 1
            security_rule = security_group.security_group_rules[0]
            assert security_rule.priority == 1
            assert security_rule.policy == "Accept"
            assert security_rule.direction == "egress"
            assert security_rule.dest_cidr_ip == "0.0.0.0/0"
            assert security_rule.port_range == "6379/6379"
            assert security_rule.ip_protocol == "TCP"

            # Multiple security groups
            security_groups_info["SecurityGroups"]["SecurityGroup"].insert(0, security_group_info_2)
            security_group = SecurityGroup("region-id", "sg-group-id")
            assert security_group.security_group_type == "enterprise"


class TestECS:
    @pytest.fixture(autouse=True)
    def init(self):
        self.mock_sdk = MagicMock()
        security_groups_info = {
            "SecurityGroups": {
                "SecurityGroup": [
                    {
                        "Description": "security group",
                        "SecurityGroupName": "sg-test",
                        "VpcId": "vpc-id",
                        "ServiceManaged": False,
                        "ResourceGroupId": "",
                        "SecurityGroupId": "sg-group-id1",
                        "SecurityGroupType": "normal",
                        "CreationTime": "2024-07-30T07:43:23Z",
                        "Tags": {
                            "Tag": []
                        }
                    }
                ]
            }
        }
        security_rules = {
            "Permissions": {
                "Permission": [
                    {
                        "SourceGroupId": "",
                        "Policy": "Accept",
                        "Description": "",
                        "SourcePortRange": "",
                        "Priority": 10,
                        "CreateTime": "2024-08-01T03:08:46Z",
                        "DestPrefixListName": "",
                        "Ipv6SourceCidrIp": "",
                        "NicType": "intranet",
                        "Direction": "egress",
                        "DestGroupId": "",
                        "SourceGroupName": "",
                        "PortRange": "6379/6379",
                        "DestGroupOwnerAccount": "",
                        "DestPrefixListId": "",
                        "SourceCidrIp": "",
                        "SourcePrefixListName": "",
                        "IpProtocol": "TCP",
                        "SecurityGroupRuleId": "sgr-id",
                        "DestCidrIp": "0.0.0.0/0",
                        "DestGroupName": "",
                        "Ipv6DestCidrIp": "",
                        "SourceGroupOwnerAccount": "",
                        "SourcePrefixListId": ""
                    },
                    {
                        "SourceGroupId": "",
                        "Policy": "Drop",
                        "Description": "",
                        "SourcePortRange": "",
                        "Priority": 1,
                        "CreateTime": "2024-08-01T03:18:52Z",
                        "DestPrefixListName": "",
                        "Ipv6SourceCidrIp": "",
                        "NicType": "intranet",
                        "Direction": "egress",
                        "DestGroupId": "",
                        "SourceGroupName": "",
                        "PortRange": "6379/6379",
                        "DestGroupOwnerAccount": "",
                        "DestPrefixListId": "",
                        "SourceCidrIp": "",
                        "SourcePrefixListName": "",
                        "IpProtocol": "TCP",
                        "SecurityGroupRuleId": "sgr-id",
                        "DestCidrIp": "192.168.0.0/16",
                        "DestGroupName": "",
                        "Ipv6DestCidrIp": "",
                        "SourceGroupOwnerAccount": "",
                        "SourcePrefixListId": ""
                    },
                    {
                        "SourceGroupId": "",
                        "Policy": "Drop",
                        "Description": "",
                        "SourcePortRange": "",
                        "Priority": 1,
                        "CreateTime": "2024-08-01T03:19:52Z",
                        "DestPrefixListName": "",
                        "Ipv6SourceCidrIp": "",
                        "NicType": "intranet",
                        "Direction": "egress",
                        "DestGroupId": "",
                        "SourceGroupName": "",
                        "PortRange": "6379/6379",
                        "DestGroupOwnerAccount": "",
                        "DestPrefixListId": "",
                        "SourceCidrIp": "",
                        "SourcePrefixListName": "",
                        "IpProtocol": "TCP",
                        "SecurityGroupRuleId": "sgr-id",
                        "DestCidrIp": "192.168.0.0/24",
                        "DestGroupName": "",
                        "Ipv6DestCidrIp": "",
                        "SourceGroupOwnerAccount": "",
                        "SourcePrefixListId": ""
                    },
                    {
                        "SourceGroupId": "",
                        "Policy": "Accept",
                        "Description": "",
                        "SourcePortRange": "",
                        "Priority": 1,
                        "CreateTime": "2024-08-01T03:18:52Z",
                        "DestPrefixListName": "",
                        "Ipv6SourceCidrIp": "",
                        "NicType": "intranet",
                        "Direction": "egress",
                        "DestGroupId": "",
                        "SourceGroupName": "",
                        "PortRange": "6379/6379",
                        "DestGroupOwnerAccount": "",
                        "DestPrefixListId": "",
                        "SourceCidrIp": "",
                        "SourcePrefixListName": "",
                        "IpProtocol": "TCP",
                        "SecurityGroupRuleId": "sgr-id",
                        "DestCidrIp": "192.168.0.0/8",
                        "DestGroupName": "",
                        "Ipv6DestCidrIp": "",
                        "SourceGroupOwnerAccount": "",
                        "SourcePrefixListId": ""
                    },
                ]
            },
            "InnerAccessPolicy": "Accept",
        }
        ecs_info = {
            "InstanceNetworkType": "vpc",
            "PublicIpAddress": {
                "IpAddress": [
                    "47.47.47.47"
                ]
            },
            "InnerIpAddress": {
                "IpAddress": []
            },
            "EipAddress": {
                "AllocationId": "",
                "IpAddress": "",
                "InternetChargeType": ""
            },
            "ZoneId": "ZoneId",
            "SecurityGroupIds": {
                "SecurityGroupId": [
                    "sg-id"
                ]
            },
            "VpcAttributes": {
                "PrivateIpAddress": {
                    "IpAddress": [
                        "192.168.0.10"
                    ]
                },
                "VpcId": "vpc-id",
                "VSwitchId": "vsw-id",
                "NatIpAddress": ""
            },
            "RegionId": "region-id",
        }
        self.mock_sdk.describe_security_groups.return_value = security_groups_info
        self.mock_sdk.describe_security_group_attribute.return_value = security_rules
        self.mock_sdk.describe_instance_attribute.return_value = ecs_info

    def test_ecs(self):
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            ecs = ECS("e-instance-id")

            # Test ecs instance info
            assert ecs.region_id == "region-id"
            assert ecs.zone_id == "ZoneId"
            assert ecs.public_ips == ["47.47.47.47"]
            assert ecs.private_ips == ["192.168.0.10"]
            assert ecs.network_type == "vpc"
            assert ecs.vpc_id == "vpc-id"
            assert ecs.v_switch_id == "vsw-id"

            # Test ecs security group info
            assert len(ecs.security_groups) == 1

            # Test classify_and_sort_security_groups
            assert len(ecs.in_security_group_rules) == 0
            assert len(ecs.out_security_group_rules.get("TCP")) == 4
            security_group_rules = ecs.out_security_group_rules.get("TCP")
            assert security_group_rules[0].priority == 1
            assert security_group_rules[1].priority == 1
            assert security_group_rules[2].priority == 1
            assert security_group_rules[3].priority == 10
            assert security_group_rules[0].policy == "Drop"
            assert security_group_rules[1].policy == "Drop"
            assert security_group_rules[2].policy == "Accept"
            assert security_group_rules[0].dest_cidr_ip == "192.168.0.0/24"
            assert security_group_rules[1].dest_cidr_ip == "192.168.0.0/16"

    def test_diagnose_security_group(self):
        with mock.patch("diagnose.sdk.SDKFactory.get_sdk", return_value=self.mock_sdk):
            ecs = ECS("e-instance-id")
            # output rule
            # default policy
            ecs.diagnose_security_group("egress", "UDP", "191.167.1.23", 6379)
            # Accept by rule 3
            ecs.diagnose_security_group("egress", "TCP", "192.167.1.23", 6379)
            with pytest.raises(EcsSecurityGroupError):
                # Intercepted by rule 2
                ecs.diagnose_security_group("egress", "TCP", "192.168.1.23", 6379)
            with pytest.raises(EcsSecurityGroupError):
                # Intercepted by rule 1
                ecs.diagnose_security_group("egress", "TCP", "192.168.0.23", 6379)

            # input rule
            with pytest.raises(EcsSecurityGroupError):
                ecs.diagnose_security_group("ingress", "TCP", "192.168.0.1", 100)