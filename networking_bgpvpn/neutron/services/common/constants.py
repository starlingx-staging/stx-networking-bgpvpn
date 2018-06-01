# Copyright 2015 OpenStack Foundation
# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2017 Wind River Systems, Inc.
#

from neutron_lib.api.definitions import bgpvpn

BGPVPN = "BGPVPN"

BGPVPN_RES = bgpvpn.BGPVPN_RES
BGPVPN_L3 = bgpvpn.BGPVPN_L3
BGPVPN_L2 = bgpvpn.BGPVPN_L2
BGPVPN_TYPES = bgpvpn.BGPVPN_TYPES
UINT32_REGEX, = bgpvpn.UINT32_REGEX,
UINT16_REGEX = bgpvpn.UINT16_REGEX
UINT8_REGEX = bgpvpn.UINT8_REGEX
IP4_REGEX = bgpvpn.IP4_REGEX
RTRD_REGEX = bgpvpn.RTRD_REGEX

BGPEVPN_RT_ETH_AUTO_DISCOVERY = "eth_ad"
BGPEVPN_RT_MAC_IP_ADV_ROUTE = "mac_ip_adv"
BGPEVPN_RT_MULTICAST_ETAG_ROUTE = "multicast_etag"
BGPEVPN_RT_ETH_SEGMENT = "eth_seg"
BGPEVPN_RT_IP_PREFIX_ROUTE = "ip_prefix"

BGPEVPN_SUPPORTED_ROUTE_TYPES = [BGPEVPN_RT_MAC_IP_ADV_ROUTE,
                                 BGPEVPN_RT_MULTICAST_ETAG_ROUTE]
