# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2017 Wind River Systems, Inc.
#

import oslo_messaging

from neutron.common import rpc as n_rpc


class BGPVPNRpcCallback(object):
    """BGP VPN RPC callback in plugin implementations.

    This class implements the server side of an RPC interface.
    For more information about changing RPC interfaces,
    see http://docs.openstack.org/developer/neutron/devref/rpc_api.html.

    # API version history:
    # 1.0 Initial version
    """
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, driver):
        self.driver = driver

    def bgpvpn_update_gateways(self, context, host, vteps):
        """Update a gateway records from learned BGP information."""
        return self.driver.update_bgpvpn_gateways(context, host, vteps)

    def bgpvpn_update_devices(self, context, host, devices):
        """Update a device based on input from learned BGP information."""
        return self.driver.update_bgpvpn_devices(context, host, devices)


class BGPVPNRpcApi(object):
    """Agent side of BGP VPN RPC API.

    This class implements the client side of an rpc interface.
    For more information about changing rpc interfaces, see
    doc/source/devref/rpc_api.rst.

    API version history:
        1.0 - Initial version.
    """
    def __init__(self, topic, context, host):
        self.context = context
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def bgpvpn_update_gateways(self, context, vteps):
        """Make a remote procedure call to add/remove VTEP gateways.

        Gateway instances are defined as:
           {<bgpvpn_id>: [{'ip_address':  <ipv4 or ipv6>,
                           'withdrawn': <boolean>}, ... ],
            ...}

        The list of VTEP gateways is assumed to have been minimally processed
        by the agent before sending so that there are no duplicate entries
        (i.e., the same IP being withdrawn and then added, and vice-versa).
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'bgpvpn_update_gateways',
                          host=self.host, vteps=vteps)

    def bgpvpn_update_devices(self, context, devices):
        """Make a remote procedure call to add/remove device records.

        Device instances are defined as:
           {<bgpvpn_id>: [{'ip_address', <ip_address>,
                           'mac_address': <mac>,
                           'gateway_ip': <nexthop>,
                           'withdrawn': <boolean>}, ...],
                          ...},
            ...}
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'bgpvpn_update_devices',
                          host=self.host, devices=devices)
