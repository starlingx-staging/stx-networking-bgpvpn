# Copyright (c) 2016 IBM.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2017 Wind River Systems, Inc.
#

import copy
import six

from oslo_log import log as logging

from neutron_lib.api.definitions import provider_net as providernet
from neutron_lib import constants as const
from neutron_lib.plugins import directory

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.plugins.common import constants as plugin_constants
from neutron.plugins.ml2.drivers.l2pop import mech_driver as l2pop_driver
from neutron.plugins.ml2.drivers.l2pop import rpc as l2pop_rpc
from neutron import service

from networking_bgpvpn.neutron.api import rpc
from networking_bgpvpn.neutron.callback import resources
from networking_bgpvpn.neutron.extensions import bgpvpn as bgpvpn_ext
from networking_bgpvpn.neutron.services.common import constants
from networking_bgpvpn.neutron.services.service_drivers import driver_api

from neutron_dynamic_routing.services.bgp.common import constants \
    as dr_constants


DR_DRIVER_NAME = "neutron-dynamic-routing"
LOG = logging.getLogger(__name__)


class DynamicRoutingBGPVPNDriver(driver_api.BGPVPNDriver):

    """BGPVPN Service Driver class for neutron-dynamic-routing"""

    def __init__(self, service_plugin):
        super(DynamicRoutingBGPVPNDriver, self).__init__(service_plugin)
        self.l2_notifier = l2pop_rpc.L2populationAgentNotifyAPI()
        self.rpc_listener = rpc.BGPVPNRpcCallback(self)
        self.connection = None
        self._core_plugin = None
        self.register_callbacks()

    def start_rpc_listeners(self):
        self.connection = n_rpc.create_connection()
        self.connection.create_consumer(
            constants.BGPVPN, [self.rpc_listener], fanout=False)
        return self.connection.consume_in_threads()

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    def get_workers(self):
        return [service.RpcWorker([self], worker_process_count=0)]

    def _format_bgpvpn_route_targets(self, bgpvpn):
        """Format BGPVPN route targets)"""

        bgpvpn_rts = {'import_rt': [],
                      'export_rt': []}

        if 'route_targets' in bgpvpn:
            bgpvpn_rts['import_rt'] += bgpvpn['route_targets']
            bgpvpn_rts['export_rt'] += bgpvpn['route_targets']

        if 'import_targets' in bgpvpn:
            bgpvpn_rts['import_rt'] += bgpvpn['import_targets']

        if 'export_targets' in bgpvpn:
            bgpvpn_rts['export_rt'] += bgpvpn['export_targets']

        return bgpvpn_rts

    def _is_bgpvpn_vni_empty(self, bgpvpn):
        if bgpvpn.get('vni', None) is None:
            raise bgpvpn_ext.BGPVPNVNINotSupported(driver=DR_DRIVER_NAME)

    def _is_bgpvpn_vni_unique(self, ctx, bgpvpn):
        # NOTE(alegacy):  in our system, VXLAN provider networks are not
        # global.  A customer can re-use the same VNI in a different part of
        # their system if they know that it is safe to do so.  For the
        # purpose of managing the BGP interactions we need the VNI to be
        # unique otherwise when we receive a packet from a peer BGP speaker
        # we won't know how to map it back to one of our instances.  Perhaps
        # we should move this to our provider network creation semantics to
        # force the VNI to be unique at the system level instead of only at
        # the BGP level.
        filters = {'vni': [bgpvpn['vni']]}
        bgpvpns = self.get_bgpvpns(ctx, filters=filters)
        if len(bgpvpns) > 1:
            raise bgpvpn_ext.BGPVPNVNIAlreadyInUse(driver=DR_DRIVER_NAME)

    def _is_bgpvpn_rd_empty(self, bgpvpn):
        if bgpvpn.get('route_distinguishers', None) is None:
            raise bgpvpn_ext.BGPVPNRDNotSupported(driver=DR_DRIVER_NAME)

    def _validate_bgpvpn(self, ctx, bgpvpn):
        self._is_bgpvpn_rd_empty(bgpvpn)
        self._is_bgpvpn_vni_empty(bgpvpn)
        self._is_bgpvpn_vni_unique(ctx, bgpvpn)

    def create_bgpvpn_precommit(self, ctx, bgpvpn):
        self._validate_bgpvpn(ctx, bgpvpn)

    def create_bgpvpn_postcommit(self, ctx, bgpvpn):
        bgpvpn_rts = self._format_bgpvpn_route_targets(bgpvpn)
        kwargs = {'id': bgpvpn['id'],
                  'name': bgpvpn['name'],
                  'context': ctx,
                  'type': bgpvpn['type'],
                  'rd': bgpvpn['route_distinguishers'],
                  'vni': bgpvpn['vni']}
        kwargs.update(bgpvpn_rts)
        registry.notify(resources.BGPVPN, events.AFTER_CREATE, self,
                        **kwargs)

    def update_bgpvpn_precommit(self, ctx, old_bgpvpn, bgpvpn):
        if (bgpvpn.get('route_distinguishers') is not None and
                old_bgpvpn['route_distinguishers'] !=
                bgpvpn['route_distinguishers']):
            raise bgpvpn_ext.BGPVPNRDNotSupported(driver=DR_DRIVER_NAME)

        if (bgpvpn.get('vni') is not None and
                old_bgpvpn['vni'] != bgpvpn['vni']):
            raise bgpvpn_ext.BGPVPNVNINotSupported(driver=DR_DRIVER_NAME)

    def update_bgpvpn_postcommit(self, ctx, old_bgpvpn, bgpvpn):
        old_vpn = {'id': old_bgpvpn['id'],
                   'name': old_bgpvpn['name'],
                   'type': old_bgpvpn['type'],
                   'rd': old_bgpvpn['route_distinguishers'],
                   'vni': old_bgpvpn['vni']}
        old_vpn_rts = self._format_bgpvpn_route_targets(old_bgpvpn)
        old_vpn.update(old_vpn_rts)
        new_vpn = {'id': bgpvpn['id'],
                   'name': bgpvpn['name'],
                   'type': bgpvpn['type'],
                   'rd': bgpvpn['route_distinguishers'],
                   'vni': bgpvpn['vni']}
        new_vpn_rts = self._format_bgpvpn_route_targets(bgpvpn)
        new_vpn.update(new_vpn_rts)
        kwargs = {'old_vpn': old_vpn,
                  'new_vpn': new_vpn}
        kwargs.update({'context': ctx})
        registry.notify(resources.BGPVPN, events.AFTER_UPDATE, self,
                        **kwargs)

    def delete_bgpvpn(self, context, id):
        # NOTE(alegacy): The deactivation of the vpn should be handled in
        # the postcommit hook but because the delete will remove gateway and
        # device records as a result of the DB cascade we need to get a
        # snapshot of the FDB records before the delete actually occurs.
        # For that reason the _deactivate_bgpvpn is split so that the two
        # constituent parts are wrapped around the actual delete operation.
        bgpvpns = [{'id': id}]
        fdb_removes = self._get_fdb_entries(context, bgpvpns=bgpvpns)
        result = super(DynamicRoutingBGPVPNDriver, self).delete_bgpvpn(
            context, id)
        if fdb_removes:
            fdb_removes['source'] = constants.BGPVPN
            self.l2_notifier.remove_fdb_entries(context, fdb_removes)
        return result

    def delete_bgpvpn_postcommit(self, ctx, bgpvpn):
        kwargs = {'id': bgpvpn['id'],
                  'name': bgpvpn['name'],
                  'context': ctx}
        registry.notify(resources.BGPVPN, events.AFTER_DELETE, self,
                        **kwargs)

    # There is no action for this moment
    def create_router_assoc_precommit(self, context, router_assoc):
        pass

    def create_router_assoc_postcommit(self, ctx, router_assoc):
        kwargs = {'context': ctx,
                  'bgpvpn_id': router_assoc['bgpvpn_id'],
                  'router_id': router_assoc['router_id']}
        registry.notify(resources.BGPVPN_ROUTER_ASSOC, events.AFTER_CREATE,
                        self, **kwargs)

    def delete_router_assoc_postcommit(self, ctx, router_assoc):
        kwargs = {'context': ctx,
                  'bgpvpn_id': router_assoc['bgpvpn_id'],
                  'router_id': router_assoc['router_id']}
        registry.notify(resources.BGPVPN_ROUTER_ASSOC, events.AFTER_DELETE,
                        self, **kwargs)

    def create_net_assoc_precommit(self, context, net_assoc):
        pass  # no action for now

    def create_net_assoc_postcommit(self, context, net_assoc):
        kwargs = {'context': context,
                  'bgpvpn_id': net_assoc['bgpvpn_id'],
                  'network_id': net_assoc['network_id']}
        registry.notify(resources.BGPVPN_NETWORK_ASSOC, events.AFTER_CREATE,
                        self, **kwargs)

    def delete_net_assoc_postcommit(self, context, net_assoc):
        kwargs = {'context': context,
                  'bgpvpn_id': net_assoc['bgpvpn_id'],
                  'network_id': net_assoc['network_id']}
        registry.notify(resources.BGPVPN_NETWORK_ASSOC, events.AFTER_DELETE,
                        self, **kwargs)
        # NOTE(alegacy): for now we only support l2vpn instances so if a
        # network association is deleted we automatically deactivate the VPN
        # because it is assumed to be the network directly implementing the
        # vpn.
        self._deactivate_bgpvpn(
            context, net_assoc['bgpvpn_id'], net_assoc['network_id'])

    def create_net_assoc(self, context, bgpvpn_id, network_association):
        bgpvpn = self.get_bgpvpn(context, bgpvpn_id)
        if bgpvpn['type'] != constants.BGPVPN_L2:
            # NOTE(alegacy): we can remove this restriction once we support
            # L3 associations to networks.
            raise bgpvpn_ext.BGPVPNNetAssocNotSupportedForType(
                driver=DR_DRIVER_NAME, type=bgpvpn['type'])
        return super(DynamicRoutingBGPVPNDriver, self).create_net_assoc(
            context, bgpvpn_id, network_association)

    def _get_network_id(self, context, bgpvpn_id):
        # This method returns a list, but for l2vpn instances there can only
        # be a single association since there can only be one network with
        # a given VNI value.
        associations = self.bgpvpn_db.get_net_assocs(context, bgpvpn_id)
        return associations[0]['network_id'] if associations else None

    def _get_network(self, context, bgpvpn_id, network_id=None):
        network_id = network_id or self._get_network_id(context, bgpvpn_id)
        if network_id:
            return self.core_plugin.get_network(context, network_id)

    def _get_agent_id(self, context, host):
        filters = {'host': [host],
                   'agent_type': [dr_constants.AGENT_TYPE_BGP_ROUTING]}
        agents = self.core_plugin.get_agents(context, filters=filters)
        return agents[0]['id'] if agents else None

    @classmethod
    def _build_fdb_template(cls, network, ports=None):
        ports = ports or {}
        return {network['id']: {
            'network_type': network[providernet.NETWORK_TYPE],
            'physical_network': network[providernet.PHYSICAL_NETWORK],
            'segment_id': network[providernet.SEGMENTATION_ID],
            'ports': ports}}

    def _merge_gateway_result(self, result, network, inserts, removes):
        """Merge a gateway result to the appropriate FDB table."""
        fdb = removes if 'withdrawn' in result else inserts
        if network['id'] not in fdb:
            fdb.update(self._build_fdb_template(network))
        ports = fdb[network['id']]['ports']
        if result['ip_address'] not in ports:
            ports[result['ip_address']] = set()
        ports[result['ip_address']].add(const.FLOODING_ENTRY)

    def _process_bgpvpn_gateway(self, context, agent_id, bgpvpn_id, gateway):
        """Updates the DB and determines the new state of the given gateway.

        Since we persist data coming from multiple agents we end up with
        multiple records for each gateway IP address.  Since the two agents
        send updates independently there is a lag between the first update
        arriving and the last update arriving which means that when a
        gateway is deleted it may still have other records in the database
        until all agents have reported their state.  For this reason,
        when any update is received we need to requery the DB to determine
        whether the gateway is still active before declaring it removed.

        This is the same process that occurs when a device update is
        received; @see _process_bgpvpn_device.
        """
        if not gateway['withdrawn']:
            self.bgpvpn_db.update_bgpvpn_gateway(
                context, agent_id, bgpvpn_id, gateway['ip_address'])
        else:
            self.bgpvpn_db.delete_bgpvpn_gateway(
                context, agent_id, bgpvpn_id, gateway['ip_address'])
        filters = {'ip_address': gateway['ip_address']}
        results = self.bgpvpn_db.get_bgpvpn_active_gateways(
            context, bgpvpn_id, filters=filters)
        # NOTE(alegacy): we are filtering by IP address so we only expect a
        # single active record for this one IP address.
        return results[0] if results else gateway

    def _process_bgpvpn_gateways(self, context, agent_id, bgpvpn_id, gateways):
        inserts = {}
        removes = {}
        network = self._get_network(context, bgpvpn_id)
        if network is None:
            LOG.warning('Ignoring gateway updates on '
                        'bgpvpn {} from agent {}'.format(
                            bgpvpn_id, agent_id))
            return inserts, removes  # Network association likely deleted
        for gateway in gateways:
            result = self._process_bgpvpn_gateway(
                context, agent_id, bgpvpn_id, gateway)
            self._merge_gateway_result(result, network, inserts, removes)
        return inserts, removes

    def _update_bgpvpn_gateways(self, context, agent_id, gateways):
        inserts = {}
        removes = {}
        for bgpvpn_id, gateways in six.iteritems(gateways):
            inserted, removed = self._process_bgpvpn_gateways(
                context, agent_id, bgpvpn_id, gateways)
            inserts.update(inserted)
            removes.update(removed)

        # Push latest changes down to compute nodes.
        if removes:
            removes['source'] = constants.BGPVPN
            self.l2_notifier.remove_fdb_entries(context, removes)
        if inserts:
            inserts['source'] = constants.BGPVPN
            self.l2_notifier.add_fdb_entries(context, inserts)

    def update_bgpvpn_gateways(self, context, host, gateways):
        LOG.debug("update_bgpvpn_gateways host={} gateways={}".format(
            host, gateways))
        if not self.core_plugin.is_host_available(context, host):
            return  # Ignore updates from hosts that are locked
        agent_id = self._get_agent_id(context, host)
        if agent_id is None:
            LOG.warning("VTEP updates received from unknown agent: {}".
                        format(host))
            return
        return self._update_bgpvpn_gateways(context, agent_id, gateways)

    def _merge_device_results(self, results, network, inserts, removes):
        """Merges a set of device results to the appropriate FDB table."""
        for r in results:
            fdb = removes if 'withdrawn' in r else inserts
            if network['id'] not in fdb:
                fdb.update(self._build_fdb_template(network))
            ports = fdb[network['id']]['ports']
            if r['gateway_ip'] not in ports:
                ports[r['gateway_ip']] = set()
            info = l2pop_rpc.PortInfo(r['mac_address'], r['ip_address'])
            ports[r['gateway_ip']].add(info)

    def _process_bgpvpn_device(self, context, agent_id, bgpvpn_id, device):
        """Updates the DB and calculates the new best route for this device.

        Since we persist data coming from multiple agents we end up with
        multiple records for each mac + ip pair.  In most cases, we expect
        both agents to return identical records and to add and remove
        individual records in lock-step.  But, for accuracy sake, we need to
        process the results to ensure that we pass consistent data down to
        compute nodes.

        We support multiple IP addresses for each MAC address so this method
        may return a list of results rather than a single record.
        """
        filters = {'mac_address': device['mac_address']}
        if not device['withdrawn']:
            self.bgpvpn_db.update_bgpvpn_device(context, agent_id, bgpvpn_id,
                                                device['mac_address'],
                                                device['ip_address'],
                                                device['gateway_ip'])
            # Run a bulk update on any devices matching the MAC address.  It
            # is technically possible that we learn different MAC:IP pairs
            # from different VTEP IP addresses for the same MAC address but
            # in practice this should not be possible or allowed.  So,
            # if we get any update for any MAC address we bulk update all
            # matching records to ensure consistency across all records.
            self.bgpvpn_db.update_bgpvpn_devices(context, agent_id, bgpvpn_id,
                                                 device['mac_address'],
                                                 device['gateway_ip'])
        else:
            self.bgpvpn_db.delete_bgpvpn_device(context, agent_id, bgpvpn_id,
                                                device['mac_address'],
                                                device['ip_address'])
            # constrain the updates to only this mac:ip pair because unlike
            # an update event a delete only affects a single device.
            filters['ip_address'] = device['ip_address']
        # Calculate the new vtep ip for this one device destination.
        results = self.bgpvpn_db.get_bgpvpn_active_devices(
            context, bgpvpn_id, filters=filters)
        return results if results else [device]

    def _process_bgpvpn_devices(self, context, agent_id, bgpvpn_id, devices):
        inserts = {}
        removes = {}
        network = self._get_network(context, bgpvpn_id)
        if network is None:
            LOG.warning('Ignoring device updates on '
                        'bgpvpn {} from agent {}'.format(
                            bgpvpn_id, agent_id))
            return inserts, removes  # Network association likely deleted
        for device in devices:
            results = self._process_bgpvpn_device(
                context, agent_id, bgpvpn_id, device)
            self._merge_device_results(results, network, inserts, removes)
        return inserts, removes

    def _update_bgpvpn_devices(self, context, agent_id, devices):
        inserts = {}
        removes = {}
        for bgpvpn_id, devices in six.iteritems(devices):
            inserted, removed = self._process_bgpvpn_devices(
                context, agent_id, bgpvpn_id, devices)
            inserts.update(inserted)
            removes.update(removed)

        # Push latest changes down to compute nodes.
        if removes:
            removes['source'] = constants.BGPVPN
            self.l2_notifier.remove_fdb_entries(context, removes)
        if inserts:
            inserts['source'] = constants.BGPVPN
            self.l2_notifier.add_fdb_entries(context, inserts)

    def update_bgpvpn_devices(self, context, host, devices):
        LOG.debug("update_bgpvpn_devices host={} devices={}".format(
            host, devices))
        if not self.core_plugin.is_host_available(context, host):
            return  # Ignore updates from hosts that are locked
        agent_id = self._get_agent_id(context, host)
        if agent_id is None:
            LOG.warning("Device updates received from unknown agent: {}".
                        format(host))
            return
        return self._update_bgpvpn_devices(context, agent_id, devices)

    def _get_network_fdb_entries(self, context, network, bgpvpn_id):
        """Return an L2POP compatible dict of FDB entries for one network."""
        fdb_entries = self._build_fdb_template(network)
        ports = fdb_entries[network['id']]['ports']
        # Add a device entry for each device in this bgpvpn
        devices = self.bgpvpn_db.get_bgpvpn_active_devices(context, bgpvpn_id)
        for d in devices:
            if d['gateway_ip'] not in ports:
                ports[d['gateway_ip']] = [const.FLOODING_ENTRY]
            info = l2pop_rpc.PortInfo(d['mac_address'], d['ip_address'])
            ports[d['gateway_ip']].append(info)
        # Add a flood entry for any VTEP instance that is not already present
        gateways = self.bgpvpn_db.get_bgpvpn_gateways(context, bgpvpn_id)
        for g in gateways:
            if g['ip_address'] not in ports:
                ports[g['ip_address']] = [const.FLOODING_ENTRY]
        return fdb_entries

    def _get_fdb_entries(self, context, bgpvpns=None):
        """Return an L2POP compatible dictionary of FDB entries.

        If network_id is specified then the DB query is constrained to only
        those devices that are associated to that network_id.
        """
        if bgpvpns is None:
            filters = {'bgpvpn_type': [constants.BGPVPN_L2]}
            bgpvpns = self.bgpvpn_db.get_bgpvpns(context, filters=filters)
        fdb_entries = {}
        for bgpvpn in bgpvpns:
            bgpvpn_id = bgpvpn['id']
            network_id = bgpvpn.get('network_id')
            network = self._get_network(context, bgpvpn_id, network_id)
            if network is None:
                continue  # No network associated to this bgpvpn
            fdb = self._get_network_fdb_entries(context, network, bgpvpn_id)
            fdb_entries.update(fdb)
        return fdb_entries

    @classmethod
    def _merge_fdb_entries(cls, fdb_entries, new_entries):
        """Merge the BGPVPN FDB entries with the L2POP FDB entries.

        In theory, there should be no overlap in the list of VTEP IP
        addresses in each list so this should just be a matter of adding
        learned VTEP IP addresses to the existing list.  Also, the segment
        information should be the same for all networks so we are just going
        to assume that it is included in the incoming FDB entries.
        """
        for network_id, entries in six.iteritems(new_entries):
            if network_id not in fdb_entries:
                fdb_entries[network_id] = entries
            else:
                fdb_ports = fdb_entries[network_id]['ports']
                ports = entries['ports']
                for gateway_ip, port_list in six.iteritems(ports):
                    if gateway_ip not in fdb_ports:
                        fdb_ports[gateway_ip] = port_list
                    else:
                        fdb_ports[gateway_ip].extend(port_list)
        return fdb_entries

    @classmethod
    def _subtract_fdb_entries(cls, a, b):
        """Subtract two sets of FDB records.

        Any data that is in 'a' and not in 'b' is maintained.
        Any data that is in 'b' and not in 'a' is ignored.
        Any data that is in both 'a' and 'b' is removed.
        """
        diff = copy.deepcopy(a)
        for network_id in a.keys():
            if network_id not in b:
                # not present in b so keep all related data
                continue

            vtep_ports = diff[network_id]['ports']
            b_vtep_ports = b[network_id]['ports']
            for gateway_ip, ports in six.iteritems(copy.deepcopy(vtep_ports)):
                if gateway_ip not in b_vtep_ports:
                    # not present in b so keep all related data
                    continue
                diff_ports = set(ports) - set(b_vtep_ports[gateway_ip])
                if not diff_ports:
                    del vtep_ports[gateway_ip]
                else:
                    vtep_ports[gateway_ip] = list(diff_ports)
            if not vtep_ports:
                # if there are no more ports drop the network from the fdb
                del diff[network_id]
        return diff

    @classmethod
    def _diff_fdb_entries(cls, current, previous):
        """Compare two sets of FDB entries and produce a delta.

        The delta is returned as two separated sets of FDB entries; one
        representing entries that must be deleted and the other representing
        those that must be added.
        """
        inserts = cls._subtract_fdb_entries(current, previous)
        removes = cls._subtract_fdb_entries(previous, current)
        return inserts, removes

    def bgpvpn_fdb_extend_func(self, context, network_id, fdb_entries,
                               exclude_host=None):
        entries = fdb_entries[network_id]
        if entries['network_type'] != plugin_constants.TYPE_VXLAN:
            return fdb_entries
        bgpvpns = self.bgpvpn_db.find_bgpvpns_for_network(
            context, network_id, bgpvpn_type=constants.BGPVPN_L2)
        bgp_entries = self._get_fdb_entries(context, bgpvpns=bgpvpns)
        LOG.debug("merging BGP entries {} into FDB {}".format(
            bgp_entries, fdb_entries))
        return self._merge_fdb_entries(fdb_entries, bgp_entries)

    def register_callbacks(self):
        # Extend any FDB records with data received from BGP
        l2pop_driver.register_fdb_extend_func(
            constants.BGPVPN, self.bgpvpn_fdb_extend_func)

    def host_updated(self, context, host):
        """Handle host state change events.

        If a host goes down then we need to purge all learned records from
        any speakers running on that host.
        """
        LOG.debug("host_updated {}".format(host))
        if host['availability'] != n_const.HOST_DOWN:
            LOG.debug("Ignoring host state change: {}".format(host))
            return  # ignore other state changes
        filters = {'agent_type': [dr_constants.AGENT_TYPE_BGP_ROUTING],
                   'host': [host['name']]}
        agents = self.core_plugin.get_agents(context, filters=filters)
        for agent in agents:
            agent['admin_state_up'] = False
            self.agent_updated(context, agent)

    def _handle_agent_down(self, context, agent):
        """Push a new FDB to compute nodes based a disabled agent.

        In order to push a change set down to compute nodes we need to
        compute the difference between the current view and the view after
        the change is applied to the database.
        """
        LOG.warning("Deleting data learned from agent {}/{}".format(
            agent['host'], agent['id']))
        with context.session.begin(subtransactions=True):
            previous = self._get_fdb_entries(context)
            # Remove all records related to this agent
            self.bgpvpn_db.delete_bgpvpn_devices(context, agent['id'])
            self.bgpvpn_db.delete_bgpvpn_gateways(context, agent['id'])
            current = self._get_fdb_entries(context)
            return self._diff_fdb_entries(current, previous)

    def _handle_agent_updated(self, context, agent):
        """Push a new FDB to compute nodes based on the agent state change.

        In order to push a change set down to compute nodes we need to
        compute the difference between the current view and the view after
        any stale records are removed from the database.
        """
        if 'start_flag' in agent:
            # Allow the agent to run and reach its next report interval
            # before looking for any stale entries attributed to this agent.
            return {}, {}
        with context.session.begin(subtransactions=True):
            agent = self.core_plugin.get_agent(context, agent['id'])
            stale_gateways = self.bgpvpn_db.get_bgpvpn_stale_gateways(
                context, agent['id'], agent['started_at'])
            if not stale_gateways:
                stale_devices = self.bgpvpn_db.get_bgpvpn_stale_devices(
                    context, agent['id'], agent['started_at'])
                if not stale_devices:
                    return {}, {}  # no action required
            previous = self._get_fdb_entries(context)
            # Remove all records related to this agent
            LOG.warning("Deleting stale data from agent {}/{}".format(
                agent['host'], agent['id']))
            count = self.bgpvpn_db.delete_bgpvpn_stale_devices(
                context, agent['id'], agent['started_at'])
            LOG.warning("Deleted {} device records from agent {}".
                        format(count or 0, agent['id']))
            count = self.bgpvpn_db.delete_bgpvpn_stale_gateways(
                context, agent['id'], agent['started_at'])
            LOG.warning("Deleted {} gateway records from agent {}".
                        format(count or 0, agent['id']))
            current = self._get_fdb_entries(context)
            return self._diff_fdb_entries(current, previous)

    def agent_updated(self, context, agent):
        """Handle agent state change events.

        If an agent goes down then we need to purge all learned records from
        any speakers associated to that agent.
        """
        if agent['agent_type'] != dr_constants.AGENT_TYPE_BGP_ROUTING:
            return  # ignore all other agents
        LOG.debug("agent_updated {}".format(agent))
        if agent.get('admin_state_up', True):
            inserts, removes = self._handle_agent_updated(context, agent)
        else:
            inserts, removes = self._handle_agent_down(context, agent)

        if not removes and not inserts:
            LOG.debug("no FDB changes to distribute from agent at {}".format(
                agent['host']))
        # Push latest changes down to compute nodes.
        if removes:
            removes['source'] = constants.BGPVPN
            self.l2_notifier.remove_fdb_entries(context, removes)
        if inserts:
            inserts['source'] = constants.BGPVPN
            self.l2_notifier.add_fdb_entries(context, inserts)

    def _deactivate_bgpvpn(self, context, bgpvpn_id, network_id=None):
        # NOTE(alegacy): fill in a fake bgpvpn dict with the id value set so
        # that the get_fdb_entries method can avoid the DB lookup.  Also,
        # if the network_id is provided then pass that in as well so that
        # the network DB lookup can work even when the network association
        # has already been deleted.
        bgpvpns = [{'id': bgpvpn_id, 'network_id': network_id}]
        fdb_removes = self._get_fdb_entries(context, bgpvpns=bgpvpns)
        if fdb_removes:
            fdb_removes['source'] = constants.BGPVPN
            self.l2_notifier.remove_fdb_entries(context, fdb_removes)
        self.bgpvpn_db.delete_bgpvpn_gateways(context, bgpvpn_id=bgpvpn_id)

    def delete_bgpvpn_speaker_assoc(self, context, bgpvpn_id):
        """Handle disassociated a VPN from a speaker.

        This will get called whenever a speaker-to-bpvpn association is
        deleted directly, or if the speaker is deleted and the association
        is deleted via a cascade event.  For now we only support a single
        association from a vpn to a speaker therefore we can remove all
        entries related to the vpn from the database and push those changes
        down to compute nodes.
        """
        self._deactivate_bgpvpn(context, bgpvpn_id)
