# Copyright (c) 2015 Orange.
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

from neutron.callbacks import resources as n_resources
from neutron.db import servicetype_db as st_db
from neutron.plugins.common import constants as p_const
from neutron.services import provider_configuration as pconf
from neutron.services import service_base

from neutron_lib.api.definitions import bgpvpn as bgpvpn_def
from neutron_lib.api.definitions import provider_net as provider
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from neutron_dynamic_routing.api.rpc.callbacks import resources as dr_resources

from oslo_log import log

from networking_bgpvpn._i18n import _

from networking_bgpvpn.neutron.extensions import bgpvpn
from networking_bgpvpn.neutron.services.common import constants

LOG = log.getLogger(__name__)


class BGPVPNPlugin(bgpvpn.BGPVPNPluginBase):
    supported_extension_aliases = ["bgpvpn"]
    path_prefix = "/bgpvpn"

    def __init__(self):
        super(BGPVPNPlugin, self).__init__()

        # Need to look into /etc/neutron/networking_bgpvpn.conf for
        # service_provider definitions:
        service_type_manager = st_db.ServiceTypeManager.get_instance()
        service_type_manager.add_provider_configuration(
            bgpvpn_def.LABEL,
            pconf.ProviderConfiguration('networking_bgpvpn'))

        # Load the default driver
        drivers, default_provider = service_base.load_drivers(bgpvpn_def.LABEL,
                                                              self)
        LOG.info("BGP VPN Service Plugin using Service Driver: %s",
                 default_provider)
        self.driver = drivers[default_provider]

        if len(drivers) > 1:
            LOG.warning("Multiple drivers configured for BGPVPN, although"
                        "running multiple drivers in parallel is not yet"
                        "supported")
        registry.subscribe(self._notify_adding_interface_to_router,
                           resources.ROUTER_INTERFACE,
                           events.BEFORE_CREATE)
        registry.subscribe(self._notify_host_updated,
                           n_resources.HOST, events.AFTER_UPDATE)
        registry.subscribe(self._notify_agent_updated,
                           resources.AGENT, events.AFTER_UPDATE)
        registry.subscribe(self._notify_removing_vpn_from_speaker,
                           dr_resources.BGP_SPEAKER_VPN_ASSOC,
                           events.AFTER_DELETE)

    def get_workers(self):
        if hasattr(self.driver, 'get_workers'):
            return self.driver.get_workers()
        return []

    def _notify_host_updated(self, resource, event, trigger, **kwargs):
        context = kwargs.get('context')
        self.driver.host_updated(context, kwargs['host'])

    def _notify_agent_updated(self, resource, event, trigger, **kwargs):
        context = kwargs.get('context')
        self.driver.agent_updated(context, kwargs['agent'])

    def _notify_removing_vpn_from_speaker(self, resource, event, trigger,
                                          **kwargs):
        context = kwargs.get('context')
        self.driver.delete_bgpvpn_speaker_assoc(context, kwargs['bgpvpn_id'])

    def _notify_adding_interface_to_router(self, resource, event, trigger,
                                           **kwargs):
        context = kwargs.get('context')
        network_id = kwargs.get('network_id')
        router_id = kwargs.get('router_id')
        try:
            routers_bgpvpns = self.driver.get_bgpvpns(
                context,
                filters={
                    'routers': [router_id],
                },
            )
        except bgpvpn.BGPVPNRouterAssociationNotSupported:
            return
        nets_bgpvpns = self.driver.get_bgpvpns(
            context,
            filters={
                'networks': [network_id],
                'type': [constants.BGPVPN_L3],
            },
        )

        if routers_bgpvpns and nets_bgpvpns:
            msg = _('It is not allowed to add an interface to a router if '
                    'both the router and the network are bound to an '
                    'L3 BGPVPN.')
            raise n_exc.BadRequest(resource='bgpvpn', msg=msg)

    def _validate_network(self, context, net_id):
        plugin = directory.get_plugin()
        network = plugin.get_network(context, net_id)
        self._validate_network_has_router_assoc(context, network, plugin)
        return network

    def _validate_network_has_router_assoc(self, context, network, plugin):
        filter = {'network_id': [network['id']],
                  'device_owner': [const.DEVICE_OWNER_ROUTER_INTF]}
        router_port = plugin.get_ports(context, filters=filter)
        if router_port:
            router_id = router_port[0]['device_id']
            filter = {'tenant_id': [network['tenant_id']]}
            bgpvpns = self.driver.get_bgpvpns(context, filters=filter)
            bgpvpns = [str(bgpvpn['id']) for bgpvpn in bgpvpns
                       if router_id in bgpvpn['routers']]
            if bgpvpns:
                msg = ('Network %(net_id)s is linked to a router which is '
                       'already associated to bgpvpn(s) %(bgpvpns)s'
                       % {'net_id': network['id'],
                          'bgpvpns': bgpvpns}
                       )
                raise n_exc.BadRequest(resource='bgpvpn', msg=msg)

    def _validate_router(self, context, router_id):
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        router = l3_plugin.get_router(context, router_id)
        plugin = directory.get_plugin()
        self._validate_router_has_net_assocs(context, router, plugin)
        return router

    def _validate_router_has_net_assocs(self, context, router, plugin):
        filter = {'device_id': [router['id']],
                  'device_owner': [const.DEVICE_OWNER_ROUTER_INTF]}
        router_ports = plugin.get_ports(context, filters=filter)
        if router_ports:
            filter = {'tenant_id': [router['tenant_id']]}
            bgpvpns = self.driver.get_bgpvpns(context, filters=filter)
            for port in router_ports:
                bgpvpns = [str(bgpvpn['id']) for bgpvpn in bgpvpns
                           if port['network_id'] in bgpvpn['networks']]
                if bgpvpns:
                    msg = ('router %(rtr_id)s has an attached network '
                           '%(net_id)s which is already associated to '
                           'bgpvpn(s) %(bgpvpns)s'
                           % {'rtr_id': router['id'],
                              'net_id': port['network_id'],
                              'bgpvpns': bgpvpns})
                    raise n_exc.BadRequest(resource='bgpvpn', msg=msg)

    def get_plugin_type(self):
        return bgpvpn_def.LABEL

    def get_plugin_description(self):
        return "Neutron BGPVPN Service Plugin"

    def create_bgpvpn(self, context, bgpvpn):
        bgpvpn = bgpvpn['bgpvpn']
        return self.driver.create_bgpvpn(context, bgpvpn)

    def get_bgpvpns(self, context, filters=None, fields=None):
        return self.driver.get_bgpvpns(context, filters, fields)

    def get_bgpvpn(self, context, id, fields=None):
        return self.driver.get_bgpvpn(context, id, fields)

    def update_bgpvpn(self, context, id, bgpvpn):
        bgpvpn = bgpvpn['bgpvpn']
        return self.driver.update_bgpvpn(context, id, bgpvpn)

    def delete_bgpvpn(self, context, id):
        self.driver.delete_bgpvpn(context, id)

    def _validate_network_type_and_vni(self, network, bgpvpn):
        if provider.NETWORK_TYPE not in network:
            # NOTE(alegacy): the unit tests for this module do not inherit
            # from the ml2 plugin therefore the network is not augmented
            # with the provider network information
            return
        if network[provider.NETWORK_TYPE] != p_const.TYPE_VXLAN:
            msg = 'l2 bgpvpn can only be associated to a vxlan network'
            raise n_exc.BadRequest(resource='bgpvpn', msg=msg)
        if network[provider.SEGMENTATION_ID] != bgpvpn['vni']:
            msg = 'vni value of bgpvpn and network must match'
            raise n_exc.BadRequest(resource='bgpvpn', msg=msg)

    def create_bgpvpn_network_association(self, context, bgpvpn_id,
                                          network_association):
        net_assoc = network_association['network_association']
        # check net exists
        net = self._validate_network(context, net_assoc['network_id'])
        # check every resource belong to the same tenant
        bgpvpn = self.get_bgpvpn(context, bgpvpn_id)
        if net['tenant_id'] != bgpvpn['tenant_id']:
            msg = 'network doesn\'t belong to the bgpvpn owner'
            raise n_exc.NotAuthorized(resource='bgpvpn', msg=msg)
        if net_assoc['tenant_id'] != bgpvpn['tenant_id']:
            msg = 'network association and bgpvpn should belong to\
                the same tenant'
            raise n_exc.NotAuthorized(resource='bgpvpn', msg=msg)
        if bgpvpn['type'] == constants.BGPVPN_L2:
            self._validate_network_type_and_vni(net, bgpvpn)
        return self.driver.create_net_assoc(context, bgpvpn_id, net_assoc)

    def get_bgpvpn_network_association(self, context, assoc_id, bgpvpn_id,
                                       fields=None):
        return self.driver.get_net_assoc(context, assoc_id, bgpvpn_id, fields)

    def get_bgpvpn_network_associations(self, context, bgpvpn_id,
                                        filters=None, fields=None):
        return self.driver.get_net_assocs(context, bgpvpn_id, filters, fields)

    def update_bgpvpn_network_association(self, context, assoc_id, bgpvpn_id,
                                          network_association):
        # TODO(matrohon) : raise an unsuppported error
        pass

    def delete_bgpvpn_network_association(self, context, assoc_id, bgpvpn_id):
        self.driver.delete_net_assoc(context, assoc_id, bgpvpn_id)

    def create_bgpvpn_router_association(self, context, bgpvpn_id,
                                         router_association):
        router_assoc = router_association['router_association']
        router = self._validate_router(context, router_assoc['router_id'])
        bgpvpn = self.get_bgpvpn(context, bgpvpn_id)
        if not bgpvpn['type'] == constants.BGPVPN_L3:
            msg = ("Router associations require the bgpvpn to be of type %s"
                   % constants.BGPVPN_L3)
            raise n_exc.BadRequest(resource='bgpvpn', msg=msg)
        if not router['tenant_id'] == bgpvpn['tenant_id']:
            msg = "router doesn't belong to the bgpvpn owner"
            raise n_exc.NotAuthorized(resource='bgpvpn', msg=msg)
        if not (router_assoc['tenant_id'] == bgpvpn['tenant_id']):
            msg = "router association and bgpvpn should " \
                  "belong to the same tenant"
            raise n_exc.NotAuthorized(resource='bgpvpn', msg=msg)
        return self.driver.create_router_assoc(context, bgpvpn_id,
                                               router_assoc)

    def get_bgpvpn_router_association(self, context, assoc_id, bgpvpn_id,
                                      fields=None):
        return self.driver.get_router_assoc(context, assoc_id, bgpvpn_id,
                                            fields)

    def get_bgpvpn_router_associations(self, context, bgpvpn_id, filters=None,
                                       fields=None):
        return self.driver.get_router_assocs(context, bgpvpn_id, filters,
                                             fields)

    def delete_bgpvpn_router_association(self, context, assoc_id, bgpvpn_id):
        self.driver.delete_router_assoc(context, assoc_id, bgpvpn_id)

    def get_bgpvpn_learned_gateways(self, context, bgpvpn_id, filters=None,
                                    fields=None):
        return self.driver.get_bgpvpn_gateways(
            context, bgpvpn_id, filters=filters, fields=fields)

    def get_bgpvpn_active_gateways(self, context, bgpvpn_id, filters=None,
                                   fields=None):
        return self.driver.get_bgpvpn_active_gateways(
            context, bgpvpn_id, filters=filters, fields=fields)

    def get_bgpvpn_learned_devices(self, context, bgpvpn_id, filters=None,
                                   fields=None):
        return self.driver.get_bgpvpn_devices(
            context, bgpvpn_id, filters=filters, fields=fields)

    def get_bgpvpn_active_devices(self, context, bgpvpn_id, filters=None,
                                  fields=None):
        return self.driver.get_bgpvpn_active_devices(
            context, bgpvpn_id, filters=filters, fields=fields)
