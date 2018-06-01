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

import abc

import six

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper

from neutron_lib.api.definitions import bgpvpn as bgpvpn_def
from neutron_lib.api import extensions as api_extensions
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services import base as libbase

from oslo_log import log

from networking_bgpvpn._i18n import _

from networking_bgpvpn.neutron import extensions as bgpvpn_ext

LOG = log.getLogger(__name__)


extensions.append_api_extensions_path(bgpvpn_ext.__path__)


class BGPVPNNotFound(n_exc.NotFound):
    message = _("BGPVPN %(id)s could not be found")


class BGPVPNNetAssocNotFound(n_exc.NotFound):
    message = _("BGPVPN network association %(id)s could not be found "
                "for BGPVPN %(bgpvpn_id)s")


class BGPVPNRouterAssocNotFound(n_exc.NotFound):
    message = _("BGPVPN router association %(id)s could not be found "
                "for BGPVPN %(bgpvpn_id)s")


class BGPVPNTypeNotSupported(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support %(type)s type")


class BGPVPNRDNotSupported(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support to manually set "
                "route distinguisher")


class BGPVPNVNINotSupported(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support to manually set "
                "vni")


class BGPVPNVNIAlreadyInUse(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support duplicate VNI "
                "values")


class BGPVPNFindFromNetNotSupported(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support to fetch BGPVPNs "
                "associated to network id %(net_id)")


class BGPVPNNetAssocAlreadyExists(n_exc.BadRequest):
    message = _("network %(net_id)s is already associated to "
                "BGPVPN %(bgpvpn_id)s")


class BGPVPNNetAssocNotSupportedForType(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support %(type)s VPN "
                "associations to networks")


class BGPVPNRouterAssocNotSupportedForType(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support %(type)s VPN "
                "associations to routers")


class BGPVPNRouterAssociationNotSupported(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support router "
                "associations")


class BGPVPNRouterAssocAlreadyExists(n_exc.BadRequest):
    message = _("router %(router_id)s is already associated to "
                "BGPVPN %(bgpvpn_id)s")


class BGPVPNMultipleRouterAssocNotSupported(n_exc.BadRequest):
    message = _("BGPVPN %(driver)s driver does not support multiple "
                "router association with a bgpvpn")


class BGPVPNNetworkAssocExistsAnotherBgpvpn(n_exc.BadRequest):
    message = _("Network %(network)s already associated with %(bgpvpn)s. "
                "BGPVPN %(driver)s driver does not support same network"
                " associated to multiple bgpvpns")


class BGPVPNDriverError(n_exc.NeutronException):
    message = _("%(method)s failed.")


class Bgpvpn(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return bgpvpn_def.NAME

    @classmethod
    def get_alias(cls):
        return bgpvpn_def.ALIAS

    @classmethod
    def get_description(cls):
        return bgpvpn_def.DESCRIPTION

    @classmethod
    def get_updated(cls):
        return bgpvpn_def.UPDATED_TIMESTAMP

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, bgpvpn_def.RESOURCE_ATTRIBUTE_MAP)
        resources = resource_helper.build_resource_info(
            plural_mappings,
            bgpvpn_def.RESOURCE_ATTRIBUTE_MAP,
            bgpvpn_def.LABEL,
            register_quota=True,
            translate_name=True)
        plugin = directory.get_plugin(bgpvpn_def.LABEL)
        for collection_name in bgpvpn_def.SUB_RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for sub-resources with 'y' ending
            # (e.g. proxies -> proxy)
            resource_name = collection_name[:-1]
            parent = bgpvpn_def.SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].\
                get('parent')
            params = bgpvpn_def.SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].\
                get('parameters')

            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent,
                                              allow_pagination=True,
                                              allow_sorting=True)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                path_prefix='bgpvpn',
                attr_map=params)
            resources.append(resource)
        return resources

    @classmethod
    def get_plugin_interface(cls):
        return BGPVPNPluginBase

    def update_attributes_map(self, attributes):
        super(Bgpvpn, self).update_attributes_map(
            attributes, extension_attrs_map=bgpvpn_def.RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return bgpvpn_def.RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class BGPVPNPluginBase(libbase.ServicePluginBase):

    def get_plugin_name(self):
        return bgpvpn_def.LABEL

    def get_plugin_type(self):
        return bgpvpn_def.LABEL

    def get_plugin_description(self):
        return 'BGP VPN Interconnection service plugin'

    @abc.abstractmethod
    def create_bgpvpn(self, context, bgpvpn):
        pass

    @abc.abstractmethod
    def get_bgpvpns(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_bgpvpn(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def update_bgpvpn(self, context, id, bgpvpn):
        pass

    @abc.abstractmethod
    def delete_bgpvpn(self, context, id):
        pass

    @abc.abstractmethod
    def create_bgpvpn_network_association(self, context, bgpvpn_id,
                                          network_association):
        pass

    @abc.abstractmethod
    def get_bgpvpn_network_association(self, context, assoc_id, bgpvpn_id,
                                       fields=None):
        pass

    @abc.abstractmethod
    def get_bgpvpn_network_associations(self, context, bgpvpn_id,
                                        filters=None, fields=None):
        pass

    @abc.abstractmethod
    def update_bgpvpn_network_association(self, context, assoc_id, bgpvpn_id,
                                          network_association):
        pass

    @abc.abstractmethod
    def delete_bgpvpn_network_association(self, context, assoc_id, bgpvpn_id):
        pass

    @abc.abstractmethod
    def create_bgpvpn_router_association(self, context, bgpvpn_id,
                                         router_association):
        pass

    @abc.abstractmethod
    def get_bgpvpn_router_association(self, context, assoc_id, bgpvpn_id,
                                      fields=None):
        pass

    @abc.abstractmethod
    def get_bgpvpn_router_associations(self, context, bgpvpn_id, filters=None,
                                       fields=None):
        pass

    @abc.abstractmethod
    def delete_bgpvpn_router_association(self, context, assoc_id, bgpvpn_id):
        pass

    @abc.abstractmethod
    def get_bgpvpn_learned_gateways(self, context, bgpvpn_id, filters=None,
                                    fields=None):
        pass

    @abc.abstractmethod
    def get_bgpvpn_active_gateways(self, context, bgpvpn_id, filters=None,
                                   fields=None):
        pass

    @abc.abstractmethod
    def get_bgpvpn_learned_devices(self, context, bgpvpn_id, filters=None,
                                   fields=None):
        pass

    @abc.abstractmethod
    def get_bgpvpn_active_devices(self, context, bgpvpn_id, filters=None,
                                  fields=None):
        pass
