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

import six

from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import timeutils
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import func
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.db import _model_query as model_query
from neutron.db import common_db_mixin

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base

from networking_bgpvpn.neutron.extensions import bgpvpn as bgpvpn_ext
from networking_bgpvpn.neutron.services.common import utils

LOG = log.getLogger(__name__)


class HasProjectNotNullable(model_base.HasProject):

    project_id = sa.Column(sa.String(db_const.PROJECT_ID_FIELD_SIZE),
                           index=True,
                           nullable=False)


class BGPVPNNetAssociation(model_base.BASEV2, model_base.HasId,
                           HasProjectNotNullable):
    """Represents the association between a bgpvpn and a network."""
    __tablename__ = 'bgpvpn_network_associations'

    bgpvpn_id = sa.Column(sa.String(36),
                          sa.ForeignKey('bgpvpns.id', ondelete='CASCADE'),
                          nullable=False)
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'),
                           nullable=False)
    sa.UniqueConstraint(bgpvpn_id, network_id)
    network = orm.relationship("Network",
                               backref=orm.backref('bgpvpn_associations',
                                                   cascade='all'),
                               lazy='joined',)


class BGPVPNRouterAssociation(model_base.BASEV2, model_base.HasId,
                              HasProjectNotNullable):
    """Represents the association between a bgpvpn and a router."""
    __tablename__ = 'bgpvpn_router_associations'

    bgpvpn_id = sa.Column(sa.String(36),
                          sa.ForeignKey('bgpvpns.id', ondelete='CASCADE'),
                          nullable=False)
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete='CASCADE'),
                          nullable=False)
    sa.UniqueConstraint(bgpvpn_id, router_id)
    router = orm.relationship("Router",
                              backref=orm.backref('bgpvpn_associations',
                                                  cascade='all'),
                              lazy='joined',)


class BGPVPN(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    """Represents a BGPVPN Object."""
    name = sa.Column(sa.String(255))
    type = sa.Column(sa.Enum("l2", "l3",
                             name="bgpvpn_type"),
                     nullable=False)
    route_targets = sa.Column(sa.String(255), nullable=False)
    import_targets = sa.Column(sa.String(255), nullable=True)
    export_targets = sa.Column(sa.String(255), nullable=True)
    route_distinguishers = sa.Column(sa.String(255), nullable=True)
    vni = sa.Column(sa.Integer)
    network_associations = orm.relationship("BGPVPNNetAssociation",
                                            backref="bgpvpn",
                                            lazy='select',
                                            cascade='all, delete-orphan')
    router_associations = orm.relationship("BGPVPNRouterAssociation",
                                           backref="bgpvpn",
                                           lazy='select',
                                           cascade='all, delete-orphan')


class BGPVPNLearnedGateway(model_base.BASEV2, model_base.HasId):
    """Represents a VTEP gateway which was imported from a Peer"""
    __tablename__ = 'wrs_bgpvpn_learned_gateways'

    agent_id = sa.Column(sa.String(36),
                         sa.ForeignKey("agents.id", ondelete="CASCADE"),
                         nullable=False)

    bgpvpn_id = sa.Column(sa.String(36),
                          sa.ForeignKey("bgpvpns.id", ondelete="CASCADE"),
                          nullable=False, )

    ip_address = sa.Column(sa.String(64), nullable=False)

    created_at = sa.Column(sa.DateTime, nullable=False)

    updated_at = sa.Column(sa.DateTime, nullable=False)

    sa.UniqueConstraint(agent_id, bgpvpn_id, ip_address,
                        name='unique_vtep0agent0vpn0ip')
    sa.Index('unique_vtep_index', agent_id, bgpvpn_id, ip_address)


class BGPVPNLearnedDevice(model_base.BASEV2, model_base.HasId):
    """Represents a layer2 device which was imported from a Peer"""
    __tablename__ = 'wrs_bgpvpn_learned_devices'

    agent_id = sa.Column(sa.String(36), nullable=False)

    bgpvpn_id = sa.Column(sa.String(36), nullable=False, )

    mac_address = sa.Column(sa.String(20), nullable=False)

    ip_address = sa.Column(sa.String(64), nullable=False)

    gateway_ip = sa.Column(sa.String(64), nullable=False)

    created_at = sa.Column(sa.DateTime, nullable=False)

    updated_at = sa.Column(sa.DateTime, nullable=False)

    sa.ForeignKeyConstraint([agent_id, bgpvpn_id, gateway_ip],
                            ['wrs_bgpvpn_learned_gateways.agent_id',
                             'wrs_bgpvpn_learned_gateways.bgpvpn_id',
                             'wrs_bgpvpn_learned_gateways.ip_address'],
                            name='gateway_fkey0agent@vpn@vtep',
                            ondelete="CASCADE")
    sa.UniqueConstraint(agent_id, bgpvpn_id, mac_address, ip_address,
                        name='unique_device0agent@vpn0mac0ip')
    sa.Index('unique_device_index', agent_id, bgpvpn_id, mac_address,
             ip_address)


def _list_bgpvpns_result_filter_hook(query, filters):
    values = filters and filters.get('networks', [])
    if values:
        query = query.join(BGPVPNNetAssociation)
        query = query.filter(BGPVPNNetAssociation.network_id.in_(values))

    values = filters and filters.get('routers', [])
    if values:
        query = query.join(BGPVPNRouterAssociation)
        query = query.filter(BGPVPNRouterAssociation.router_id.in_(values))

    return query


class BGPVPNPluginDb(common_db_mixin.CommonDbMixin):
    """BGPVPN service plugin database class using SQLAlchemy models."""

    def __new__(cls, *args, **kwargs):
        model_query.register_hook(
            BGPVPN,
            "bgpvpn_filter_by_resource_association",
            query_hook=None,
            filter_hook=None,
            result_filters=_list_bgpvpns_result_filter_hook)
        return super(BGPVPNPluginDb, cls).__new__(cls, *args, **kwargs)

    def _get_bgpvpns_for_tenant(self, session, tenant_id, fields):
        try:
            qry = session.query(BGPVPN)
            bgpvpns = qry.filter_by(tenant_id=tenant_id)
        except exc.NoResultFound:
            return

        return [self._make_bgpvpn_dict(bgpvpn, fields=fields)
                for bgpvpn in bgpvpns]

    def _make_bgpvpn_dict(self, bgpvpn_db, fields=None):
        net_list = [net_assocs.network_id for net_assocs in
                    bgpvpn_db.network_associations]
        router_list = [router_assocs.router_id for router_assocs in
                       bgpvpn_db.router_associations]
        res = {
            'id': bgpvpn_db['id'],
            'tenant_id': bgpvpn_db['tenant_id'],
            'networks': net_list,
            'routers': router_list,
            'name': bgpvpn_db['name'],
            'type': bgpvpn_db['type'],
            'route_targets':
                utils.rtrd_str2list(bgpvpn_db['route_targets']),
            'route_distinguishers':
                utils.rtrd_str2list(bgpvpn_db['route_distinguishers']),
            'import_targets':
                utils.rtrd_str2list(bgpvpn_db['import_targets']),
            'export_targets':
                utils.rtrd_str2list(bgpvpn_db['export_targets']),
            'vni': bgpvpn_db['vni']
        }
        return self._fields(res, fields)

    def create_bgpvpn(self, context, bgpvpn):
        rt = utils.rtrd_list2str(bgpvpn['route_targets'])
        i_rt = utils.rtrd_list2str(bgpvpn['import_targets'])
        e_rt = utils.rtrd_list2str(bgpvpn['export_targets'])
        rd = utils.rtrd_list2str(bgpvpn.get('route_distinguishers', ''))

        with context.session.begin(subtransactions=True):
            bgpvpn_db = BGPVPN(
                id=uuidutils.generate_uuid(),
                tenant_id=bgpvpn['tenant_id'],
                name=bgpvpn['name'],
                type=bgpvpn['type'],
                route_targets=rt,
                import_targets=i_rt,
                export_targets=e_rt,
                route_distinguishers=rd,
                vni=bgpvpn['vni']
            )
            context.session.add(bgpvpn_db)

        return self._make_bgpvpn_dict(bgpvpn_db)

    def get_bgpvpns(self, context, filters=None, fields=None):
        return self._get_collection(context, BGPVPN, self._make_bgpvpn_dict,
                                    filters=filters, fields=fields)

    def _get_bgpvpn(self, context, id):
        try:
            return self._get_by_id(context, BGPVPN, id)
        except exc.NoResultFound:
            raise bgpvpn_ext.BGPVPNNotFound(id=id)

    def get_bgpvpn(self, context, id, fields=None):
        bgpvpn_db = self._get_bgpvpn(context, id)
        return self._make_bgpvpn_dict(bgpvpn_db, fields)

    def update_bgpvpn(self, context, id, bgpvpn):
        with context.session.begin(subtransactions=True):
            bgpvpn_db = self._get_bgpvpn(context, id)
            if bgpvpn:
                # Format Route Target lists to string
                if 'route_targets' in bgpvpn:
                    rt = utils.rtrd_list2str(bgpvpn['route_targets'])
                    bgpvpn['route_targets'] = rt
                if 'import_targets' in bgpvpn:
                    i_rt = utils.rtrd_list2str(bgpvpn['import_targets'])
                    bgpvpn['import_targets'] = i_rt
                if 'export_targets' in bgpvpn:
                    e_rt = utils.rtrd_list2str(bgpvpn['export_targets'])
                    bgpvpn['export_targets'] = e_rt
                if 'route_distinguishers' in bgpvpn:
                    rd = utils.rtrd_list2str(bgpvpn['route_distinguishers'])
                    bgpvpn['route_distinguishers'] = rd
                bgpvpn_db.update(bgpvpn)
        return self._make_bgpvpn_dict(bgpvpn_db)

    def delete_bgpvpn(self, context, id):
        with context.session.begin(subtransactions=True):
            bgpvpn_db = self._get_bgpvpn(context, id)
            bgpvpn = self._make_bgpvpn_dict(bgpvpn_db)
            context.session.delete(bgpvpn_db)
        return bgpvpn

    def find_bgpvpns_for_network(self, context, network_id, bgpvpn_type=None):
        # Note : we could use added backref in the network table
        query = (context.session.query(BGPVPN).
                 join(BGPVPNNetAssociation).
                 filter(BGPVPNNetAssociation.network_id == network_id))
        if bgpvpn_type is not None:
            query = query.filter(BGPVPN.type == bgpvpn_type)
        return [self._make_bgpvpn_dict(bgpvpn) for bgpvpn in query.all()]

    def _make_net_assoc_dict(self, net_assoc_db, fields=None):
        res = {'id': net_assoc_db['id'],
               'tenant_id': net_assoc_db['tenant_id'],
               'bgpvpn_id': net_assoc_db['bgpvpn_id'],
               'network_id': net_assoc_db['network_id']}
        return self._fields(res, fields)

    def _get_net_assoc(self, context, assoc_id, bgpvpn_id):
        try:
            query = self._model_query(context, BGPVPNNetAssociation)
            return query.filter(BGPVPNNetAssociation.id == assoc_id,
                                BGPVPNNetAssociation.bgpvpn_id == bgpvpn_id
                                ).one()
        except exc.NoResultFound:
            raise bgpvpn_ext.BGPVPNNetAssocNotFound(id=assoc_id,
                                                    bgpvpn_id=bgpvpn_id)

    def create_net_assoc(self, context, bgpvpn_id, net_assoc):
        try:
            with context.session.begin(subtransactions=True):
                net_assoc_db = BGPVPNNetAssociation(
                    tenant_id=net_assoc['tenant_id'],
                    bgpvpn_id=bgpvpn_id,
                    network_id=net_assoc['network_id'])
                context.session.add(net_assoc_db)
            return self._make_net_assoc_dict(net_assoc_db)
        except db_exc.DBDuplicateEntry:
            LOG.warning("network %(net_id)s is already associated to "
                        "BGPVPN %(bgpvpn_id)s",
                        {'net_id': net_assoc['network_id'],
                         'bgpvpn_id': bgpvpn_id})
            raise bgpvpn_ext.BGPVPNNetAssocAlreadyExists(
                bgpvpn_id=bgpvpn_id, net_id=net_assoc['network_id'])

    def get_net_assoc(self, context, assoc_id, bgpvpn_id, fields=None):
        net_assoc_db = self._get_net_assoc(context, assoc_id, bgpvpn_id)
        return self._make_net_assoc_dict(net_assoc_db, fields)

    def get_net_assocs(self, context, bgpvpn_id, filters=None, fields=None):
        if not filters:
            filters = {}
        filters['bgpvpn_id'] = [bgpvpn_id]
        return self._get_collection(context, BGPVPNNetAssociation,
                                    self._make_net_assoc_dict,
                                    filters, fields)

    def delete_net_assoc(self, context, assoc_id, bgpvpn_id):
        LOG.info("deleting network association %(id)s for "
                 "BGPVPN %(bgpvpn)s", {'id': assoc_id,
                                       'bgpvpn': bgpvpn_id})
        with context.session.begin(subtransactions=True):
            net_assoc_db = self._get_net_assoc(context, assoc_id, bgpvpn_id)
            net_assoc = self._make_net_assoc_dict(net_assoc_db)
            context.session.delete(net_assoc_db)
        return net_assoc

    def _make_router_assoc_dict(self, router_assoc_db, fields=None):
        res = {'id': router_assoc_db['id'],
               'tenant_id': router_assoc_db['tenant_id'],
               'bgpvpn_id': router_assoc_db['bgpvpn_id'],
               'router_id': router_assoc_db['router_id']}
        return self._fields(res, fields)

    def _get_router_assoc(self, context, assoc_id, bgpvpn_id):
        try:
            query = self._model_query(context, BGPVPNRouterAssociation)
            return query.filter(BGPVPNRouterAssociation.id == assoc_id,
                                BGPVPNRouterAssociation.bgpvpn_id == bgpvpn_id
                                ).one()
        except exc.NoResultFound:
            raise bgpvpn_ext.BGPVPNRouterAssocNotFound(id=assoc_id,
                                                       bgpvpn_id=bgpvpn_id)

    def create_router_assoc(self, context, bgpvpn_id, router_association):
        router_id = router_association['router_id']
        try:
            with context.session.begin(subtransactions=True):
                router_assoc_db = BGPVPNRouterAssociation(
                    tenant_id=router_association['tenant_id'],
                    bgpvpn_id=bgpvpn_id,
                    router_id=router_id)
                context.session.add(router_assoc_db)
            return self._make_router_assoc_dict(router_assoc_db)
        except db_exc.DBDuplicateEntry:
            LOG.warning("router %(router_id)s is already associated to "
                        "BGPVPN %(bgpvpn_id)s",
                        {'router_id': router_id,
                         'bgpvpn_id': bgpvpn_id})
            raise bgpvpn_ext.BGPVPNRouterAssocAlreadyExists(
                bgpvpn_id=bgpvpn_id, router_id=router_association['router_id'])

    def get_router_assoc(self, context, assoc_id, bgpvpn_id, fields=None):
        router_assoc_db = self._get_router_assoc(context, assoc_id, bgpvpn_id)
        return self._make_router_assoc_dict(router_assoc_db, fields)

    def get_router_assocs(self, context, bgpvpn_id, filters=None, fields=None):
        if not filters:
            filters = {}
        filters['bgpvpn_id'] = [bgpvpn_id]
        return self._get_collection(context, BGPVPNRouterAssociation,
                                    self._make_router_assoc_dict,
                                    filters, fields)

    def delete_router_assoc(self, context, assoc_id, bgpvpn_id):
        LOG.info("deleting router association %(id)s for "
                 "BGPVPN %(bgpvpn)s",
                 {'id': assoc_id, 'bgpvpn': bgpvpn_id})
        with context.session.begin(subtransactions=True):
            router_assoc_db = self._get_router_assoc(context, assoc_id,
                                                     bgpvpn_id)
            router_assoc = self._make_router_assoc_dict(router_assoc_db)
            context.session.delete(router_assoc_db)
        return router_assoc

    def _make_bgpvpn_gateway_dict(self, bgpvpn_gateway_db, fields=None):
        res = {'id': bgpvpn_gateway_db['id'],
               'agent_id': bgpvpn_gateway_db['agent_id'],
               'bgpvpn_id': bgpvpn_gateway_db['bgpvpn_id'],
               'ip_address': bgpvpn_gateway_db['ip_address'],
               'updated_at': bgpvpn_gateway_db['updated_at']}
        return self._fields(res, fields)

    @staticmethod
    def _get_bgpvpn_gateway(context, agent_id, bgpvpn_id, ip_address):
        query = (context.session.query(BGPVPNLearnedGateway).
                 filter(BGPVPNLearnedGateway.agent_id == agent_id).
                 filter(BGPVPNLearnedGateway.bgpvpn_id == bgpvpn_id).
                 filter(BGPVPNLearnedGateway.ip_address == ip_address))
        return query.one()

    @staticmethod
    def _apply_filters(model, query, filters=None):
        """Apply filters to the query.

        Unlike _apply_filters_to_query this method will only use the in_
        operator if the filter value is a list; otherwise a direct
        comparison is used instead.
        """
        for key, value in six.iteritems(filters or {}):
            if value is None:
                continue
            column = getattr(model, key, None)
            if column is not None:
                if isinstance(value, list):
                    query = query.filter(column.in_(value))
                else:
                    query = query.filter(column == value)
        return query

    @classmethod
    def _get_bgpvpn_gateway_query(cls, context, filters=None):
        query = (context.session.query(BGPVPNLearnedGateway))
        query = cls._apply_filters(BGPVPNLearnedGateway, query,
                                   filters=filters)
        return query

    def _get_bgpvpn_gateways(self, context, filters=None):
        query = self._get_bgpvpn_gateway_query(context, filters=filters)
        return query.all()

    def get_bgpvpn_gateway(self, context, agent_id, bgpvpn_id, ip_address,
                           fields=None):
        try:
            bgpvpn_gateway_db = self._get_bgpvpn_gateway(
                context, agent_id, bgpvpn_id, ip_address)
            return self._make_bgpvpn_gateway_dict(
                bgpvpn_gateway_db, fields=fields)
        except exc.NoResultFound:
            return

    def get_bgpvpn_gateways(self, context, bgpvpn_id, filters=None,
                            fields=None):
        filters = filters or {}
        filters.update({'bgpvpn_id': bgpvpn_id})
        gateways = self._get_bgpvpn_gateways(context, filters=filters)
        return [self._make_bgpvpn_gateway_dict(g, fields=fields)
                for g in gateways]

    def get_bgpvpn_stale_gateways(self, context, agent_id, timestamp):
        """Retrieve records that have not been updated since last restart."""
        filters = {'agent_id': agent_id}
        query = self._get_bgpvpn_gateway_query(context, filters=filters)
        query = query.filter(BGPVPNLearnedGateway.updated_at < timestamp)
        return [self._make_bgpvpn_gateway_dict(g) for g in query.all()]

    def delete_bgpvpn_stale_gateways(self, context, agent_id, timestamp):
        """Delete records that have not been updated since last restart."""
        try:
            filters = {'agent_id': agent_id}
            query = self._get_bgpvpn_gateway_query(context, filters=filters)
            query = query.filter(BGPVPNLearnedGateway.updated_at < timestamp)
            return query.delete()
        except exc.NoResultFound:
            return

    @classmethod
    def _get_bgpvpn_active_gateways(cls, context, filters=None):
        """This function returns active gateways entries.

        Since we can learn gateway information from behind multiple agents
        we need to reduce this list down to one entry per gateway ip
        address; otherwise we'll duplicate the information distributed
        internally. This is similar to how the RYU driver selects a "best"
        route and does not tell us about other potential routes for any
        given mac + ip pair until those routes become the best/only option.

        This is done with a where clause which leverages a subquery.  The
        purpose of the subquery is to find the oldest timestamp for any
        given gateway ip address.

        That subquery is then used in another query to filter results based
        on the selected timestamp for each gateway.  It cannot be done in a
        single statement using DISTINCT because that will not allow
        returning columns unrelated to the distinct criteria.  For example,
        you can say "distinct ip" but that will only make the ip column
        available.  If you also want "agent_id" then you need to add it to
        the distinct set and since we could learn the same gateway ip from 2
        different from different agents we'd end up with both records which
        is not what we want.
        """
        # Build the subquery
        s = (context.session.query(
            BGPVPNLearnedGateway.bgpvpn_id,
            BGPVPNLearnedGateway.ip_address,
            func.min(BGPVPNLearnedGateway.updated_at).label('date')))
        s = cls._apply_filters(BGPVPNLearnedGateway, s, filters=filters)
        s = (s.group_by(BGPVPNLearnedGateway.bgpvpn_id,
                        BGPVPNLearnedGateway.ip_address).subquery('s'))
        # Build the main query
        query = (context.session.query(BGPVPNLearnedGateway).
                 filter(BGPVPNLearnedGateway.bgpvpn_id == s.c.bgpvpn_id).
                 filter(BGPVPNLearnedGateway.ip_address == s.c.ip_address).
                 filter(BGPVPNLearnedGateway.updated_at == s.c.date))
        query = cls._apply_filters(BGPVPNLearnedGateway, query,
                                   filters=filters)
        return query.all()

    def get_bgpvpn_active_gateways(self, context, bgpvpn_id,
                                   filters=None, fields=None):
        filters = filters or {}
        filters.update({'bgpvpn_id': bgpvpn_id})
        gateways = self._get_bgpvpn_active_gateways(context, filters=filters)
        return [self._make_bgpvpn_gateway_dict(g, fields=fields)
                for g in gateways]

    def create_bgpvpn_gateway(self, context, agent_id, bgpvpn_id, ip_address):
        with context.session.begin(subtransactions=True):
            now = timeutils.utcnow()
            bgpvpn_gateway_db = BGPVPNLearnedGateway(
                id=uuidutils.generate_uuid(),
                agent_id=agent_id,
                bgpvpn_id=bgpvpn_id,
                ip_address=ip_address,
                created_at=now,
                updated_at=now)
            context.session.add(bgpvpn_gateway_db)
        return self._make_bgpvpn_gateway_dict(bgpvpn_gateway_db)

    def update_bgpvpn_gateway(self, context, agent_id, bgpvpn_id, ip_address):
        with context.session.begin(subtransactions=True):
            try:
                bgpvpn_gateway_db = self._get_bgpvpn_gateway(
                    context, agent_id, bgpvpn_id, ip_address)
                updates = {'updated_at': timeutils.utcnow()}
                bgpvpn_gateway_db.update(updates)
                return self._make_bgpvpn_gateway_dict(bgpvpn_gateway_db)
            except exc.NoResultFound:
                return self.create_bgpvpn_gateway(
                    context, agent_id, bgpvpn_id, ip_address)

    def delete_bgpvpn_gateway(self, context, agent_id, bgpvpn_id, ip_address):
        with context.session.begin(subtransactions=True):
            try:
                bgpvpn_gateway_db = self._get_bgpvpn_gateway(
                    context, agent_id, bgpvpn_id, ip_address)
                bgpvpn_gateway = self._make_bgpvpn_gateway_dict(
                    bgpvpn_gateway_db)
                context.session.delete(bgpvpn_gateway_db)
                return bgpvpn_gateway
            except exc.NoResultFound:
                return

    def delete_bgpvpn_gateways(self, context, agent_id=None, bgpvpn_id=None):
        """Bulk delete any VTEP records matching the specified criteria."""
        with context.session.begin(subtransactions=True):
            try:
                filters = {}
                if agent_id is not None:
                    filters['agent_id'] = agent_id
                if bgpvpn_id is not None:
                    filters['bgpvpn_id'] = bgpvpn_id
                query = self._get_bgpvpn_gateway_query(
                    context, filters=filters)
                return query.delete()
            except exc.NoResultFound:
                return

    def _make_bgpvpn_device_dict(self, bgpvpn_device_db, fields=None):
        res = {'id': bgpvpn_device_db['id'],
               'agent_id': bgpvpn_device_db['agent_id'],
               'bgpvpn_id': bgpvpn_device_db['bgpvpn_id'],
               'mac_address': bgpvpn_device_db['mac_address'],
               'ip_address': bgpvpn_device_db['ip_address'],
               'gateway_ip': bgpvpn_device_db['gateway_ip'],
               'updated_at': bgpvpn_device_db['updated_at']}
        return self._fields(res, fields)

    @staticmethod
    def _get_bgpvpn_device(context, agent_id, bgpvpn_id, mac_address,
                           ip_address):
        query = (context.session.query(BGPVPNLearnedDevice).
                 filter(BGPVPNLearnedDevice.agent_id == agent_id).
                 filter(BGPVPNLearnedDevice.bgpvpn_id == bgpvpn_id).
                 filter(BGPVPNLearnedDevice.mac_address == mac_address).
                 filter(BGPVPNLearnedDevice.ip_address == ip_address))
        return query.one()

    def get_bgpvpn_device(self, context, agent_id, bgpvpn_id, mac_address,
                          ip_address, fields=None):
        try:
            bgpvpn_device_db = self._get_bgpvpn_device(
                context, agent_id, bgpvpn_id, mac_address, ip_address)
            return self._make_bgpvpn_device_dict(bgpvpn_device_db,
                                                 fields=fields)
        except exc.NoResultFound:
            return

    def get_bgpvpn_stale_devices(self, context, agent_id, timestamp):
        """Retrieve records that have not been updated since last restart."""
        filters = {'agent_id': agent_id}
        query = self._get_bgpvpn_devices_query(context, filters=filters)
        query = query.filter(BGPVPNLearnedDevice.updated_at < timestamp)
        return [self._make_bgpvpn_device_dict(d) for d in query.all()]

    def delete_bgpvpn_stale_devices(self, context, agent_id, timestamp):
        """Delete records that have not been updated since last restart."""
        try:
            filters = {'agent_id': agent_id}
            query = self._get_bgpvpn_devices_query(context, filters=filters)
            query = query.filter(BGPVPNLearnedDevice.updated_at < timestamp)
            return query.delete()
        except exc.NoResultFound:
            return

    @classmethod
    def _get_bgpvpn_active_devices(cls, context, filters=None):
        """This function returns active devices entries.

        Since we can learn device information from behind multiple agents we
        need to reduce this list down to one entry per mac + ip address
        pair; otherwise we'll add conflicting records in to our fastpath.
        This is similar to how the RYU driver selects a "best" route and
        does not tell us about other potential routes for any given mac +
        ip pair until those routes become the best/only option.

        This is done with a where clause which leverages a subquery.  The
        purpose of the subquery is to find the oldest timestamp for any
        given mac + ip combination.

        That subquery is then used in another query to filter results based
        on the selected timestamp for each mac + ip.  It cannot be done in a
        single statement using DISTINCT because that will not allow returning
        columns unrelated to the distinct criteria.  For example, you can
        say "distinct mac, ip" but that will only make the mac and ip
        columns available.  If you also want "gateway_ip" then you need to add
        it to the distinct set and since we could learn the same mac + ip
        from 2 different VTEP instances (from different agents) we'd end up
        with both records which is not what we want.
        """
        # Build the subquery
        s = (context.session.query(
             BGPVPNLearnedDevice.bgpvpn_id,
             BGPVPNLearnedDevice.mac_address,
             BGPVPNLearnedDevice.ip_address,
             func.min(BGPVPNLearnedDevice.updated_at).label('date')))
        s = cls._apply_filters(BGPVPNLearnedDevice, s, filters=filters)
        s = (s.group_by(BGPVPNLearnedDevice.bgpvpn_id,
                        BGPVPNLearnedDevice.mac_address,
                        BGPVPNLearnedDevice.ip_address).subquery('s'))
        # Build the main query
        query = (context.session.query(BGPVPNLearnedDevice).
                 filter(BGPVPNLearnedDevice.bgpvpn_id == s.c.bgpvpn_id).
                 filter(BGPVPNLearnedDevice.mac_address == s.c.mac_address).
                 filter(BGPVPNLearnedDevice.ip_address == s.c.ip_address).
                 filter(BGPVPNLearnedDevice.updated_at == s.c.date))
        query = cls._apply_filters(BGPVPNLearnedDevice, query, filters=filters)
        return query.all()

    def get_bgpvpn_active_devices(self, context, bgpvpn_id,
                                  filters=None, fields=None):
        filters = filters or {}
        filters.update({'bgpvpn_id': bgpvpn_id})
        devices = self._get_bgpvpn_active_devices(context, filters=filters)
        return [self._make_bgpvpn_device_dict(d, fields=fields)
                for d in devices]

    @classmethod
    def _get_bgpvpn_devices_query(cls, context, filters=None):
        query = context.session.query(BGPVPNLearnedDevice)
        query = cls._apply_filters(BGPVPNLearnedDevice, query, filters=filters)
        return query

    def _get_bgpvpn_devices(self, context, filters=None):
        return self._get_bgpvpn_devices_query(context, filters=filters).all()

    def get_bgpvpn_devices(self, context, bgpvpn_id, filters=None,
                           fields=None):
        filters = filters or {}
        filters.update({'bgpvpn_id': bgpvpn_id})
        devices = self._get_bgpvpn_devices(context, filters=filters)
        return [self._make_bgpvpn_device_dict(d, fields=fields)
                for d in devices]

    def create_bgpvpn_device(self, context, agent_id, bgpvpn_id,
                             mac_address, ip_address, gateway_ip):
        with context.session.begin(subtransactions=True):
            now = timeutils.utcnow()
            bgpvpn_device_db = BGPVPNLearnedDevice(
                agent_id=agent_id,
                bgpvpn_id=bgpvpn_id,
                mac_address=mac_address,
                ip_address=ip_address,
                gateway_ip=gateway_ip,
                created_at=now,
                updated_at=now)
            context.session.add(bgpvpn_device_db)
        return self._make_bgpvpn_device_dict(bgpvpn_device_db)

    def update_bgpvpn_device(self, context, agent_id, bgpvpn_id,
                             mac_address, ip_address, gateway_ip):
        with context.session.begin(subtransactions=True):
            try:
                bgpvpn_device_db = self._get_bgpvpn_device(
                    context, agent_id, bgpvpn_id, mac_address, ip_address)
                updates = {'gateway_ip': gateway_ip,
                           'updated_at': timeutils.utcnow()}
                bgpvpn_device_db.update(updates)
                return self._make_bgpvpn_device_dict(bgpvpn_device_db)
            except exc.NoResultFound:
                return self.create_bgpvpn_device(
                    context, agent_id, bgpvpn_id,
                    mac_address, ip_address, gateway_ip)

    def update_bgpvpn_devices(self, context, agent_id, bgpvpn_id,
                              mac_address, gateway_ip):
        """Bulk update any device entries matching a given MAC address."""
        with context.session.begin(subtransactions=True):
            try:
                filters = {'agent_id': agent_id,
                           'bgpvpn_id': bgpvpn_id,
                           'mac_address': mac_address}
                query = self._get_bgpvpn_devices_query(
                    context, filters=filters)
                updates = {'gateway_ip': gateway_ip,
                           'updated_at': timeutils.utcnow()}
                return query.update(updates)
            except exc.NoResultFound:
                return

    def delete_bgpvpn_device(self, context, agent_id, bgpvpn_id,
                             mac_address, ip_address):
        with context.session.begin(subtransactions=True):
            try:
                bgpvpn_device_db = self._get_bgpvpn_device(
                    context, agent_id, bgpvpn_id, mac_address, ip_address)
                bgpvpn_device = self._make_bgpvpn_device_dict(bgpvpn_device_db)
                context.session.delete(bgpvpn_device_db)
                return bgpvpn_device
            except exc.NoResultFound:
                return

    def delete_bgpvpn_devices(self, context, agent_id, bgpvpn_id=None,
                              gateway_ip=None):
        """Bulk delete any devices behind a given VTEP IP address."""
        with context.session.begin(subtransactions=True):
            try:
                filters = {'agent_id': agent_id,
                           'bgpvpn_id': bgpvpn_id,
                           'gateway_ip': gateway_ip}
                query = self._get_bgpvpn_devices_query(
                    context, filters=filters)
                return query.delete()
            except exc.NoResultFound:
                return
