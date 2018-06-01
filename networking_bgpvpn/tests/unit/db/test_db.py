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

from neutron_lib import context

from networking_bgpvpn.neutron.db.bgpvpn_db import BGPVPNPluginDb
from networking_bgpvpn.neutron.extensions.bgpvpn \
    import BGPVPNNetAssocAlreadyExists
from networking_bgpvpn.neutron.extensions.bgpvpn import BGPVPNNetAssocNotFound
from networking_bgpvpn.neutron.extensions.bgpvpn import BGPVPNNotFound
from networking_bgpvpn.neutron.services.common import constants
from networking_bgpvpn.tests.unit.services import test_plugin


def _id_list(list):
    return [bgpvpn['id'] for bgpvpn in list]


class BgpvpnDBTestCase(test_plugin.BgpvpnTestCaseMixin):

    def setUp(self):
        super(BgpvpnDBTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.plugin_db = BGPVPNPluginDb()

    def test_bgpvpn_create_update_delete(self):
        with self.network() as net:
            # create
            bgpvpn = self.plugin_db.create_bgpvpn(
                self.ctx,
                {"tenant_id": self._tenant_id,
                 "type": "l3",
                 "name": "",
                 "route_targets": ["64512:1"],
                 "import_targets": ["64512:11", "64512:12"],
                 "export_targets": ["64512:13", "64512:14"],
                 "route_distinguishers": ["64512:15", "64512:16"],
                 "vni": "1000"
                 }
            )

            net_assoc = {'network_id': net['network']['id'],
                         'tenant_id': self._tenant_id}
            # associate network
            assoc1 = self.plugin_db.create_net_assoc(self.ctx, bgpvpn['id'],
                                                     net_assoc)

            # retrieve
            bgpvpn = self.plugin_db.get_bgpvpn(self.ctx, bgpvpn['id'])

            # check
            self.assertEqual("l3", bgpvpn['type'])
            # we could check tenant_id
            self.assertEqual(["64512:1"], bgpvpn['route_targets'])
            self.assertEqual(["64512:11", "64512:12"],
                             bgpvpn['import_targets'])
            self.assertEqual(["64512:13", "64512:14"],
                             bgpvpn['export_targets'])
            self.assertEqual(["64512:15", "64512:16"],
                             bgpvpn['route_distinguishers'])
            self.assertEqual(1000, bgpvpn['vni'])
            self.assertEqual([net['network']['id']], bgpvpn['networks'])

            assoc1 = self.plugin_db.get_net_assoc(self.ctx, assoc1['id'],
                                                  bgpvpn['id'])
            self.assertEqual(net['network']['id'], assoc1['network_id'])
            self.assertEqual(bgpvpn['id'], assoc1['bgpvpn_id'])

            with self.network(name='net2') as net2:
                net_assoc2 = {'network_id': net2['network']['id'],
                              'tenant_id': self._tenant_id}
                # associate network
                assoc2 = self.plugin_db.create_net_assoc(self.ctx,
                                                         bgpvpn['id'],
                                                         net_assoc2)
                # retrieve
                assoc2 = self.plugin_db.get_net_assoc(self.ctx, assoc2['id'],
                                                      bgpvpn['id'])
                assoc_list = self.plugin_db.get_net_assocs(self.ctx,
                                                           bgpvpn['id'])
                self.assertIn(assoc2, assoc_list)
                self.assertIn(assoc1, assoc_list)

            self._test_router_assocs(bgpvpn['id'], 2)

            # update
            self.plugin_db.update_bgpvpn(
                self.ctx,
                bgpvpn['id'],
                {"type": "l2",
                 "name": "foo",
                 "tenant_id": "a-b-c-d",
                 "route_targets": [],
                 "import_targets": ["64512:22"],
                 "route_distinguishers": []
                 })

            # retrieve
            bgpvpn2 = self.plugin_db.get_bgpvpn(self.ctx, bgpvpn['id'])
            # check
            self.assertEqual("l2", bgpvpn2['type'])
            self.assertEqual("a-b-c-d", bgpvpn2['tenant_id'])
            self.assertEqual("foo", bgpvpn2['name'])
            self.assertEqual([], bgpvpn2['route_targets'])
            self.assertEqual(["64512:22"], bgpvpn2['import_targets'])
            self.assertEqual(["64512:13", "64512:14"],
                             bgpvpn2['export_targets'])
            self.assertEqual([], bgpvpn2['route_distinguishers'])

            # find bgpvpn by network_id
            bgpvpn3 = self.plugin_db.get_bgpvpns(
                self.ctx,
                filters={
                    'networks': [net['network']['id']],
                },
            )
            self.assertEqual(1, len(bgpvpn3))
            self.assertEqual(bgpvpn2['id'], bgpvpn3[0]['id'])

            # asset that GETting the assoc, but for another BGPVPN, does fails
            self.assertRaises(BGPVPNNetAssocNotFound,
                              self.plugin_db.get_net_assoc,
                              self.ctx,
                              assoc2['id'],
                              "bogus_bgpvpn_id")

            # assert that deleting a net remove the assoc
            self._delete('networks', net2['network']['id'])
            assoc_list = self.plugin_db.get_net_assocs(self.ctx,
                                                       bgpvpn['id'])
            self.assertNotIn(assoc2, assoc_list)
            self.assertRaises(BGPVPNNetAssocNotFound,
                              self.plugin_db.get_net_assoc,
                              self.ctx,
                              assoc2['id'], bgpvpn['id'])
            # delete
            self.plugin_db.delete_bgpvpn(self.ctx, bgpvpn['id'])
            # check that delete was effective
            self.assertRaises(BGPVPNNotFound,
                              self.plugin_db.get_bgpvpn,
                              self.ctx, bgpvpn['id'])
            # check that the assoc has been deleted after deleting the bgpvpn
            self.assertRaises(BGPVPNNetAssocNotFound,
                              self.plugin_db.get_net_assoc,
                              self.ctx,
                              assoc1['id'], bgpvpn['id'])

    def _test_router_assocs(self, bgpvpn_id, max_assocs, assoc_count=0,
                            previous_assocs=None):
        with self.router(tenant_id=self._tenant_id) as router:
            router_assoc = {'router_id': router['router']['id'],
                            'tenant_id': self._tenant_id}
            assoc = self.plugin_db.create_router_assoc(self.ctx,
                                                       bgpvpn_id,
                                                       router_assoc)
            assoc_count += 1
            assoc = self.plugin_db.get_router_assoc(self.ctx, assoc['id'],
                                                    bgpvpn_id)
            assoc_list = self.plugin_db.get_router_assocs(self.ctx, bgpvpn_id)

            bgpvpn = self.plugin_db.get_bgpvpn(self.ctx, bgpvpn_id)
            self.assertIn(router['router']['id'], bgpvpn['routers'])

            if previous_assocs is None:
                previous_assocs = []
            previous_assocs.append(assoc)
            for assoc in previous_assocs:
                self.assertIn(assoc, assoc_list)

            if assoc_count == max_assocs:
                return
            else:
                self._test_router_assocs(bgpvpn_id, max_assocs,
                                         assoc_count=assoc_count)

    def test_db_associate_disassociate_net(self):
        with self.network() as net:
            net_id = net['network']['id']
            with self.bgpvpn() as bgpvpn:
                id = bgpvpn['bgpvpn']['id']
                with self.assoc_net(id, net_id):
                    bgpvpn = self.plugin_db.get_bgpvpn(self.ctx, id)
                    self.assertEqual([net_id], bgpvpn['networks'])
                bgpvpn = self.plugin_db.get_bgpvpn(self.ctx, id)
                self.assertEqual([], bgpvpn['networks'])

    def test_db_associate_twice(self):
        with self.network() as net, self.bgpvpn() as bgpvpn:
            net_id = net['network']['id']
            id = bgpvpn['bgpvpn']['id']
            with self.assoc_net(id, net_id=net_id):
                self.assoc_net(id,
                               net_id=net_id,
                               do_disassociate=False)
                self.assertRaises(BGPVPNNetAssocAlreadyExists,
                                  self.plugin_db.create_net_assoc,
                                  self.ctx,
                                  id, {'tenant_id': self._tenant_id,
                                       'network_id': net_id})

    def test_db_find_bgpvpn_for_associated_network(self):
        with self.network() as net, \
                self.bgpvpn(type=constants.BGPVPN_L2) as bgpvpn_l2, \
                self.bgpvpn() as bgpvpn_l3, \
                self.assoc_net(bgpvpn_l2['bgpvpn']['id'],
                               net['network']['id']), \
                self.assoc_net(bgpvpn_l3['bgpvpn']['id'],
                               net['network']['id']):
            net_id = net['network']['id']

            bgpvpn_id_list = _id_list(
                self.plugin_db.get_bgpvpns(
                    self.ctx,
                    filters={'networks': [net_id]},
                )
            )
            self.assertIn(bgpvpn_l2['bgpvpn']['id'], bgpvpn_id_list)
            self.assertIn(bgpvpn_l3['bgpvpn']['id'], bgpvpn_id_list)

            bgpvpn_l2_id_list = _id_list(
                self.plugin_db.get_bgpvpns(
                    self.ctx,
                    filters={
                        'networks': [net_id],
                        'type': [constants.BGPVPN_L2],
                    },
                )
            )
            self.assertIn(bgpvpn_l2['bgpvpn']['id'], bgpvpn_l2_id_list)
            self.assertNotIn(bgpvpn_l3['bgpvpn']['id'], bgpvpn_l2_id_list)

            bgpvpn_l3_id_list = _id_list(
                self.plugin_db.get_bgpvpns(
                    self.ctx,
                    filters={
                        'networks': [net_id],
                        'type': [constants.BGPVPN_L3],
                    },
                )
            )
            self.assertNotIn(bgpvpn_l2['bgpvpn']['id'], bgpvpn_l3_id_list[0])
            self.assertIn(bgpvpn_l3['bgpvpn']['id'], bgpvpn_l3_id_list[0])

    def test_db_delete_net(self):
        with self.bgpvpn() as bgpvpn:
            id = bgpvpn['bgpvpn']['id']
            with self.network() as net:
                net_id = net['network']['id']
                self.assoc_net(id, net_id=net_id, do_disassociate=False)
            bgpvpn_db = self.plugin_db.get_bgpvpn(self.ctx, id)
            self.assertEqual([], bgpvpn_db['networks'])

    def test_db_associate_disassociate_router(self):
        with self.router(tenant_id=self._tenant_id) as router:
            router_id = router['router']['id']
            with self.bgpvpn() as bgpvpn:
                id = bgpvpn['bgpvpn']['id']
                with self.assoc_router(id, router_id):
                    bgpvpn = self.plugin_db.get_bgpvpn(self.ctx, id)
                    self.assertEqual([router_id], bgpvpn['routers'])
                bgpvpn = self.plugin_db.get_bgpvpn(self.ctx, id)
                self.assertEqual([], bgpvpn['routers'])

    def test_db_find_bgpvpn_for_associated_router(self):
        with self.router(tenant_id=self._tenant_id) as router:
            router_id = router['router']['id']
            with self.bgpvpn() as bgpvpn:
                id = bgpvpn['bgpvpn']['id']
                with self.assoc_router(id, router_id=router_id):
                    bgpvpn_list = self.plugin_db.get_bgpvpns(
                        self.ctx,
                        filters={'routers': [router_id]},
                    )
                    self.assertEqual(id, bgpvpn_list[0]['id'])

    def test_db_delete_router(self):
        with self.bgpvpn() as bgpvpn:
            id = bgpvpn['bgpvpn']['id']
            with self.router(tenant_id=self._tenant_id) as router:
                router_id = router['router']['id']
                self.assoc_router(id, router_id=router_id,
                                  do_disassociate=False)
            bgpvpn_db = self.plugin_db.get_bgpvpn(self.ctx, id)
            self.assertEqual([], bgpvpn_db['routers'])

    def test_db_list_bgpvpn_filtering_associated_resources(self):
        with self.network() as network1, \
                self.network() as network2, \
                self.router(tenant_id=self._tenant_id) as router1, \
                self.router(tenant_id=self._tenant_id) as router2, \
                self.bgpvpn() as bgpvpn1, \
                self.bgpvpn() as bgpvpn2, \
                self.bgpvpn() as bgpvpn3, \
                self.assoc_net(bgpvpn1['bgpvpn']['id'],
                               network1['network']['id']), \
                self.assoc_router(bgpvpn3['bgpvpn']['id'],
                                  router1['router']['id']), \
                self.assoc_net(bgpvpn2['bgpvpn']['id'],
                               network2['network']['id']), \
                self.assoc_router(bgpvpn2['bgpvpn']['id'],
                                  router2['router']['id']):
            network1_id = network1['network']['id']
            network2_id = network2['network']['id']
            router1_id = router1['router']['id']
            router2_id = router2['router']['id']

            bgpvpn_id_list = _id_list(
                self.plugin_db.get_bgpvpns(
                    self.ctx,
                    filters={
                        'networks': [network1_id],
                    },
                )
            )
            self.assertIn(bgpvpn1['bgpvpn']['id'], bgpvpn_id_list)
            self.assertNotIn(bgpvpn2['bgpvpn']['id'], bgpvpn_id_list)
            self.assertNotIn(bgpvpn3['bgpvpn']['id'], bgpvpn_id_list)

            bgpvpn_id_list = _id_list(
                self.plugin_db.get_bgpvpns(
                    self.ctx,
                    filters={
                        'networks': [network1_id, network2_id],
                    },
                )
            )
            self.assertIn(bgpvpn1['bgpvpn']['id'], bgpvpn_id_list)
            self.assertIn(bgpvpn2['bgpvpn']['id'], bgpvpn_id_list)
            self.assertNotIn(bgpvpn3['bgpvpn']['id'], bgpvpn_id_list)

            bgpvpn_id_list = _id_list(
                self.plugin_db.get_bgpvpns(
                    self.ctx,
                    filters={
                        'routers': [router1_id],
                    },
                )
            )
            self.assertNotIn(bgpvpn1['bgpvpn']['id'], bgpvpn_id_list)
            self.assertNotIn(bgpvpn2['bgpvpn']['id'], bgpvpn_id_list)
            self.assertIn(bgpvpn3['bgpvpn']['id'], bgpvpn_id_list)

            bgpvpn_id_list = _id_list(
                self.plugin_db.get_bgpvpns(
                    self.ctx,
                    filters={
                        'routers': [router1_id, router2_id],
                    },
                )
            )
            self.assertNotIn(bgpvpn1['bgpvpn']['id'], bgpvpn_id_list)
            self.assertIn(bgpvpn2['bgpvpn']['id'], bgpvpn_id_list)
            self.assertIn(bgpvpn3['bgpvpn']['id'], bgpvpn_id_list)

            bgpvpn_id_list = _id_list(
                self.plugin_db.get_bgpvpns(
                    self.ctx,
                    filters={
                        'networks': [network1_id],
                        'routers': [router1_id],
                    },
                )
            )
            self.assertNotIn(bgpvpn1['bgpvpn']['id'], bgpvpn_id_list)
            self.assertNotIn(bgpvpn2['bgpvpn']['id'], bgpvpn_id_list)
            self.assertNotIn(bgpvpn3['bgpvpn']['id'], bgpvpn_id_list)

            bgpvpn_id_list = _id_list(
                self.plugin_db.get_bgpvpns(
                    self.ctx,
                    filters={
                        'networks': [network2_id],
                        'routers': [router2_id],
                    },
                )
            )
            self.assertNotIn(bgpvpn1['bgpvpn']['id'], bgpvpn_id_list)
            self.assertIn(bgpvpn2['bgpvpn']['id'], bgpvpn_id_list)
            self.assertNotIn(bgpvpn3['bgpvpn']['id'], bgpvpn_id_list)
