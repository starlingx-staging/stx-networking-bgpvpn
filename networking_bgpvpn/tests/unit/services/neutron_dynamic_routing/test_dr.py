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

import copy
import mock
import webob.exc

from neutron.callbacks import events
from neutron.callbacks import registry

from networking_bgpvpn.neutron.callback import resources
from networking_bgpvpn.tests.unit.services import test_plugin


class TestBgpvpnDRCommon(test_plugin.BgpvpnTestCaseMixin):

    def setUp(self):

        l2pop_notify_p = mock.patch('neutron.plugins.ml2.drivers.l2pop.'
                                    'rpc.L2populationAgentNotifyAPI')
        l2pop_notify_p.start()
        rpc_conn_p = mock.patch('neutron.common.rpc.create_connection')
        rpc_conn_p.start()

        provider = ('networking_bgpvpn.neutron.services.service_drivers.'
                    'neutron_dynamic_routing.dr.DynamicRoutingBGPVPNDriver')
        super(TestBgpvpnDRCommon, self).setUp(service_provider=provider)

        self.create_callback = mock.Mock()
        self.update_callback = mock.Mock()
        self.delete_callback = mock.Mock()
        self.router_create_callback = mock.Mock()
        self.router_delete_callback = mock.Mock()

        registry.subscribe(self.create_callback,
                           resources.BGPVPN,
                           events.AFTER_CREATE)
        registry.subscribe(self.update_callback,
                           resources.BGPVPN,
                           events.AFTER_UPDATE)
        registry.subscribe(self.delete_callback,
                           resources.BGPVPN,
                           events.AFTER_DELETE)
        registry.subscribe(self.router_create_callback,
                           resources.BGPVPN_ROUTER_ASSOC,
                           events.AFTER_CREATE)
        registry.subscribe(self.router_delete_callback,
                           resources.BGPVPN_ROUTER_ASSOC,
                           events.AFTER_DELETE)


class TestDRServiceDriver(TestBgpvpnDRCommon):

    def test_create_bgpvpn_with_empty_rd_dr(self):
        bgpvpn_data = copy.copy(self.bgpvpn_data['bgpvpn'])
        bgpvpn_data.update({"route_distinguishers": ""})

        # Assert that an error is returned to the client
        bgpvpn_req = self.new_create_request(
            'bgpvpn/bgpvpns', bgpvpn_data)
        res = bgpvpn_req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code,
                         res.status_int)

    def test_create_bgpvpn_with_empty_vni_dr(self):
        bgpvpn_data = copy.copy(self.bgpvpn_data['bgpvpn'])
        bgpvpn_data.update({"vni": ""})

        # Assert that an error is returned to the client
        bgpvpn_req = self.new_create_request(
            'bgpvpn/bgpvpns', bgpvpn_data)
        res = bgpvpn_req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code,
                         res.status_int)

    def test_create_bgpvpn(self):
        with self.bgpvpn(do_delete=False) as bgpvpn:
            self.create_callback.assert_called_once_with(
                resources.BGPVPN,
                events.AFTER_CREATE,
                mock.ANY,
                name=bgpvpn['bgpvpn']['name'],
                id=bgpvpn['bgpvpn']['id'],
                context=mock.ANY,
                type=bgpvpn['bgpvpn']['type'],
                rd=bgpvpn['bgpvpn']['route_distinguishers'],
                vni=bgpvpn['bgpvpn']['vni'],
                import_rt=bgpvpn['bgpvpn']['route_targets'] +
                bgpvpn['bgpvpn']['import_targets'],
                export_rt=bgpvpn['bgpvpn']['route_targets'] +
                bgpvpn['bgpvpn']['export_targets'])

    def test_update_bgpvpn_with_new_rd(self):
        with self.bgpvpn(do_delete=False) as bgpvpn:
            new_data = {"bgpvpn": {"route_distinguishers": "100:300"}}
            # Assert that an error is returned to the client
            self._update('bgpvpn/bgpvpns',
                         bgpvpn['bgpvpn']['id'],
                         new_data,
                         expected_code=webob.exc.HTTPBadRequest.code)

    def test_update_bgpvpn_with_new_vni(self):
        with self.bgpvpn(do_delete=False) as bgpvpn:
            new_data = {"bgpvpn": {"vni": "2000"}}
            # Assert that an error is returned to the client
            self._update('bgpvpn/bgpvpns',
                         bgpvpn['bgpvpn']['id'],
                         new_data,
                         expected_code=webob.exc.HTTPBadRequest.code)

    def test_update_bgpvpn(self):
        with self.bgpvpn(do_delete=False) as bgpvpn:
            update_data = {"bgpvpn": {"name": "foo"}}
            self._update('bgpvpn/bgpvpns',
                         bgpvpn['bgpvpn']['id'],
                         update_data)
            new_vpn = {'id': bgpvpn['bgpvpn']['id'],
                       'name': 'foo',
                       'type': bgpvpn['bgpvpn']['type'],
                       'rd': bgpvpn['bgpvpn']['route_distinguishers'],
                       'vni': bgpvpn['bgpvpn']['vni'],
                       'export_rt': bgpvpn['bgpvpn']['route_targets'] +
                       bgpvpn['bgpvpn']['export_targets'],
                       'import_rt': bgpvpn['bgpvpn']['route_targets'] +
                       bgpvpn['bgpvpn']['import_targets']}
            old_vpn = {'id': bgpvpn['bgpvpn']['id'],
                       'name': 'bgpvpn1',
                       'type': bgpvpn['bgpvpn']['type'],
                       'rd': bgpvpn['bgpvpn']['route_distinguishers'],
                       'vni': bgpvpn['bgpvpn']['vni'],
                       'export_rt': bgpvpn['bgpvpn']['route_targets'] +
                       bgpvpn['bgpvpn']['export_targets'],
                       'import_rt': bgpvpn['bgpvpn']['route_targets'] +
                       bgpvpn['bgpvpn']['import_targets']}
            self.update_callback.assert_called_once_with(
                resources.BGPVPN,
                events.AFTER_UPDATE,
                mock.ANY,
                context=mock.ANY,
                new_vpn=new_vpn,
                old_vpn=old_vpn)

    def test_delete_bgpvpn(self):
        with self.bgpvpn(do_delete=False) as bgpvpn:
            self._delete('bgpvpn/bgpvpns',
                         bgpvpn['bgpvpn']['id'])
            self.delete_callback.assert_called_once_with(
                resources.BGPVPN,
                events.AFTER_DELETE,
                mock.ANY,
                id=bgpvpn['bgpvpn']['id'],
                name=bgpvpn['bgpvpn']['name'],
                context=mock.ANY)

    def test_create_bgpvpn_router_assoc(self):
        with self.bgpvpn() as bgpvpn, \
            self.router(tenant_id=self._tenant_id) as router:
            with self.assoc_router(bgpvpn['bgpvpn']['id'],
                                   router['router']['id'],
                                   do_disassociate=False):
                self.router_create_callback.assert_called_once_with(
                    resources.BGPVPN_ROUTER_ASSOC,
                    events.AFTER_CREATE,
                    mock.ANY,
                    context=mock.ANY,
                    bgpvpn_id=bgpvpn['bgpvpn']['id'],
                    router_id=router['router']['id'])

    def test_delete_bgpvpn_router_assoc(self):
        with self.bgpvpn() as bgpvpn, \
            self.router(tenant_id=self._tenant_id) as router:
            with self.assoc_router(bgpvpn['bgpvpn']['id'],
                                   router['router']['id'],
                                   do_disassociate=False) as assoc:
                assoc_id = assoc['router_association']['id']
                res = 'bgpvpn/bgpvpns/' + bgpvpn['bgpvpn']['id'] + \
                      '/router_associations'
                self._delete(res, assoc_id)
                self.router_delete_callback.assert_called_once_with(
                    resources.BGPVPN_ROUTER_ASSOC,
                    events.AFTER_DELETE,
                    mock.ANY,
                    context=mock.ANY,
                    bgpvpn_id=bgpvpn['bgpvpn']['id'],
                    router_id=router['router']['id'])
