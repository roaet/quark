# Copyright 2014 Openstack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for# the specific language governing permissions and limitations
#  under the License.

import mock
import netaddr

import contextlib

from oslo_config import cfg
from quark.db import api as db_api
from quark.db import ip_types

from quark import exceptions as q_exceptions
import quark.ipam
import quark.plugin
import quark.plugin_modules.ip_addresses as ip_api
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.ports as port_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest


class QuarkSharedIPs(BaseFunctionalTest):
    def __init__(self, *args, **kwargs):
        super(QuarkSharedIPs, self).__init__(*args, **kwargs)
        self.disassociate_exception = q_exceptions.PortRequiresDisassociation
        self.cidr = "192.168.2.0/24"
        self.ip_network = netaddr.IPNetwork(self.cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        self.network = {"network": network}
        subnet = dict(ip_version=4, next_auto_assign_ip=2,
                      cidr=self.cidr, first_ip=self.ip_network.first,
                      last_ip=self.ip_network.last, ip_policy=None,
                      tenant_id="fake")
        self.subnet = {"subnet": subnet}
        port1 = {'port': dict(device_id='a')}
        port2 = {'port': dict(device_id='b')}
        port3 = {'port': dict(device_id='c')}
        port4 = {'port': dict(device_id='d')}
        self.ports_info2 = [port1, port2]
        self.ports_info4 = [port1, port2, port3, port4]

    def setUp(self):
        super(QuarkSharedIPs, self).setUp()
        self.old_show_port_service = cfg.CONF.QUARK.show_port_service
        cfg.CONF.set_override('show_port_service', True, 'QUARK')

    def tearDown(self):
        super(QuarkSharedIPs, self).tearDown()
        cfg.CONF.set_override('show_port_service', self.old_show_port_service,
                              'QUARK')

    @contextlib.contextmanager
    def _stubs(self, network_info, subnet_info, ports_info):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(
                mock.patch("neutron.common.rpc.get_notifier"),
                mock.patch("neutron.quota.QUOTAS.limit_check")):
            net = network_api.create_network(self.context, network_info)
            mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
            self.context.is_admin = True
            macrng_api.create_mac_address_range(self.context, mac)
            self.context.is_admin = False
            subnet_info['subnet']['network_id'] = net['id']
            sub = subnet_api.create_subnet(self.context, subnet_info)
            ports = []
            for port_info in ports_info:
                port_info['port']['network_id'] = net['id']
                ports.append(port_api.create_port(self.context, port_info))
            yield net, sub, ports

    def test_create_shared_ips_with_port_ids(self):

        def _make_body(ip):
            fix_ip = dict(ip_address=ip, subnet_id=sub['id'])
            port_info = {"port": dict(fixed_ips=[fix_ip])}
            return port_info

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            self.assertEqual(2, len(ports_ip))

    def test_shared_ip_in_fixed_ip_list(self):

        def _make_body(service):
            body = dict(service=service)
            port_info = {"port": dict(body)}
            return port_info

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            print "before adding to shared ip, all ports should have 1 ip"
            for port in ports:
                self.assertEqual(1, len(port['fixed_ips']))
                print "individual ports %s\n" % port

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            p_id = ports[0]['id']
            assoc = db_api.ip_port_association_find(self.context,
                                                    port_id=p_id)
            print "the association entries:"
            for a in assoc.all():
                print "association: %s" % str(a.__dict__)
            print "no more associations\n"

            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])
            print "Shared ip made successfully. All ports should have 2 ips\n"
            print "the shared ip: %s\n" % ip

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            print "list of ports by ip has 2: %s\n" % ports_ip
            self.assertEqual(2, len(ports_ip))

            ip_db = db_api.ip_address_find(self.context, id=ip['id'],
                                           scope=db_api.ONE)
            print "ip ports from db is the backref of port ips from db"
            print "ip ports from db: %s\n" % ip_db.ports

            port_ip_update = ip_api.update_port_for_ip_address
            updated_port = port_ip_update(self.context, ip['id'],
                                          p_id, _make_body('derp'))
            print "Service updated port[%s] %s\n" % (p_id, updated_port)
            self.assertEqual('derp', updated_port.get('service'))

            port = port_api.get_port(self.context, p_id)
            if 2 != len(port['fixed_ips']):
                ports_ip = ip_api.get_port_for_ip_address(self.context,
                                                          ip['id'],
                                                          p_id)
                print "Port from ip perspective %s\n" % ports_ip
                p_db = db_api.port_find(self.context, id=p_id,
                                        scope=db_api.ONE)
                print "Port from DB perspective: %s\n" % p_db
                print "Port ips from DB perspective: %s\n" % p_db.ip_addresses

                ip_db = db_api.ip_address_find(self.context, id=ip['id'],
                                               scope=db_api.ONE)
                print "ip from db: %s\n" % ip_db
                print "ip ports from db is the backref of port ips from db"
                print "ip ports from db: %s\n" % ip_db.ports

                assoc = db_api.ip_port_association_find(self.context,
                                                        ip_address_id=ip['id'])
                print "the association entries:"
                for a in assoc.all():
                    print "association: %s" % str(a.__dict__)
                print "no more associations\n"
            print "Port from GET /port perspective %s\n" % port
            self.assertEqual(2, len(port['fixed_ips']))
            #self.fail("jesus christ")

    def test_ip_port_list_has_services(self):

        def _make_body(service):
            body = dict(service=service)
            port_info = {"port": dict(body)}
            return port_info

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            for port in ports:
                self.assertEqual(1, len(port['fixed_ips']))

            device_ids = [ports[0]['device_id'], ports[1]['device_id']]
            shared_ip = {'ip_address': dict(device_ids=device_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'],
                           ports[0]['id'], _make_body('derp'))

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            self.assertEqual(2, len(ports_ip))

            for port in ports_ip:
                self.assertTrue('service' in port)
                self.assertTrue('device_id' in port)
                self.assertTrue('id' in port)
                self.assertTrue(port['service'] in ('derp', 'none'),
                                'Service is: %s' % str(port['service']))

    def test_can_delete_ip_without_active_port(self):

        def _make_body(service):
            body = dict(service=service)
            port_info = {"port": dict(body)}
            return port_info

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):
            device_ids = [ports[0]['device_id'], ports[1]['device_id']]
            shared_ip = {'ip_address': dict(device_ids=device_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            ip_api.delete_ip_address(self.context, ip['id'])
            with self.assertRaises(q_exceptions.IpAddressNotFound):
                ip_api.get_ip_address(self.context, ip['id'])

    def test_cannot_delete_ip_with_active_port(self):

        def _make_body(service):
            body = dict(service=service)
            port_info = {"port": dict(body)}
            return port_info

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):
            device_ids = [ports[0]['device_id'], ports[1]['device_id']]
            shared_ip = {'ip_address': dict(device_ids=device_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'],
                           ports[0]['id'], _make_body('derp'))

            with self.assertRaises(self.disassociate_exception):
                ip_api.delete_ip_address(self.context, ip['id'])
