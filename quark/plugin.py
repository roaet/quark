# Copyright 2011 Nicira Networks, Inc.
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
# @author: Dan Wendlandt, Nicira, Inc.

"""
v2 Quantum Plug-in API Quark Implementation
"""

import uuid

from quantum import quantum_plugin_base_v2


class Plugin(quantum_plugin_base_v2.QuantumPluginBaseV2):
    def _gen_uuid(self):
        return uuid.uuid1()

    def _make_network_dict(self, network, fields=None):
        if not network.get('subnets'):
            network['subnets'] = {}
        res = {'id': network.get('id'),
               'name': network.get('name'),
               'tenant_id': network.get('tenant_id'),
               'admin_state_up': network.get('admin_state_up'),
               'status': network.get('status'),
               'shared': network.get('shared'),
               'subnets': [subnet.get('id')
                           for subnet in network.get('subnets')]}
        return res

    def _make_subnet_dict(self, subnet, fields=None):
        if not subnet.get('allocation_pools'):
            subnet['allocation_pools'] = {}
        if not subnet.get('dns_nameservers'):
            subnet['dns_nameservers'] = {}
        if not subnet.get('routes'):
            subnet['routes'] = {}
        res = {'id': subnet.get('id'),
               'name': subnet.get('name'),
               'tenant_id': subnet.get('tenant_id'),
               'network_id': subnet.get('network_id'),
               'ip_version': subnet.get('ip_version'),
               'cidr': subnet.get('cidr'),
               'allocation_pools': [{'start': pool.get('first_ip'),
                                     'end': pool.get('last_ip')}
                                    for pool in
                                    subnet.get('allocation_pools')],
               'gateway_ip': subnet.get('gateway_ip'),
               'enable_dhcp': subnet.get('enable_dhcp'),
               'dns_nameservers': [dns.get('address')
                                   for dns in subnet.get('dns_nameservers')],
               'host_routes': [{'destination': route.get('destination'),
                                'nexthop': route.get('nexthop')}
                               for route in subnet.get('routes')],
               'shared': subnet.get('shared')
               }
        if subnet.get('gateway_ip'):
            res['gateway_ip'] = subnet.get('gateway_ip')
        return res

    def _make_port_dict(self, port, fields=None):
        if not port.get('fixed_ips'):
            port['fixed_ips'] = {}
        res = {"id": port.get("id"),
               'name': port.get('name'),
               "network_id": port.get("network_id"),
               'tenant_id': port.get('tenant_id'),
               "mac_address": port.get("mac_address"),
               "admin_state_up": port.get("admin_state_up"),
               "status": port.get("status"),
               "fixed_ips": [{'subnet_id': ip.get("subnet_id"),
                              'ip_address': ip.get("ip_address")}
                             for ip in port.get("fixed_ips")],
               "device_id": port.get("device_id"),
               "device_owner": port.get("device_owner")}
        return res

    def create_subnet(self, context, subnet):
        """
        Create a subnet, which represents a range of IP addresses
        that can be allocated to devices
        : param context: quantum api request context
        : param subnet: dictionary describing the subnet, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.  All keys will be populated.
        """
        subnet = {'id': self._gen_uuid()}
        return self._make_subnet_dict(subnet)

    def update_subnet(self, context, id, subnet):
        """
        Update values of a subnet.
        : param context: quantum api request context
        : param id: UUID representing the subnet to update.
        : param subnet: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.
        """
        subnet = {'id': id}
        return self._make_subnet_dict(subnet)

    def get_subnet(self, context, id, fields=None):
        """
        Retrieve a subnet.
        : param context: quantum api request context
        : param id: UUID representing the subnet to fetch.
        : param fields: a list of strings that are valid keys in a
            subnet dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        subnet = {'id': id}
        return self._make_subnet_dict(subnet)

    def get_subnets(self, context, filters=None, fields=None):
        """
        Retrieve a list of subnets.  The contents of the list depends on
        the identity of the user making the request (as indicated by the
        context) as well as any filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a subnet as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.
        : param fields: a list of strings that are valid keys in a
            subnet dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        subnet = {'id': self._gen_uuid()}
        return [self._make_subnet_dict(subnet)]

    def get_subnets_count(self, context, filters=None):
        """
        Return the number of subnets.  The result depends on the identity of
        the user making the request (as indicated by the context) as well as
        any filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.

        NOTE: this method is optional, as it was not part of the originally
              defined plugin API.
        """
        return 1

    def delete_subnet(self, context, id):
        """
        Delete a subnet.
        : param context: quantum api request context
        : param id: UUID representing the subnet to delete.
        """
        pass

    def create_network(self, context, network):
        """
        Create a network, which represents an L2 network segment which
        can have a set of subnets and ports associated with it.
        : param context: quantum api request context
        : param network: dictionary describing the network, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.  All keys will be populated.
        """
        network = {'id': self._gen_uuid()}
        return self._make_network_dict(network)

    def update_network(self, context, id, network):
        """
        Update values of a network.
        : param context: quantum api request context
        : param id: UUID representing the network to update.
        : param network: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.
        """
        network = {'id': id}
        return self._make_network_dict(network)

    def get_network(self, context, id, fields=None):
        """
        Retrieve a network.
        : param context: quantum api request context
        : param id: UUID representing the network to fetch.
        : param fields: a list of strings that are valid keys in a
            network dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        network = {'id': id}
        return self._make_network_dict(network)

    def get_networks(self, context, filters=None, fields=None):
        """
        Retrieve a list of networks.  The contents of the list depends on
        the identity of the user making the request (as indicated by the
        context) as well as any filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.
        : param fields: a list of strings that are valid keys in a
            network dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        network = {'id': self._gen_uuid()}
        return [self._make_network_dict(network)]

    def get_networks_count(self, context, filters=None):
        """
        Return the number of networks.  The result depends on the identity
        of the user making the request (as indicated by the context) as well
        as any filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.

        NOTE: this method is optional, as it was not part of the originally
              defined plugin API.
        """
        return 1

    def delete_network(self, context, id):
        """
        Delete a network.
        : param context: quantum api request context
        : param id: UUID representing the network to delete.
        """
        pass

    def create_port(self, context, port):
        """
        Create a port, which is a connection point of a device (e.g., a VM
        NIC) to attach to a L2 Quantum network.
        : param context: quantum api request context
        : param port: dictionary describing the port, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.  All keys will be populated.
        """
        new_port = {'id': self._gen_uuid()}
        return self._make_port_dict(new_port)

    def update_port(self, context, id, port):
        """
        Update values of a port.
        : param context: quantum api request context
        : param id: UUID representing the port to update.
        : param port: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.
        """
        new_port = {'id': id}
        return self._make_port_dict(new_port)

    def get_port(self, context, id, fields=None):
        """
        Retrieve a port.
        : param context: quantum api request context
        : param id: UUID representing the port to fetch.
        : param fields: a list of strings that are valid keys in a
            port dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        new_port = {'id': id}
        return self._make_port_dict(new_port)

    def get_ports(self, context, filters=None, fields=None):
        """
        Retrieve a list of ports.  The contents of the list depends on
        the identity of the user making the request (as indicated by the
        context) as well as any filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a port as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.
        : param fields: a list of strings that are valid keys in a
            port dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        new_port = {'id': self._gen_uuid()}
        return [self._make_port_dict(new_port)]

    def get_ports_count(self, context, filters=None):
        """
        Return the number of ports.  The result depends on the identity of
        the user making the request (as indicated by the context) as well as
        any filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.

        NOTE: this method is optional, as it was not part of the originally
              defined plugin API.
        """
        return 1

    def delete_port(self, context, id):
        """
        Delete a port.
        : param context: quantum api request context
        : param id: UUID representing the port to delete.
        """
        pass
