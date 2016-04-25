# Copyright 2016 Rackspace Hosting
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
from oslo_log import log as logging

from quark.db import api as db_api


LOG = logging.getLogger(__name__)

OPERATION_CREATE = "create"
OPERATION_DELETE = "delete"
OPERATION_UPDATE = "update"
OPERATION_ASSOCIATE = "associate"
OPERATION_DISASSOCIATE = "associate"
OPERATION_ALLOCATE = "allocate"
OPERATION_DEALLOCATE = "deallocate"


def _ip_address_audit(context, ip, op, port=None):
    i = ip if 'ip_address' not in ip else ip['ip_address']
    desc = 'ip: "%s"' % (i['address_readable'])
    if port:
        desc = '%s, Port: "%s"' % (desc, port['id'])
    audit = dict(
        operation=op,
        resource='ip_addresses',
        resource_id=i['id'],
        resource_desc=desc,
        tenant_id=i['used_by_tenant_id'],
        instance_uuid=port['device_id'] if port else None,
        version=i['version'],
        network=i['network_id'])
    db_api.create_audit_record(context, **audit)


def ip_address_audit_deallocate(context, ip_address):
    _ip_address_audit(context, ip_address, OPERATION_DEALLOCATE)


def ip_address_audit_allocate(context, ip_address):
    _ip_address_audit(context, ip_address, OPERATION_ALLOCATE)


def ip_address_audit_associate(context, ip_address, port):
    _ip_address_audit(context, ip_address, OPERATION_ASSOCIATE, port=port)


def ip_address_audit_disassociate(context, ip_address, port):
    _ip_address_audit(context, ip_address, OPERATION_DISASSOCIATE, port=port)


def ip_address_audit_create(context, ip_address):
    _ip_address_audit(context, ip_address, OPERATION_CREATE)


def ip_address_audit_update(context, ip_address):
    _ip_address_audit(context, ip_address, OPERATION_UPDATE)


def ip_address_audit_delete(context, ip_address):
    _ip_address_audit(context, ip_address, OPERATION_DELETE)


def _subnet_audit(context, subnet, op):
    s = subnet if 'subnet' not in subnet else subnet['subnet']
    desc = 'Cidr: "%s"' % (s['cidr'])
    audit = dict(
        operation=op,
        resource='subnet',
        resource_id=s['id'],
        resource_desc=desc,
        tenant_id=s['tenant_id'],
        instance_uuid=None,
        network=s['network_id'])
    db_api.create_audit_record(context, **audit)


def subnet_audit_create(context, subnet):
    _subnet_audit(context, subnet, OPERATION_CREATE)


def subnet_audit_update(context, subnet):
    _subnet_audit(context, subnet, OPERATION_UPDATE)


def subnet_audit_delete(context, subnet):
    _subnet_audit(context, subnet, OPERATION_DELETE)


def _network_audit(context, network, op):
    n = network if 'network' not in network else network['network']
    desc = 'Name: "%s", IPAM "%s"' % (n['name'], n['ipam_strategy'])
    audit = dict(
        operation=op,
        resource='network',
        resource_id=n['id'],
        resource_desc=desc,
        tenant_id=n['tenant_id'],
        instance_uuid=None,
        network=n['id'])
    db_api.create_audit_record(context, **audit)


def network_audit_create(context, network):
    _network_audit(context, network, OPERATION_CREATE)


def network_audit_update(context, network):
    _network_audit(context, network, OPERATION_UPDATE)


def network_audit_delete(context, network):
    _network_audit(context, network, OPERATION_DELETE)


def _port_audit(context, port, op):
    p = port if 'port' not in port else port['port']
    desc = 'Name: "%s", Bridge "%s"' % (p['name'], p['bridge'])
    audit = dict(
        operation=op,
        resource='port',
        resource_id=p['id'],
        resource_desc=desc,
        tenant_id=p['tenant_id'],
        instance_uuid=p['device_id'],
        network=p['network_id'])
    db_api.create_audit_record(context, **audit)


def port_audit_create(context, port):
    _port_audit(context, port, OPERATION_CREATE)


def port_audit_update(context, port):
    _port_audit(context, port, OPERATION_UPDATE)


def port_audit_delete(context, port):
    LOG.debug("Auditing port delete")
    _port_audit(context, port, OPERATION_DELETE)
