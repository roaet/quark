# Copyright 2013 Openstack Foundation
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

import datetime
import inspect

import netaddr
from neutron.db.sqlalchemyutils import paginate_query
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from oslo.config import cfg
from oslo.utils import timeutils
from sqlalchemy import event
from sqlalchemy import func as sql_func
from sqlalchemy import and_, asc, desc, orm, or_, not_

from quark.db import models
from quark import network_strategy


STRATEGY = network_strategy.STRATEGY
LOG = logging.getLogger(__name__)
CONF = cfg.CONF


ONE = "one"
ALL = "all"


# NOTE(jkoelker) init event listener that will ensure id is filled in
#                on object creation (prior to commit).
def _perhaps_generate_id(target, args, kwargs):
    if hasattr(target, 'id') and target.id is None:
        target.id = uuidutils.generate_uuid()


# NOTE(jkoelker) Register the event on all models that have ids
for _name, klass in inspect.getmembers(models, inspect.isclass):
    if klass is models.HasId:
        continue

    if models.HasId in klass.mro():
        event.listen(klass, "init", _perhaps_generate_id)


def _listify(filters):
    for key in ["name", "network_id", "id", "device_id", "tenant_id",
                "subnet_id", "mac_address", "shared", "version", "segment_id",
                "device_owner", "ip_address", "used_by_tenant_id", "group_id"]:
        if key in filters:
            if not filters[key]:
                continue
            listified = filters[key]
            if not isinstance(listified, list):
                listified = [listified]
            filters[key] = listified


def _model_query(context, model, filters, fields=None):
    filters = filters or {}
    model_filters = []

    if filters.get("name"):
        model_filters.append(model.name.in_(filters["name"]))

    if filters.get("network_id"):
        model_filters.append(model.network_id.in_(filters["network_id"]))

    if filters.get("mac_address"):
        model_filters.append(model.mac_address.in_(filters["mac_address"]))

    if filters.get("segment_id"):
        model_filters.append(model.segment_id.in_(filters["segment_id"]))

    if filters.get("id"):
        model_filters.append(model.id.in_(filters["id"]))

    if filters.get("group_id"):
        model_filters.append(model.group_id.in_(filters["group_id"]))

    if filters.get("reuse_after"):
        reuse_after = filters["reuse_after"]
        reuse = (timeutils.utcnow() -
                 datetime.timedelta(seconds=reuse_after))
        model_filters.append(model.deallocated_at <= reuse)

    if filters.get("subnet_id"):
        model_filters.append(model.subnet_id.in_(filters["subnet_id"]))

    if filters.get("deallocated"):
        model_filters.append(model.deallocated == filters["deallocated"])

    if filters.get("_deallocated") is not None:
        if filters.get("_deallocated"):
            model_filters.append(model._deallocated == 1)
        else:
            model_filters.append(model._deallocated != 1)

    if filters.get("address"):
        model_filters.append(model.address == filters["address"])

    if filters.get("version"):
        model_filters.append(model.version.in_(filters["version"]))

    if filters.get("ip_version"):
        model_filters.append(model.ip_version == filters["ip_version"])

    if filters.get("ip_address") and model == models.IPAddress:
        model_filters.append(model.address.in_(
            [netaddr.IPAddress(ip).ipv6().value for ip in
             filters["ip_address"]]))

    if filters.get("type") and model == models.IPAddress:
        model_filters.append(model.address_type == filters["type"])

    if filters.get("mac_address_range_id"):
        model_filters.append(model.mac_address_range_id ==
                             filters["mac_address_range_id"])

    if filters.get("cidr"):
        model_filters.append(model.cidr == filters["cidr"])

    if filters.get("service"):
        model_filters.append(model.service == filters["service"])

    # Inject the tenant id if none is set. We don't need unqualified queries.
    # This works even when a non-shared, other-tenant owned network is passed
    # in because the authZ checks that happen in Neutron above us yank it back
    # out of the result set.
    if not filters.get("tenant_id") and not context.is_admin:
        filters["tenant_id"] = [context.tenant_id]

    # Begin:Added for RM6299
    if filters.get("used_by_tenant_id"):
        model_filters.append(model.used_by_tenant_id.in_(
                             filters["used_by_tenant_id"]))

    if filters.get("tenant_id"):
        if model == models.IPAddress:
            model_filters.append(model.used_by_tenant_id.in_(
                                 filters["tenant_id"]))
        else:
            model_filters.append(model.tenant_id.in_(filters["tenant_id"]))
    # End: Added for RM6299
    if filters.get("device_owner"):
        model_filters.append(model.device_owner.in_(filters["device_owner"]))

    return model_filters


def scoped(f):
    def wrapped(*args, **kwargs):
        scope = None
        if "scope" in kwargs:
            scope = kwargs.pop("scope")
        if scope not in [None, ALL, ONE]:
            raise Exception("Invalid scope")
        _listify(kwargs)

        res = f(*args, **kwargs)
        if not res:
            return
        if "order_by" in kwargs:
            res = res.order_by(kwargs["order_by"])

        if scope == ALL:
            if isinstance(res, list):
                return res
            return res.all()
        elif scope == ONE:
            if isinstance(res, list):
                return res[0]
            return res.first()
        return res
    return wrapped


@scoped
def port_find(context, limit=None, sorts=None, marker_obj=None, fields=None,
              **filters):
    query = context.session.query(models.Port).options(
        orm.joinedload(models.Port.ip_addresses))
    model_filters = _model_query(context, models.Port, filters)
    if filters.get("ip_address_id"):
        model_filters.append(models.Port.ip_addresses.any(
            models.IPAddress.id.in_(filters["ip_address_id"])))

    if filters.get("device_id"):
        model_filters.append(models.Port.device_id.in_(filters["device_id"]))

    if "join_security_groups" in filters:
        query = query.options(orm.joinedload(models.Port.security_groups))

    if fields and "port_subnets" in fields:
        query = query.options(orm.joinedload("ip_addresses.subnet"))
        query = query.options(
            orm.joinedload("ip_addresses.subnet.dns_nameservers"))
        query = query.options(
            orm.joinedload("ip_addresses.subnet.routes"))
    return paginate_query(query.filter(*model_filters), models.Port, limit,
                          sorts, marker_obj)


@scoped
def port_find_by_ip_address(context, **filters):
    query = context.session.query(models.IPAddress).options(
        orm.joinedload(models.IPAddress.ports))
    model_filters = _model_query(context, models.IPAddress, filters)
    return query.filter(*model_filters)


def port_count_all(context, **filters):
    query = context.session.query(sql_func.count(models.Port.id))
    model_filters = _model_query(context, models.Port, filters)
    return query.filter(*model_filters).scalar()


def port_create(context, **port_dict):
    port = models.Port()
    port.update(port_dict)
    port["tenant_id"] = context.tenant_id
    if "addresses" in port_dict:
        port["ip_addresses"].extend(port_dict["addresses"])
    context.session.add(port)
    return port


def port_disassociate_ip(context, ports, address):
    assocs_to_remove = [assoc for assoc in address.associations
                        if assoc.port in ports]
    for assoc in assocs_to_remove:
        context.session.delete(assoc)
        # NOTE(thomasem): Need to update in-session model for caller.
        address.associations.remove(assoc)
    context.session.add(address)
    return address


def port_associate_ip(context, ports, address, enable_port=None):
    for port in ports:
        assoc = models.PortIpAssociation()
        assoc.port_id = port.id
        assoc.ip_address_id = address.id
        assoc.enabled = port.id in enable_port if enable_port else False
        address.associations.append(assoc)
    context.session.add(address)
    return address


def update_port_associations_for_ip(context, ports, address):
    assoc_ports = set(address.ports)
    new_ports = set(ports)
    new_address = port_associate_ip(context, new_ports - assoc_ports,
                                    address)
    return port_disassociate_ip(context,
                                assoc_ports - new_ports, new_address)


def port_update(context, port, **kwargs):
    if "addresses" in kwargs:
        port["ip_addresses"] = kwargs.pop("addresses")
    port.update(kwargs)
    context.session.add(port)
    return port


def port_delete(context, port):
    context.session.delete(port)


def ip_address_update(context, address, **kwargs):
    address.update(kwargs)
    context.session.add(address)
    return address


def ip_address_create(context, **address_dict):
    ip_address = models.IPAddress()
    address = address_dict.pop("address")
    ip_address.update(address_dict)
    ip_address["address"] = int(address.ipv6())
    ip_address["address_readable"] = str(address)
    ip_address["used_by_tenant_id"] = context.tenant_id
    ip_address["_deallocated"] = 0
    ip_address["allocated_at"] = timeutils.utcnow()
    context.session.add(ip_address)
    return ip_address


def ip_address_delete(context, addr):
    context.session.delete(addr)


@scoped
def ip_address_find(context, lock_mode=False, **filters):
    query = context.session.query(models.IPAddress)

    if lock_mode:
        query = query.with_lockmode("update")

    model_filters = _model_query(context, models.IPAddress, filters)

    if filters.get("device_id"):
        model_filters.append(models.IPAddress.ports.any(
            models.Port.device_id.in_(filters["device_id"])))

    if filters.get("service"):
        model_filters.append(models.IPAddress.ports.any(
            models.Port.service == filters["service"]))

    if filters.get("port_id"):
        model_filters.append(models.IPAddress.ports.any(
            models.Port.id == filters['port_id']))

    if filters.get("address_type"):
        model_filters.append(
            models.IPAddress.address_type == filters['address_type'])

    return query.filter(*model_filters)


@scoped
def mac_address_find(context, lock_mode=False, **filters):
    query = context.session.query(models.MacAddress)
    if lock_mode:
        query = query.with_lockmode("update")
    model_filters = _model_query(context, models.MacAddress, filters)
    return query.filter(*model_filters)


def mac_address_delete(context, mac_address):
    context.session.delete(mac_address)


def mac_address_range_find_allocation_counts(context, address=None,
                                             use_forbidden_mac_range=False):
    count = sql_func.count(models.MacAddress.address)
    query = context.session.query(models.MacAddressRange,
                                  count.label("count")).with_lockmode("update")
    query = query.outerjoin(models.MacAddress)
    query = query.group_by(models.MacAddressRange.id)
    query = query.order_by(desc(count))
    if address:
        query = query.filter(models.MacAddressRange.last_address >= address)
        query = query.filter(models.MacAddressRange.first_address <= address)
    query = query.filter(models.MacAddressRange.next_auto_assign_mac != -1)
    if not use_forbidden_mac_range:
        query = query.filter(models.MacAddressRange.do_not_use == '0')  # noqa
    query = query.limit(1)
    return query.first()


@scoped
def mac_address_range_find(context, **filters):
    query = context.session.query(models.MacAddressRange)
    model_filters = _model_query(context, models.MacAddressRange, filters)
    return query.filter(*model_filters)


def mac_address_range_create(context, **range_dict):
    new_range = models.MacAddressRange()
    new_range.update(range_dict)
    context.session.add(new_range)
    return new_range


def mac_address_range_delete(context, mac_address_range):
    context.session.delete(mac_address_range)


def mac_address_range_update(context, mac_range, **kwargs):
    mac_range.update(kwargs)
    context.session.add(mac_range)
    return mac_range


def mac_address_update(context, mac, **kwargs):
    mac.update(kwargs)
    context.session.add(mac)
    return mac


def mac_address_create(context, **mac_dict):
    mac_address = models.MacAddress()
    mac_address.update(mac_dict)
    mac_address["tenant_id"] = context.tenant_id
    mac_address["deallocated"] = False
    mac_address["deallocated_at"] = None
    context.session.add(mac_address)
    return mac_address


INVERT_DEFAULTS = 'invert_defaults'


@scoped
def network_find(context, limit=None, sorts=None, marker=None,
                 page_reverse=False, fields=None, **filters):
    ids = []
    defaults = []
    if "id" in filters:
        ids, defaults = STRATEGY.split_network_ids(context, filters["id"])
        if ids:
            filters["id"] = ids
        else:
            filters.pop("id")

    if "shared" in filters:
        defaults = STRATEGY.get_assignable_networks(context)
        if True in filters["shared"]:
            if ids:
                defaults = [net for net in ids if net in defaults]
                filters.pop("id")
            if not defaults:
                return []
        else:
            defaults.insert(0, INVERT_DEFAULTS)
        filters.pop("shared")
    return _network_find(context, limit, sorts, marker, page_reverse, fields,
                         defaults=defaults, **filters)


def _network_find(context, limit, sorts, marker, page_reverse, fields,
                  defaults=None, **filters):
    query = context.session.query(models.Network)
    model_filters = _model_query(context, models.Network, filters, query)

    if defaults:
        invert_defaults = False
        if INVERT_DEFAULTS in defaults:
            invert_defaults = True
            defaults.pop(0)
        if filters and invert_defaults:
            query = query.filter(and_(not_(models.Network.id.in_(defaults)),
                                      and_(*model_filters)))
        elif filters and not invert_defaults:
            query = query.filter(or_(models.Network.id.in_(defaults),
                                     and_(*model_filters)))

        elif not invert_defaults:
            query = query.filter(models.Network.id.in_(defaults))
    else:
        query = query.filter(*model_filters)

    if "join_subnets" in filters:
        query = query.options(orm.joinedload(models.Network.subnets))

    return paginate_query(query, models.Network, limit, sorts, marker)


def network_create(context, **network):
    new_net = models.Network()
    new_net.update(network)
    context.session.add(new_net)
    return new_net


def network_update(context, network, **kwargs):
    network.update(kwargs)
    context.session.add(network)
    return network


def network_count_all(context):
    query = context.session.query(sql_func.count(models.Network.id))
    return query.filter(
        models.Network.tenant_id == context.tenant_id).scalar()


def network_delete(context, network):
    context.session.delete(network)


def subnet_find_ordered_by_most_full(context, net_id, **filters):
    count = sql_func.count(models.IPAddress.address).label("count")
    size = (models.Subnet.last_ip - models.Subnet.first_ip)
    query = context.session.query(models.Subnet, count).with_lockmode('update')
    query = query.filter_by(do_not_use=False)
    query = query.outerjoin(models.Subnet.generated_ips)
    query = query.group_by(models.Subnet.id)
    query = query.order_by(
        asc(models.Subnet.ip_version),
        asc(size - count))

    query = query.filter(models.Subnet.network_id == net_id)
    if "ip_version" in filters:
        query = query.filter(models.Subnet.ip_version == filters["ip_version"])
    if "segment_id" in filters and filters["segment_id"]:
        query = query.filter(models.Subnet.segment_id == filters["segment_id"])
    if "subnet_id" in filters and filters["subnet_id"]:
        query = query.filter(models.Subnet.id.in_(filters["subnet_id"]))
    query = query.filter(models.Subnet.next_auto_assign_ip != -1)
    return query


@scoped
def subnet_find(context, limit=None, page_reverse=False, sorts=None,
                marker_obj=None, **filters):
    if "shared" in filters and True in filters["shared"]:
        return []
    query = context.session.query(models.Subnet)
    model_filters = _model_query(context, models.Subnet, filters)

    if "join_dns" in filters:
        query = query.options(orm.joinedload(models.Subnet.dns_nameservers))

    if "join_routes" in filters:
        query = query.options(orm.joinedload(models.Subnet.routes))

    return paginate_query(query.filter(*model_filters), models.Subnet, limit,
                          sorts, marker_obj)


def subnet_count_all(context, **filters):
    query = context.session.query(sql_func.count(models.Subnet.id))
    if filters.get("network_id"):
        query = query.filter(
            models.Subnet.network_id == filters["network_id"])
    query.filter(models.Subnet.tenant_id == context.tenant_id)
    return query.scalar()


def subnet_delete(context, subnet):
    context.session.delete(subnet)


def subnet_create(context, **subnet_dict):
    subnet = models.Subnet()
    subnet.update(subnet_dict)
    subnet["tenant_id"] = context.tenant_id
    context.session.add(subnet)
    return subnet


def subnet_update(context, subnet, **kwargs):
    subnet.update(kwargs)
    context.session.add(subnet)
    return subnet


@scoped
def route_find(context, fields=None, **filters):
    query = context.session.query(models.Route)
    model_filters = _model_query(context, models.Route, filters)
    return query.filter(*model_filters)


def route_create(context, **route_dict):
    new_route = models.Route()
    new_route.update(route_dict)
    new_route["tenant_id"] = context.tenant_id
    context.session.add(new_route)
    return new_route


def route_update(context, route, **kwargs):
    route.update(kwargs)
    context.session.add(route)
    return route


def route_delete(context, route):
    context.session.delete(route)


def dns_create(context, **dns_dict):
    dns_nameserver = models.DNSNameserver()
    ip = dns_dict.pop("ip")
    dns_nameserver.update(dns_dict)
    dns_nameserver["ip"] = int(ip)
    dns_nameserver["tenant_id"] = context.tenant_id
    context.session.add(dns_nameserver)
    return dns_nameserver


def dns_delete(context, dns):
    context.session.delete(dns)


@scoped
def security_group_find(context, **filters):
    query = context.session.query(models.SecurityGroup).options(
        orm.joinedload(models.SecurityGroup.rules))
    model_filters = _model_query(context, models.SecurityGroup, filters)
    return query.filter(*model_filters)


@scoped
def security_group_count(context, **filters):
    query = context.session.query(sql_func.count(models.SecurityGroup.id))
    model_filters = _model_query(context, models.SecurityGroup, filters)
    return query.filter(*model_filters).scalar()


@scoped
def ports_with_security_groups_find(context):
    query = context.session.query(models.Port)
    query = query.join(models.Port.security_groups)
    query = query.options(orm.contains_eager(models.Port.security_groups))
    return query


@scoped
def ports_with_security_groups_count(context):
    query = context.session.query(
        sql_func.count(models.port_group_association_table.c.port_id))
    return query.scalar()


def security_group_create(context, **sec_group_dict):
    new_group = models.SecurityGroup()
    new_group.update(sec_group_dict)
    new_group["tenant_id"] = context.tenant_id
    context.session.add(new_group)
    return new_group


def security_group_update(context, group, **kwargs):
    group.update(kwargs)
    context.session.add(group)
    return group


def security_group_delete(context, group):
    context.session.delete(group)


@scoped
def security_group_rule_find(context, **filters):
    query = context.session.query(models.SecurityGroupRule)
    model_filters = _model_query(context, models.SecurityGroupRule, filters)
    return query.filter(*model_filters)


def security_group_rule_create(context, **rule_dict):
    new_rule = models.SecurityGroupRule()
    new_rule.update(rule_dict)
    new_rule.group_id = rule_dict['security_group_id']
    new_rule.tenant_id = rule_dict['tenant_id']
    context.session.add(new_rule)
    return new_rule


def security_group_rule_delete(context, rule):
    context.session.delete(rule)


def ip_policy_create(context, **ip_policy_dict):
    new_policy = models.IPPolicy()
    exclude = ip_policy_dict.pop("exclude")
    ip_set = netaddr.IPSet()
    for excluded_cidr in exclude:
        cidr_net = netaddr.IPNetwork(excluded_cidr).ipv6()
        new_policy["exclude"].append(
            models.IPPolicyCIDR(cidr=excluded_cidr,
                                first_ip=cidr_net.first,
                                last_ip=cidr_net.last))
        ip_set.add(excluded_cidr)
    ip_policy_dict["size"] = ip_set.size
    new_policy.update(ip_policy_dict)
    new_policy["tenant_id"] = context.tenant_id
    context.session.add(new_policy)
    return new_policy


@scoped
def ip_policy_find(context, **filters):
    query = context.session.query(models.IPPolicy)
    model_filters = _model_query(context, models.IPPolicy, filters)
    return query.filter(*model_filters)


def ip_policy_update(context, ip_policy, **ip_policy_dict):
    exclude = ip_policy_dict.pop("exclude", [])
    if exclude:
        ip_policy["exclude"] = []
        ip_set = netaddr.IPSet()
        for excluded_cidr in exclude:
            cidr_net = netaddr.IPNetwork(excluded_cidr).ipv6()
            ip_policy["exclude"].append(
                models.IPPolicyCIDR(cidr=excluded_cidr,
                                    first_ip=cidr_net.first,
                                    last_ip=cidr_net.last))
            ip_set.add(excluded_cidr)
        ip_policy_dict["size"] = ip_set.size

    ip_policy.update(ip_policy_dict)
    context.session.add(ip_policy)
    return ip_policy


def ip_policy_delete(context, ip_policy):
    context.session.delete(ip_policy)
