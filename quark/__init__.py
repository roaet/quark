# Copyright (c) 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron.openstack.common.gettextutils import _
from oslo.config import cfg

CONF = cfg.CONF


quark_opts = [
    cfg.StrOpt('net_driver',
               default='quark.drivers.base.BaseDriver',
               help=_('The client to use to talk to the backend')),
    cfg.StrOpt('ipam_driver', default='quark.ipam.QuarkIpam',
               help=_('IPAM Implementation to use')),
    cfg.IntOpt('ipam_reuse_after', default=7200,
               help=_("Time in seconds til IP and MAC reuse"
                      "after deallocation.")),
    cfg.StrOpt("strategy_driver",
               default='quark.network_strategy.JSONStrategy',
               help=_("Tree of network assignment strategy")),
    cfg.StrOpt("default_network_type",
               default='BASE',
               help=_("Default network type to use when"
                      "none is provided"))
]


CONF.register_opts(quark_opts, "QUARK")
