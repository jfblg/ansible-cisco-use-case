#!/usr/bin/env python
import json
from os import listdir
from os.path import isfile, join
from collections import namedtuple
from ciscoconfparse import CiscoConfParse

"""
Analysis of Ansible ios_facts.json file specific to configuration of DHCP snooping.
"""

__author__ = "Frantisek Janus"
__email__ = "inbox.jfblg@gmail.com"
__status__ = "Development"

HostRecord = namedtuple("HostRecord", "host int_list")

DHCP_SNOOP_VLAN = "500"
OUT_DIR = "inventories"
OUT_FILE = "inventory-dhcp-snoop.txt"


def main():
    device_fact_files = find_files("device_details")
    devices_to_change = process_configuration(device_fact_files)
    inventory_lines = output_preprocess(devices_to_change)
    create_inventory_file(inventory_lines, join(OUT_DIR, OUT_FILE))


def output_preprocess(data):
    return_list = []
    for item in data:
        line = "{} interfaces=\"{}\"".format(item.host, item.int_list)
        return_list.append(line + "\n")

    return return_list


def create_inventory_file(data, filename):
    """Creates ansible inventory files with interface variables"""

    with open(filename, 'w') as fh:
        fh.write("[ci_list]\n")
        fh.writelines(data)


def find_files(path):
    """ Find log in the defined directory which end with "iosfacts.json"
    """
    return [join(path, f) for f in listdir(path) if isfile(join(path, f)) if f.endswith("iosfacts.json")]


def process_configuration(filename_list, vlan=DHCP_SNOOP_VLAN):
    """Find ansible_net_config in the JSON and pass it to analyze_ios_config_file.

    Return which interfaces on which devices have VLAN1400 as access vlan configured
    """

    devices_to_configure = []

    for file in filename_list:
        with open(file, 'r') as fh:
            data_dic = json.load(fh)

            try:
                hostname = data_dic["ansible_facts"]["ansible_net_hostname"].lower()

            except TypeError:
                return False

            result = analyze_ios_config_file(data_dic, vlan)

            if result is not None and len(result) > 0:
                devices_to_configure.append(HostRecord(hostname, result))

    return devices_to_configure


def find_interface_beloging_to_vlan(ios_config, vlan="1"):
    """ Parse the IOS configuration and return list of interfaces configured in a specific VLAN.

    Return list of interfaces or None
    """
    parse = CiscoConfParse(ios_config.splitlines())

    found_interfaces = []

    for obj in parse.find_objects(r"interface"):
        if obj.re_search_children(r"switchport\saccess\svlan\s{}".format(vlan)):
            found_interfaces.append(obj.text.split()[1])

    if len(found_interfaces) == 0:
        return None
    return found_interfaces


def analyze_ios_config_file(data_dic, vlan):
    """Parse Cisco IOS configuration"""

    config_file = data_dic["ansible_facts"]["ansible_net_config"]
    if find_interface_beloging_to_vlan(config_file, vlan=vlan) is not None:
        return find_trunk_interfaces(config_file)


def find_trunk_interfaces(ios_config):
    """Parse the IOS config and return list of interfaces configured as trunk"""

    parse = CiscoConfParse(ios_config.splitlines())

    found_interfaces = []

    for obj in parse.find_objects(r"interface"):
        if obj.re_search_children(r"switchport\smode\strunk"):
            found_interfaces.append(obj.text.split()[1])

    if len(found_interfaces) == 0:
        return None
    return found_interfaces


if __name__ == '__main__':
    main()
