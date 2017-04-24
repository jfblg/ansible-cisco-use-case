#!/usr/bin/env python
import json
from os import listdir
from os.path import isfile, join
from collections import namedtuple

"""
Analysis of Ansible ios_facts.json file specific to configuration of UDLD activation.
"""

__author__ = "Frantisek Janus"
__email__ = "inbox.jfblg@gmail.com"
__status__ = "Development"

HostRecord = namedtuple("HostRecord", "host int_list")

OUT_DIR = "inventories"
OUT_FILE = "inventory-udld.txt"


def main():
    device_fact_files = find_files("device_details")
    ci_db = analyze_found_files(device_fact_files)
    inventory_lines = output_preprocess(ci_db)
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


def analyze_found_files(filename_list):
    """ Analyze logs.
    :return: master_dic - IP to count assotiations:
    :rtype: dictionary
    """

    configuration_ci_list = []

    for file in filename_list:
        with open(file, 'r') as fh:
            result = analyze_iosfacts_json(json.load(fh))
            if len(result.int_list) > 0:
                configuration_ci_list.append(result)

    return configuration_ci_list


def analyze_iosfacts_json(data_dic):
    """Analyze contenct of the file as needed"""

    int_list = []

    try:
        hostname = data_dic["ansible_facts"]["ansible_net_hostname"].lower()

    except TypeError:
        return False

    for int_name, int_details in data_dic["ansible_facts"]["ansible_net_interfaces"].items():
        try:
            if "Vlan" not in int_name and "Loopback" not in int_name and "Port-channel" not in int_name:
                if int_details["operstatus"] == "up":
                    if "10GBase" in int_details["mediatype"] or "SFP" in int_details["mediatype"]:
                        int_list.append(int_name)
        except TypeError:
            print("ERROR: {}".format(int_name))

    return HostRecord(host=hostname, int_list=int_list)


if __name__ == '__main__':
    main()
