#!/usr/bin/env python3

import random
import threading
import time
import json

from mininet.net import Mininet, Node
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.clean import cleanup

import requests
import queues

SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080


def get_port_no(intf):
    try:
        return int(intf.ifindex)
    except AttributeError:
        # Extract the number from interface name "h1-eth0" -> 0
        return int(intf.name.split('eth')[-1])


def scalable_topology(K=3, T=20, auto_recover=True, num_slices=3):
    """
    Spine–leaf topology with redundancy and dynamic slice creation:
    - K spine switches
    - 2*K leaf switches
    - K hosts per leaf
    - each leaf is connected to all spines
    - every T seconds a random spine–leaf link fails
    """
    cleanup()
    net = Mininet(controller=RemoteController, link=TCLink)
    net.addController("c0")

    # ----- SPINE SWITCHES -----
    spine_switches = []
    for i in range(K):
        spine = net.addSwitch(f"s_spine_{i+1}", dpid=f"1{i+1:03d}", datapath='osvk', protocols='OpenFlow13')
        spine_switches.append(spine)

    # ----- LEAF SWITCHES -----
    leaf_switches = []
    uplink_factor = 2  # change this to tune redundancy

    for i in range(2 * K):
        leaf = net.addSwitch(f"s_leaf_{i+1}", dpid=f"2{i+1:03d}", datapath='osvk', protocols='OpenFlow13')
        leaf_switches.append(leaf)

        # Connect leaf to a subset of spines
        selected_spines = random.sample(spine_switches, min(uplink_factor, K))
        for spine in selected_spines:
             net.addLink(spine, leaf, delay="5ms", custom_bw="100")

        # Add hosts
        for _ in range(K):
            host = net.addHost(f"h{len(net.hosts) + 1}")
            net.addLink(host, leaf, custom_bw="50")


    net.start()
    net.waitConnected()

    # ----- DYNAMIC SLICE CREATION -----
    def create_slices(hosts, num_slices):
        slices = {i: [] for i in range(num_slices)}
        host_list: list[Node] = hosts[:]
        random.shuffle(host_list)

        for idx, host in enumerate(host_list):
            slice_id = idx % num_slices
            slices[slice_id].append(host.IP())

        return slices

    slices = create_slices(net.hosts, num_slices)
    print("\nDynamically created slices:", slices)

    # Save slices for the controller
    with open("slices.json", "w") as f:
        json.dump(slices, f)

    request_result = requests.post(
        f"http://{SERVER_IP}:{SERVER_PORT}/api/v0/slices",
        headers={'ContentType': 'application/json'},
        json=slices
    )

    if request_result.status_code != 200:
        print(f"Server returned status {request_result.status_code}")
        print(f"Body: {request_result.json()}")
        net.stop()
        cleanup()
        return

    # ----- CONVERT MININET TOPOLOGY FOR THE CONTROLLER -----
    nodes = []

    # Hosts
    for h in net.hosts:
        nodes.append({
            "type": "h",
            "id": h.IP()
        })

    # Switches
    for s in net.switches:
        nodes.append({
            "type": "s",
            "id": s.dpid
        })

    # ----- LINKS -----
    links = []
    for link in net.links:
        intf1 = link.intf1
        intf2 = link.intf2

        node0 = intf1.node
        node1 = intf2.node

        # Extract TCLink parameters
        params = intf1.params
        bw = params.get("custom_bw", 100)
        delay = params.get("delay", "0ms")

        links.append({
            "node0": {
                "type": "h" if node0 in net.hosts else "s",
                "id": node0.IP() if node0 in net.hosts else node0.dpid
            },
            "node1": {
                "type": "h" if node1 in net.hosts else "s",
                "id": node1.IP() if node1 in net.hosts else node1.dpid
            },
            "port0": str(get_port_no(intf1)),
            "port1": str(get_port_no(intf2)),
            "bw": bw,
            "delay": delay
        })

    # ----- SEND NETWORK GRAPH TO CONTROLLER -----
    request_result = requests.post(
        f"http://{SERVER_IP}:{SERVER_PORT}/api/v0/graph",
        headers={'ContentType': 'application/json'},
        json={'nodes': nodes, 'links': links}
    )

    if request_result.status_code != 200:
        print(f"Server returned status {request_result.status_code}, for net upload")
        print(f"Body: {request_result.json()}")
        net.stop()
        cleanup()
        return
    
    if not queues.load_queues('./qos.json', net.switches, SERVER_IP, SERVER_PORT, 100e6):
        print("QoS load failed")
        net.stop()
        cleanup()
        queues.clear_queues()
        return

    request_result = requests.post(
        f"http://{SERVER_IP}:{SERVER_PORT}/api/v0/init",
        headers={'ContentType': 'application/json'},
        json={'default_qos': 0}
    )

    if request_result.status_code != 200:
        print(f"Server returned status {request_result.status_code}, while trying to finalize init")
        print(f"Body: {request_result.json()}")
        net.stop()
        cleanup()
        queues.clear_queues()
        return

    # ----- ENVIRONMENTAL EVENTS -----
    def environmental_events():
        while True:
            time.sleep(T)
            leaf = random.choice(leaf_switches)
            spine = random.choice(spine_switches)

            print(f"\n*** EVENT: disabling link {spine.name} <-> {leaf.name}\n")
            net.configLinkStatus(spine.name, leaf.name, "down")

            link = net.linksBetween(spine, leaf)[0]
            print(f"Link state after down: {link.intf1.status()} - {link.intf2.status()}")

            if auto_recover:
                time.sleep(T)
                print(f"\n*** RECOVERY: enabling link {spine.name} <-> {leaf.name}\n")
                net.configLinkStatus(spine.name, leaf.name, "up")
                print(f"Link state after up: {link.intf1.status()} - {link.intf2.status()}")

    #event_thread = threading.Thread(target=environmental_events, daemon=True)
    #event_thread.start()

    CLI(net)

    request_result = requests.post(
        f"http://{SERVER_IP}:{SERVER_PORT}/api/v0/shutdown",
        headers={'ContentType': 'application/json'},
        json={}
    )

    net.stop()
    cleanup()
    queues.clear_queues()


if __name__ == "__main__":
    setLogLevel("info")
    scalable_topology(K=3, T=15, auto_recover=False, num_slices=3)
