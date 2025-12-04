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

SERVER_IP='127.0.0.1'
SERVER_PORT=8080


def scalable_topology(K=3, T=20, auto_recover=True, num_slices=3):
    """
    Topologia spine–leaf con ridondanza e creazione dinamica delle slice:
    - K spine
    - 2*K leaf
    - K host per leaf
    - ogni leaf è collegato a tutti gli spine
    - ogni T sec cade un link leaf<->spine casuale
    """
    cleanup()
    net = Mininet(controller=RemoteController, link=TCLink)
    net.addController("c0")

    # ----- SPINE -----
    spine_switches = []
    for i in range(K):
        spine = net.addSwitch(f"s_spine_{i+1}")
        spine_switches.append(spine)

    # ----- LEAF -----
    leaf_switches = []
    for i in range(2 * K):
        leaf = net.addSwitch(f"s_leaf_{i+1}")
        leaf_switches.append(leaf)

        # collega ogni leaf a TUTTI gli spine
        for spine in spine_switches:
            net.addLink(spine, leaf, bw=100, delay="5ms")

        # aggiungi host
        for h in range(K):
            host = net.addHost(f"h{len(net.hosts) + 1}")
            net.addLink(host, leaf, bw=50)

    net.start()
    net.waitConnected()

    # ----- CREAZIONE DINAMICA DELLE SLICE -----
    def create_slices(hosts, num_slices):
        slices = {i: [] for i in range(num_slices)}
        host_list: list[Node] = hosts[:]
        random.shuffle(host_list)

        for idx, host in enumerate(host_list):
            slice_id = idx % num_slices
            slices[slice_id].append(host.IP())

        return slices

    slices = create_slices(net.hosts, num_slices)
    print("\nSlice create dinamicamente:", slices)

    # Salvataggio su file JSON per il controller
    with open("slices.json", "w") as f:
        json.dump(slices, f)

    request_result = requests.post(f'http://{SERVER_IP}:{SERVER_PORT}/api/v0/slices', 
                                   headers={'ContentType': 'application/json'},
                                   json=slices)
    if request_result.status_code != 200:
        print(f"Server returned status {request_result.status_code}")
        print(f'Body: {request_result.json()}')
        net.stop()
        cleanup()
        return
    
    fake_nodes = [{'type': 'h', 'id': '192.168.1.1'}, {'type': 'h', 'id': '192.168.1.2'}, {'type': 's', 'id': '0'}]
    #{"node0": node, "node1": node, "port0": str, "port1": str, "bw": float, "delay": float}
    fake_links = [{"node0": fake_nodes[0], "node1": fake_nodes[2], "port0": "0", "port1": "0", "bw": 1, "delay": 1},
                  {"node0": fake_nodes[2], "node1": fake_nodes[1], "port0": "1", "port1": "0", "bw": 1, "delay": 1}]
    request_result = requests.post(f'http://{SERVER_IP}:{SERVER_PORT}/api/v0/graph', 
                                   headers={'ContentType': 'application/json'},
                                   json={'nodes': fake_nodes, 'links': fake_links})
    if request_result.status_code != 200:
        print(f"Server returned status {request_result.status_code}, for net upload")
        print(f'Body: {request_result.json()}')
        net.stop()
        cleanup()
        return

    # ----- EVENTI AMBIENTALI -----
    def environmental_events():
        while True:
            time.sleep(T)
            leaf = random.choice(leaf_switches)
            spine = random.choice(spine_switches)

            print(f"\n*** EVENTO: disabilito link {spine.name} <-> {leaf.name}\n")
            net.configLinkStatus(spine.name, leaf.name, "down")

            link = net.linksBetween(spine, leaf)[0]
            print(f"Stato link dopo down: {link.intf1.status()} - {link.intf2.status()}")

            if auto_recover:
                time.sleep(T)
                print(f"\n*** RECOVERY: riattivo link {spine.name} <-> {leaf.name}\n")
                net.configLinkStatus(spine.name, leaf.name, "up")
                print(f"Stato link dopo up: {link.intf1.status()} - {link.intf2.status()}")

    #event_thread = threading.Thread(target=environmental_events, daemon=True)
    #event_thread.start()

    CLI(net)
    net.stop()
    cleanup()


if __name__ == "__main__":
    setLogLevel("info")
    scalable_topology(K=3, T=15, auto_recover=True, num_slices=3)
