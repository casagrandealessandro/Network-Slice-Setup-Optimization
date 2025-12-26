#!/usr/bin/env python3

import random
import threading
import time
import json
from subprocess import Popen
import os

from comnetsemu.net import Containernet, VNFManager
from comnetsemu.node import DockerHost

from mininet.net import Node
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.clean import cleanup

import requests
import queues
from subprocess import Popen, PIPE
from controller.dns_api import DNSServer

SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080

COMMON_CONFIG_FILE = "./config/common.json"


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
    docker_img_ls = Popen(['docker image ls | grep dns-mn'], shell=True, stdout=PIPE, stderr=PIPE)
    exit_status = docker_img_ls.wait()
    if exit_status != 0 and exit_status != 1:
        print(f"stderr: {docker_img_ls.stderr.read().decode()}")
        print(f"stdout: {docker_img_ls.stdout.read().decode()}")
        print(f"docker image ls failed, skip")
    else:
        if exit_status == 1 or len(docker_img_ls.stdout.read().decode().split()) <= 1:
            print("Missing docker image for dns server, did you build it?")
            return 
    
    cleanup()
    net = Containernet(controller=RemoteController, link=TCLink)
    mgr = VNFManager(net)
    net.addController("c0")

    with open(COMMON_CONFIG_FILE) as conf:
        common_config = json.load(conf)

    cwd = os.getcwd()

    print(f"Using config folder: {cwd}/config/dns_config")

    # Start DNS server in a container
    # The container's name will be 'dns_server'
    dns_server: DockerHost = net.addDockerHost('dns_server', dimage="dns-mn", dmcd="/etc/dns", ip=f"{common_config['dns_ip']}", 
                                           docker_args=
                                           {
                                                "ports" : { "5380/tcp": 5380, "53/tcp": 53, "53/udp": 53 },
                                                "environment": {"DNS_SERVER_ADMIN_PASSWORD": "admin"},
                                                "volumes": {
                                                    f"{cwd}/config/dns_config": {"bind": "/opt/technitium/dns/sh", "mode": "rw"}
                                                }
                                            })

    # ----- SPINE SWITCHES -----
    spine_switches = []
    for i in range(K):
        spine = net.addSwitch(f"s_spine_{i+1}", dpid=f"1{i+1:03d}", datapath='osvk', protocols='OpenFlow13')
        spine_switches.append(spine)
        
    net.addLink(spine_switches[0], dns_server)


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

        # Add hosts as DockerHost
        for _ in range(K):
            #host = net.addHost(f"h{len(net.hosts) + 1}")
            host = net.addDockerHost(
                f"h{len(net.hosts) + 1}",
                dimage="dev_test",
                docker_args={"hostname": f"h{len(net.hosts) + 1}"}
            )
            net.addLink(host, leaf, custom_bw="50")


    net.start()
    # This will make sure that the REST server will be up
    # by the time we use it
    net.waitConnected()

    #try:
    #    dns_url = f"127.0.0.1:{common_config['dns_api_port']}"
    #    dns_conn: DNSServer = DNSServer.connect("admin", "admin", dns_url)
    #except:
    #    import traceback
    #    traceback.print_exc()
    #    print(f"DNS login failed")
    #    net.stop()
    #    cleanup()
    #    return
    #
    #if not isinstance(dns_conn, DNSServer):
    #    print(f"DNS login failed")
    #    net.stop()
    #    cleanup()
    #    return
    #
    #print(f"DNS session token: {dns_conn.token}")
    #print(f"Create zone: {dns_conn.create_zone_for_net('service.mn')}")
    #print(f"Add record: {dns_conn.add_record('0.service.mn', 'service.mn', 3600, '10.0.0.1')}")
    #print(f"Records: {dns_conn.get_zone_records('service.mn')}")

    # ----- DYNAMIC SLICE CREATION -----
    def create_slices(hosts, num_slices):
        slices = {i: [] for i in range(num_slices)}
        host_list: list[Node] = hosts[:]
        random.shuffle(host_list)

        for idx, host in enumerate(host_list):
            slice_id = idx % num_slices
            slices[slice_id].append(host.IP())

        return slices

    slices = create_slices(list(filter(lambda host: host.name != "dns_server", net.hosts)), num_slices)
    print("\nDynamically created slices:", slices)

    # Save slices for the controller
    with open("slices.json", "w") as f:
        json.dump(slices, f)

    # Send slices to controller
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
    
    # Attempt to load QoS from file, configure them on the switches and send them
    # to the controller
    if not queues.load_queues('./qos.json', net.switches, SERVER_IP, SERVER_PORT, 100e6):
        print("QoS load failed")
        net.stop()
        cleanup()
        queues.clear_queues()
        return

    # Send network init to controller. The controller will
    # then setup flows and other things
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

    # ----- SERVICE INITIALIZATION -----
    print("\n*** Starting Services ***\n")
    
    # Web service on slice 0
    web_server_ip = slices[0][0]
    web_client_ip = slices[0][1]
    
    # Streaming service on slice 2
    stream_server_ip = slices[2][0]
    stream_client_ip = slices[2][1]
    
    # Find host objects
    web_server_host = None
    web_client_host = None
    stream_server_host = None
    stream_client_host = None
    
    for host in net.hosts:
        if host.IP() == web_server_ip:
            web_server_host = host
        elif host.IP() == web_client_ip:
            web_client_host = host
        elif host.IP() == stream_server_ip:
            stream_server_host = host
        elif host.IP() == stream_client_ip:
            stream_client_host = host
    
    print(f"Web Server: {web_server_host.name} ({web_server_ip})")
    print(f"Web Client: {web_client_host.name} ({web_client_ip})")
    print(f"Stream Server: {stream_server_host.name} ({stream_server_ip})")
    print(f"Stream Client: {stream_client_host.name} ({stream_client_ip})")
    
    # Start server containers
    print(f"\nStarting web server on {web_server_host.name}...")
    web_server_container = mgr.addContainer(
        "web_server",
        web_server_host.name,
        "nginx:alpine",
        "nginx -g 'daemon off;'"
    )
    
    print(f"Starting stream server on {stream_server_host.name}...")
    stream_server_container = mgr.addContainer(
        "stream_server",
        stream_server_host.name,
        "nginx:alpine",
        "nginx -g 'daemon off;'"
    )
    
    time.sleep(3)
    
    # Simulate streaming with a large file (100 MB)
    print("Creating video file...")
    import docker
    docker_client = docker.from_env()
    container = docker_client.containers.get("stream_server")
    container.exec_run('sh -c "dd if=/dev/zero of=/usr/share/nginx/html/video.dat bs=1M count=100"')
    
    # Start client services
    print("\nStarting client services...")
    web_client_host.cmd(f'while true; do curl -s http://{web_server_ip}:80 > /dev/null 2>&1; sleep 1; done &')
    stream_client_host.cmd(f'while true; do curl -s -o /dev/null http://{stream_server_ip}:80/video.dat 2>&1; sleep 2; done &')
    
    print("\n*** Services started ***\n")

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

    # Request that the controller destroys the current network
    # state
    request_result = requests.post(
        f"http://{SERVER_IP}:{SERVER_PORT}/api/v0/shutdown",
        headers={'ContentType': 'application/json'},
        json={}
    )

    #print(f"Update DNS record: {dns_conn.update_record('0.service.mn', 'service.mn', '10.0.0.1', '10.0.0.2')}")
    #print(f"Remove DNS record: {dns_conn.delete_record('0.service.mn', 'service.mn', '10.0.0.2')}")
    #print(f"Delete zone: {dns_conn.delete_zone('service.mn')}")
    #del dns_conn

    # Stop services clients
    if web_client_host:
        web_client_host.cmd('pkill -f "curl"')
    
    if stream_client_host:
        stream_client_host.cmd('pkill -f "curl"')
    
    # Stop and remove server containers using VNFManager
    try:
        mgr.removeContainer("web_server")
        mgr.removeContainer("stream_server")
    except Exception as e:
        print(f"Error removing containers: {e}")

    net.stop()
    mgr.stop()
    cleanup()
    queues.clear_queues()


if __name__ == "__main__":
    setLogLevel("info")
    scalable_topology(K=3, T=15, auto_recover=False, num_slices=3)
