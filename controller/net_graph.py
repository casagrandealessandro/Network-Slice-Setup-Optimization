import unittest
import copy

from typing import List, Dict, Tuple, Optional

class NetNode:
    def __init__(self):
        return
    
class NetSwitch(NetNode):
    def __init__(self, dpid):
        super().__init__()
        self.dpid = dpid

    def __eq__(self, value):
        if type(value) != type(self):
            return False
        return self.dpid == value.dpid

    def __str__(self):
        return f'Switch({self.dpid})'

class NetHost(NetNode):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip

    def __eq__(self, value):
        if type(value) != type(self):
            return False
        return self.ip == value.ip

    def __ne__(self, value):
        return not (self.__eq__(value))

    def __str__(self):
        return f'Host({self.ip})'

    def __hash__(self):
        return hash(self.ip)
    
class NetLink:
    def __init__(self, bw: int, delay: float, node0: NetNode, node1: NetNode, port1: str, port2: str):
        if node0 == node1:
            raise Exception("Attempting to link a node to itself")
        self.bw = bw
        self.delay = delay
        self.node0 = node0
        self.node1 = node1
        self.port1 = port1
        self.port2 = port2
    
    def __str__(self):
        return f'Link({self.node0} -> {self.node1})'

    def __eq__(self, value):
        if type(value) != type(self):
            return False
        return (self.node0 == value.node0 and self.node1 == value.node1) or \
        (self.node0 == value.node1 and self.node1 == value.node0)

    def contains_node(self, node: NetNode):
        return self.node0 == node or self.node1 == node

class NetGraph:
    def __init__(self):
        self.links: list[NetLink] = []
        self.nodes: list[NetNode] = []
        self.path_cache: Dict[NetNode, Dict[NetNode, Tuple[str, list[NetLink]]]] = {}
        return

    def cache_invalidate(self):
        length = len(self.path_cache)
        self.path_cache.clear()
        return length

    def _cache_add(self, src: NetNode, dst: NetNode, path: List[NetLink], opt_type: str):
        """
        Add a new path from src to dst to the cache, replacing the old
        path if present

        ## Parameters
        1. src Src node
        2. dst Dst node
        3. path The path between the nodes
        4. opt_type How the path was optimized

        ## Returns 
        The old path, if any
        """
        if not src in self.path_cache:
            self.path_cache[src] = {}
        if not dst in self.path_cache:
            self.path_cache[dst] = {}
        old_path = None
        if dst in self.path_cache[src]:
            old_path = self.path_cache[src][dst]
        if src in self.path_cache[dst]:
            if old_path is None:
                old_path = self.path_cache[dst][src]
            else:
                del self.path_cache[dst][src] #somehow someone inserted couple entries in the cache
        self.path_cache[src][dst] = (opt_type, copy.deepcopy(path))
        return old_path

    def cache_get(self, src: NetNode, dst: NetNode, opt_type: str):
        def get_impl(self, src: NetNode, dst: NetNode, opt_type: str, recursive: bool):
            if not src in self.path_cache:
                #Check with dst as first entry in table
                if not recursive:
                    return get_impl(self, dst, src, opt_type, True)
                return None

            #Check with src as first entry in table
            if not dst in self.path_cache[src]:
                if not recursive:
                    return get_impl(self, dst, src, opt_type, True)
                return None
            path = self.path_cache[src][dst]
            if path[0] != opt_type:
                return None
            return path[1]
        return get_impl(self, src, dst, opt_type, False)

    def cache_flatten(self):
        #flattened_cache = [dst. for dst in list(src.values() for src in self.path_cache.values())]
        flattened = []
        for src in self.path_cache.values():
            for dst in src.values():
                flattened.append(dst[1])
        return flattened

    def cache_invalidate_link(self, link: NetLink):
        inv_paths: list[Tuple[NetHost, NetHost, list[NetLink]]] = []
        for src, dsts in self.path_cache.items():
            for dst, path in dsts.items():
                if link in path[1]:
                    inv_paths.append((src, dst, path))
        for src, dst, _ in inv_paths:
            del self.path_cache[src][dst]
        return inv_paths

    def cache_invalidate_path(self, src: NetNode, dst: NetNode):
        def invalidate_path_impl(self, src: NetNode, dst: NetNode, recursive: bool):
            if not src in self.path_cache:
                #Check with dst as first entry in table
                if not recursive:
                    return invalidate_path_impl(self, dst, src, True)
                return False

            #Check with src as first entry in table
            if not dst in self.path_cache[src]:
                if not recursive:
                    return invalidate_path_impl(self, dst, src, True)
                return False
            del self.path_cache[src][dst]
            return True
        return invalidate_path_impl(self, src, dst, False)

    def modify_link(self, link: NetLink, **kwargs):
        if not link in self.links or len(kwargs) == 0:
            return []
        if "bw" not in kwargs.keys() and not "delay" in kwargs.keys():
            return []
        index = self.links.index(link)
        has_to_invalidate = False
        if "bw" in kwargs.keys() and self.links[index].bw != kwargs["bw"]:
            self.links[index].bw = kwargs["bw"]
            has_to_invalidate = True

        if "delay" in kwargs.keys() and self.links[index].delay != kwargs['delay']:
            self.links[index].delay = kwargs["delay"]
            has_to_invalidate = True 

        inv_paths = []
        if has_to_invalidate:
            inv_paths = self.cache_invalidate_link(link)
        return inv_paths

    
    def add_link(self, link: NetLink):
        if type(link.node0) == NetHost and type(link.node1) == NetHost:
            raise Exception("Cannot connect two hosts directly")
        links_with_node0 = list(filter(lambda curr_link: curr_link.contains_node(link.node0), self.links))
        links_with_node1 = list(filter(lambda curr_link: curr_link.contains_node(link.node1), self.links))

        for curr_link in links_with_node0:
            if curr_link.node0 == link.node0 and curr_link.port1 == link.port1:
                raise Exception(f'Port {link.port1} already used for {link.node0}')
            elif curr_link.node1 == link.node0 and curr_link.port2 == link.port1:
                raise Exception(f'Port {link.port1} already used for {link.node0}')

        for curr_link in links_with_node1:
            if curr_link.node0 == link.node1 and curr_link.port1 == link.port2:
                raise Exception(f'Port {link.port2} already used for {link.node1}')
            elif curr_link.node1 == link.node1 and curr_link.port2 == link.port2:
                raise Exception(f'Port {link.port2} already used for {link.node1}')
        
        if link in self.links:
            return
        self.links.append(copy.deepcopy(link))
        #Maybe invalidate cache? In my mind this is not required, for
        #now, given that we consider the topology itself to be static,
        #there should be no need to expect this method to be called
        #after network init
        return

    def add_node(self, node: NetNode):
        if node in self.nodes:
            return
        self.nodes.append(copy.deepcopy(node))
        #Nothing to do here
        return

    def contains_node(self, node: NetNode):
        return node in self.nodes

    def contains_link(self, link: NetLink):
        return link in self.links

    def find_paths(self, host1: NetHost, host2: NetHost, min_bw: float, max_delay: float):
        if host1 == host2:
            return []
        if not host1 in self.nodes or not host2 in self.nodes:
            return None
        paths: list[list[NetLink]] = []
        starting_points = list(filter(lambda link: link.contains_node(host1), self.links))
        if len(starting_points) != 1:
            return None
        start = starting_points[0]
        if host1 == start.node1: #switch the two
            start = copy.deepcopy(start)
            temp_node = start.node0
            start.node0 = start.node1
            start.node1 = temp_node
            temp_port = start.port1
            start.port1 = start.port2
            start.port2 = temp_port

        if start.bw < min_bw or start.delay > max_delay:
            return None

        init_path = [start]
        def find_path_sub(self: NetGraph, visited_nodes: List[NetNode], curr_path: List[NetLink], curr_min_bw: float, curr_delay: float):
            curr_link = curr_path[-1]
            next_node = None 
            if curr_link.node0 in visited_nodes:
                if curr_link.node1 in visited_nodes:
                    return
                next_node = curr_link.node1
            else:
                next_node = curr_link.node0
            if next_node == host2:
                paths.append(copy.deepcopy(curr_path))
                return
            possible_links = list(filter(lambda link: link.contains_node(next_node) \
                and link != curr_link and link not in curr_path, self.links))
            visited_nodes.append(next_node)
            for link in possible_links:
                new_path = copy.deepcopy(curr_path)
                if next_node == link.node1: #Maybe by the perspective of the user of the graph, 
                                            #if we put the link as is in the list, it would seem
                                            #like we are going in the wrong direction of the link.
                                            #I will simply swap the two nodes (and the ports)
                    link = copy.deepcopy(link)
                    temp = link.node0
                    link.node0 = link.node1
                    link.node1 = temp
                    temp_port = link.port1
                    link.port1 = link.port2
                    link.port2 = temp_port
                new_path.append(link)
                next_min_bw = min(curr_min_bw, float(link.bw))
                next_delay = curr_delay + link.delay
                if next_min_bw >= min_bw and next_delay <= max_delay:
                    find_path_sub(self, copy.deepcopy(visited_nodes), new_path, next_min_bw, next_delay)
        find_path_sub(self, [host1], init_path, start.bw, start.delay)
        if len(paths) == 0:
            return None
        #Do not add to cache, since we do not exactly know which
        #path is going to be selected
        return paths

    def find_path(self, host1: NetHost, host2: NetHost, **kwargs):
        opt = "none" if "opt" not in kwargs else kwargs["opt"]
        ignore_cache = False if "ignore_cache" not in kwargs else kwargs["ignore_cache"]
        min_bw = 0 if "min_bw" not in kwargs else kwargs["min_bw"]
        max_delay = float('inf') if "max_delay" not in kwargs else kwargs["max_delay"]
        if not ignore_cache:
            path: list[NetLink] = self.cache_get(host1, host2, opt)
            if path != None:
                curr_min_bw = min(link.bw for link in path)
                curr_delay = sum(link.delay for link in path)
                if curr_min_bw < min_bw or curr_delay > max_delay:
                    self.cache_invalidate_path(host1, host2)
                else:
                    return path

        opt_options = ["none", "bw", "delay", "hops"]
        if not opt in opt_options:
            raise Exception("Invalid optimization")
        paths = self.find_paths(host1, host2, min_bw, max_delay)
        if paths == None:
            return None
        the_path = None
        if opt == "none":
            the_path = paths[0]
        elif opt == "bw":
            paths.sort(key=lambda path: min(link.bw for link in path), reverse=True)
            if len(paths) > 1:
                curr_bw = min(link.bw for link in paths[0])
                paths = list(filter(lambda path: min(link.bw for link in path) == curr_bw, paths)) #Isolate all paths with bw equal to the current top one
                paths.sort(key=lambda path: sum(link.delay for link in path)) #Also sort them by delay
            the_path = paths[0]
        elif opt == "hops":
            paths.sort(key=lambda path: len(path))
            the_path = paths[0]
        else:
            paths.sort(key=lambda path: sum(link.delay for link in path))
            the_path = paths[0]
        self._cache_add(host1, host2, the_path, opt)
        return the_path

class NetGraphTests(unittest.TestCase):
    def test_host_equal(self):
        host1 = NetHost('192.168.1.1')
        host2 = NetHost('192.168.1.1')
        self.assertTrue(host1 == host2)

    def test_host_not_equal(self):
        host1 = NetHost('192.168.1.1')
        host2 = NetHost('192.168.1.2')
        self.assertTrue(host1 != host2)

    def test_link_equal(self):
        link1 = NetLink(1, 1, NetHost('192.168.1.1'), NetHost('192.168.1.2'), 0, 0)
        link2 = NetLink(1, 1, NetHost('192.168.1.2'), NetHost('192.168.1.1'), 0, 0)
        self.assertTrue(link1 == link2)

    def test_link_not_equal(self):
        link1 = NetLink(1, 1, NetHost('192.168.1.1'), NetHost('192.168.1.2'), 0, 0)
        link2 = NetLink(1, 1, NetHost('192.168.1.3'), NetHost('192.168.1.1'), 0, 0)
        self.assertTrue(link1 != link2)

    def test_simple_graph(self):
        host1 = NetHost('192.168.1.1')
        host2 = NetHost('192.168.1.2')
        sw1 = NetSwitch('0')
        link1 = NetLink(1, 1, NetHost('192.168.1.1'), NetSwitch('0'), 0, 0)
        link2 = NetLink(1, 1, NetSwitch('0'), NetHost('192.168.1.2'), 1, 0)
        graph = NetGraph()
        graph.add_node(host1)
        graph.add_node(host2)
        graph.add_node(sw1)
        graph.add_link(link1)
        graph.add_link(link2)
        self.assertEqual(len(graph.nodes), 3)
        self.assertEqual(len(graph.links), 2)
        path = graph.find_path(host1, host2)
        self.assertNotEqual(path, None)
        print(list(map(lambda link: str(link), path)))
        self.assertEqual(graph.find_path(host1, NetHost('192.168.1.3')), None)

    def test_complex_graph(self):
        graph = NetGraph()
        central_switches = [NetSwitch('0'), NetSwitch('1')]
        graph.add_node(central_switches[0])
        graph.add_node(central_switches[1])
        num_switches = 6
        hosts_per_switch = 2
        for curr_switch in range(num_switches):
            new_switch = NetSwitch(str(curr_switch + 2))
            graph.add_node(new_switch)
            graph.add_link(NetLink(1, 1, new_switch, central_switches[0], 0, curr_switch))
            graph.add_link(NetLink(1, 1, new_switch, central_switches[1], 1, curr_switch))
            for curr_host in range(hosts_per_switch):
                curr_ip = f'192.168.{curr_switch+1}.{curr_host+1}'
                new_host = NetHost(curr_ip)
                graph.add_node(new_host)
                graph.add_link(NetLink(1, 1, new_host, new_switch, 0, 2+curr_host))
        total_nodes = 2 + num_switches + num_switches * hosts_per_switch
        self.assertEqual(len(graph.nodes), total_nodes)
        path_bw    = graph.find_path(NetHost('192.168.1.1'), NetHost('192.168.6.1'), opt="bw")
        path_delay = graph.find_path(NetHost('192.168.1.1'), NetHost('192.168.6.1'), opt="delay")
        self.assertNotEqual(path_bw, None)
        self.assertNotEqual(path_delay, None)
        print()
        print(list(map(lambda link: str(link), path_bw)))
        print(list(map(lambda link: str(link), path_delay)))
        self.assertEqual(len(graph.cache_flatten()), 1)
        self.assertEqual(path_delay, graph.cache_get(NetHost('192.168.1.1'), NetHost('192.168.6.1'), "delay"))
        self.assertEqual(path_delay, graph.cache_get(NetHost('192.168.6.1'), NetHost('192.168.1.1'), "delay"))

    def test_simple_cache(self):
        host1 = NetHost('192.168.1.1')
        host2 = NetHost('192.168.1.2')
        host3 = NetHost('192.168.1.3')
        sw1 = NetSwitch('0')
        link1 = NetLink(1, 1, NetHost('192.168.1.1'), NetSwitch('0'), 0, 0)
        link2 = NetLink(1, 1, NetSwitch('0'), NetHost('192.168.1.2'), 1, 0)
        link3 = NetLink(1, 1, sw1, host3, 2, 0)
        graph = NetGraph()
        graph.add_node(host1)
        graph.add_node(host2)
        graph.add_node(host3)
        graph.add_node(sw1)
        graph.add_link(link1)
        graph.add_link(link2)
        graph.add_link(link3)
        path1 = graph.find_path(host1, host2)
        path2 = graph.find_path(host1, host3)
        path3 = graph.find_path(host2, host3)
        self.assertNotEqual(path1, None)
        self.assertNotEqual(path2, None)
        self.assertNotEqual(path3, None)
        paths = graph.cache_flatten()
        print()
        for path in paths:
            print(list(map(lambda link: str(link), path)))
        self.assertEqual(len(paths), 3)
        self.assertEqual(len(graph.modify_link(link1, bw=2)), 2)
        self.assertEqual(len(graph.cache_flatten()), 1)
        self.assertTrue(graph.cache_invalidate_path(host2, host3))
        self.assertEqual(len(graph.cache_flatten()), 0)

    def test_path_reqs(self):
        host1 = NetHost('192.168.1.1')
        host2 = NetHost('192.168.1.2')
        host3 = NetHost('192.168.1.3')
        sw1 = NetSwitch('0')
        link1 = NetLink(1, 1, NetHost('192.168.1.1'), NetSwitch('0'), 0, 0)
        link2 = NetLink(1, 1, NetSwitch('0'), NetHost('192.168.1.2'), 1, 0)
        link3 = NetLink(1, 1, sw1, host3, 2, 0)
        graph = NetGraph()
        graph.add_node(host1)
        graph.add_node(host2)
        graph.add_node(host3)
        graph.add_node(sw1)
        graph.add_link(link1)
        graph.add_link(link2)
        graph.add_link(link3)
        self.assertEqual(graph.find_path(host1, host2, min_bw=2), None)
        self.assertNotEqual(graph.find_path(host1, host2, min_bw=1), None)
        self.assertEqual(graph.find_path(host1, host2, max_delay=1), None)
        self.assertNotEqual(graph.find_path(host1, host2, max_delay=2), None)


if __name__ == "__main__":
    unittest.main()
