import unittest
import copy

from typing import List, Dict, Tuple, Optional

class NetNode:
    """
    Base class for our network graph 
    """
    def __init__(self):
        return
    
class NetSwitch(NetNode):
    """
    A simple switch, needs only
    the dpid of the "real" switch
    """
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
    """
    Represents an host with
    a single IP address
    """
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
        """
        Useful for when an host is
        used as key in a dictionary
        """
        return hash(self.ip)
    
class NetLink:
    """
    A link between two nodes. Ideally the link should be between "interfaces"
    where each "interface" is associated to a node, but this will make
    due for our purposes
    """
    def __init__(self, bw: int, delay: float, node0: NetNode, node1: NetNode, port1: str, port2: str):
        """
        Create a new link

        bw and delay are expected to be in Mb/s and ms respectively, but,
        in reality, the graph implementation does not really care.
        As long as the units are consistent, the implementation
        will behave correctly
        """
        if node0 == node1:
            raise Exception("Attempting to link a node to itself")
        # Current bw
        self.bw = bw 
        # Max possible bw
        self.max_bw = bw 
        self.delay = delay
        self.node0 = node0
        self.node1 = node1
        self.port1 = port1
        self.port2 = port2
        self.port1_down = False 
        self.port2_down = False
    
    def __str__(self):
        return f'Link({self.node0} -> {self.node1})'

    def __eq__(self, value):
        """
        Returns whether a link is equal to self. 

        N.B.! Ports are not taken into consideration,
        so if two nodes are connected by two different
        links (directly) those links are considered
        as one and the same
        """
        if type(value) != type(self):
            return False
        return (self.node0 == value.node0 and self.node1 == value.node1) or \
        (self.node0 == value.node1 and self.node1 == value.node0)

    def contains_node(self, node: NetNode):
        """
        Returns whether the link is connected to a specific node
        """
        return self.node0 == node or self.node1 == node
    
    def is_down(self):
        """
        Returns if either of the two ports
        is currently down
        """
        return self.port1_down or self.port2_down
    
    def exchange_nodes(self):
        """
        Exchange the value for the two nodes. Useful 
        if one wants to always have a certain
        type of node as the first or second node
        """
        self.node0, self.node1 = self.node1, self.node0
        self.port1, self.port2 = self.port2, self.port1
        self.port1_down, self.port2_down = self.port2_down, self.port1_down

    def get_node_port(self, node: NetNode):
        """
        If "node" is connected by this link:

        Returns a tuple where the first
        element is the interface number
        on the device and the second is
        0 if the node is associated to 
        the first node, else 1
        """
        if self.node0 == node:
            return self.port1, 0
        elif self.node1 == node:
            return self.port2, 1
        return None
    
    def subtract_from_max_bw(self, used_bw: float):
        """
        Subtract "used_bw" from the maximum
        bandwidth, set bw to that value
        """
        if used_bw > self.max_bw:
            raise Exception("Occupied bw greater than max bw?")
        self.bw = self.max_bw - used_bw

class NetGraph:
    def __init__(self):
        self.links: list[NetLink] = []
        self.nodes: list[NetNode] = []
        self.path_cache: Dict[NetNode, Dict[NetNode, Tuple[str, list[NetLink]]]] = {}
        return

    def cache_invalidate(self):
        """
        Invalidate all paths

        # Returns
        The size of the cache before deletion
        """
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
        """
        Retrieve path between src and dst if it exists and it
        matches the required opt_type

        # Params
        - src Source node
        - dst Dest node
        - opt_type One of the optimizations options

        # Returns
        The path or None 
        """
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
        """
        Returns list of all paths in the cache
        """
        flattened = []
        for src in self.path_cache.values():
            for dst in src.values():
                flattened.append(dst[1])
        return flattened

    def cache_invalidate_link(self, link: NetLink):
        """
        Marks link as modified, invalidates all paths
        including said link

        # Params
        The link to modify

        # Returns
        List of all now-invalid paths
        """
        inv_paths: list[Tuple[NetHost, NetHost, list[NetLink]]] = []
        for src, dsts in self.path_cache.items():
            for dst, path in dsts.items():
                if link in path[1]:
                    inv_paths.append((src, dst, path))
        for src, dst, _ in inv_paths:
            del self.path_cache[src][dst]
        return inv_paths

    def cache_invalidate_path(self, src: NetNode, dst: NetNode):
        """
        Invalidates single path between src and dst if it exists
        """
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
        """
        Modify link parameters and invalidate all paths
        containing said link.

        # Params
        - link: The link
        
        ## Optional params
        - bw:         New bandwidth
        - delay:      New delay
        - port1_down: set port 1 up or down
        - port2_down: same thing put for the other port 

        # Returns
        List of invalidated paths
        """
        if not link in self.links or len(kwargs) == 0:
            return []
        if "bw" not in kwargs.keys() and not "delay" in kwargs.keys() and not "port1_down" in kwargs.keys() and not "port2_down" in kwargs.keys():
            return []
        index = self.links.index(link)
        has_to_invalidate = False
        if "bw" in kwargs.keys() and self.links[index].bw != kwargs["bw"]:
            self.links[index].bw = kwargs["bw"]
            has_to_invalidate = True

        if "delay" in kwargs.keys() and self.links[index].delay != kwargs['delay']:
            self.links[index].delay = kwargs["delay"]
            has_to_invalidate = True 

        if "port1_down" in kwargs.keys() and self.links[index].port1_down != kwargs['port1_down']:
            self.links[index].port1_down = kwargs['port1_down']
            has_to_invalidate = True

        if "port2_down" in kwargs.keys() and self.links[index].port2_down != kwargs['port2_down']:
            self.links[index].port2_down = kwargs['port2_down']
            has_to_invalidate = True

        inv_paths = []
        if has_to_invalidate:
            inv_paths = self.cache_invalidate_link(link)
        return inv_paths
    
    def modify_curr_link_bw(self, link: NetLink, used_bw: float):
        if not link in self.links:
            return []
        index = self.links.index(link)
        old_bw = self.links[index].bw
        self.links[index].subtract_from_max_bw(used_bw)
        if self.links[index].bw != old_bw:
            return self.cache_invalidate_link(link)
        return []
    
    def add_link(self, link: NetLink):
        """
        Add new link to the graph, also makes sure that
        said link is not already included and that it
        does not used previously used ports
        """
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
        """
        Find all possible paths between two endpoints, filtering by 
        the provided constraints

        # Params
        - host1
        - host2
        - min_bw: Min allowed bandwidth on the path
        - max_delay: Max allowed delay of the path

        # Returns
        List of possible paths
        """
        if host1 == host2: # Do not return None, since a path exists, it just only is of length zero
            return []
        if not host1 in self.nodes or not host2 in self.nodes:
            return None
        paths: list[list[NetLink]] = []
        # Find all possible starting links
        starting_points = list(filter(lambda link: link.contains_node(host1), self.links))
        if len(starting_points) != 1: # Node is not connected to the rest of the network,
                                      # or it is not an host but a switch
            return None
        start = starting_points[0]
        if host1 == start.node1: #switch the two
            start = copy.deepcopy(start)
            start.exchange_nodes()

        if start.bw < min_bw or start.delay > max_delay or start.is_down(): # Check if the first link respects constraints
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
                    link.exchange_nodes()
                new_path.append(link)
                next_min_bw = min(curr_min_bw, float(link.bw))
                next_delay = curr_delay + link.delay
                if next_min_bw >= min_bw and next_delay <= max_delay and not link.is_down():
                    find_path_sub(self, copy.deepcopy(visited_nodes), new_path, next_min_bw, next_delay)
        find_path_sub(self, [host1], init_path, start.bw, start.delay)
        if len(paths) == 0:
            return None
        #Do not add to cache, since we do not exactly know which
        #path is going to be selected
        return paths

    def find_path(self, host1: NetHost, host2: NetHost, **kwargs):
        """
        Find single path between endpoints respecting requirements

        # Params
        - host1
        - host2

        ## Optional params
        - opt: Optimization type, select from ["none", "bw", "delay", "hops"]
        - min_bw
        - max_delay
        - ignore_cache: If a path already exists in the cache, ignore it and recompute
        - keep_cache: Do not overwrite path in cache if it exists

        # Returns
        The path
        """
        opt = "none" if "opt" not in kwargs else kwargs["opt"]
        ignore_cache = False if "ignore_cache" not in kwargs else kwargs["ignore_cache"]
        min_bw = 0 if "min_bw" not in kwargs else kwargs["min_bw"]
        max_delay = float('inf') if "max_delay" not in kwargs else kwargs["max_delay"]
        keep_cache = False if "keep_cache" not in kwargs else kwargs["keep_cache"]
        if not ignore_cache:
            path: list[NetLink] = self.cache_get(host1, host2, opt)
            if path != None:
                curr_min_bw = min(link.bw for link in path)
                curr_delay = sum(link.delay for link in path)
                if curr_min_bw < min_bw or curr_delay > max_delay:
                    if not keep_cache:
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
        if not keep_cache:
            self._cache_add(host1, host2, the_path, opt)
        return the_path
    
    def get_links_with_node(self, node: NetNode):
        return list(filter(lambda link: link.contains_node(node), self.links))
    
def get_path_extremes(path: List[NetLink]):
    if len(path) == 0:
        return None
    return path[0].node0, path[-1].node1

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
