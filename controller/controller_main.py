from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.app import wsgi
from ryu.app.wsgi import Request, Response

import logging
import typing
import json
import copy

import net_graph

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def route_handler(http_method: str):
    def route_handler_wrap(method):
        def wrapper(self, req: Request, *args, **kwargs):
            if req.method != http_method:
                return Response(content_type='application/json', body=json.dumps({'status': 'E_INV_METHOD'}), status=400)
            if req.method == 'POST':
                if req.headers.get('ContentType') != 'application/json' or not req.body:
                    message = {'status': 'E_INV_CONTENT'}
                    return Response(content_type='application/json', body=json.dumps(message), status=400)

            try:
                (body, status) = method(self, req, *args, **kwargs)
                return Response(content_type='application/json', body=json.dumps(body), status=status)
            except json.JSONDecodeError:
                logging.error(f'[REST] JSON Decode error')
                return Response(
                    content_type='application/json', body=json.dumps({'status': 'E_INV_BODY'}), 
                    status=400
                )
            except Exception:
                logging.error(f'[REST] Generic exception')
                logging.exception("Exception while parsing")
                return Response(
                    content_type='application/json', body=json.dumps({'status': 'E_INTERNAL_ERROR'}), 
                    status=500
                )
        return wrapper
    return route_handler_wrap

class InitEvent(ofp_event.event.EventBase):
    def __init__(self):
        super().__init__()

class ShutdownEvent(ofp_event.event.EventBase):
    def __init__(self):
        super().__init__()

class RestServer(wsgi.ControllerBase):
    def __init__(self, req, link, data: typing.Dict, **config):
        super(RestServer, self).__init__(req, link, data, **config)

    @route_handler(http_method="POST")
    def handle_slices(self, req: Request, **_kwargs):
        body: typing.Dict = json.loads(req.body.decode())
        if type(body) != type({}):
            logging.error(f'[REST] Invalid body received: {body}')
            return {'status': 'E_INV_BODY'}, 400
        slices: typing.Dict[str, list] = {}
        for slice_name, slice_ips in body.items():
            if type(slice_name) != type(""):
                return {'status': 'E_INV_SLICE_ID'}, 400
            if type(slice_ips) != type([]):
                return {'status': 'E_INV_SLICE_IPS'}, 400
            slices[slice_name] = slice_ips
        logger.info(f'[REST] Received slices: {json.dumps(slices)}')
        self.data['slices'] = slices
        return {'status': 'E_OK'}, 200
    
    @route_handler(http_method="POST")
    def handle_net(self, req: Request, **_kwargs):
        """
        Expected format: 
        node = {"type": 'h/s', "id": "dpid/ip"}
        link = {"node0": node, "node1": node, "port0": str, "port1": str, "bw": float, "delay": float}
        {"nodes": [node...], "links": [{"node0": }]}
        """
        body: typing.Dict[str, typing.List] = json.loads(req.body.decode())
        if type(body) != type({}):
            logger.error(f'[REST] Invalid body received: {body}')
            return {'status': 'E_INV_BODY'}, 400
        if self.data['graph'] != None:
            logger.error('[REST] Attempting to rewrite topology, not implemented')
            return {'status': 'E_ALREADY_SET'}, 403
        if "nodes" not in body:
            return {'status': 'E_MISSING_NODES'}, 400
        if "links" not in body:
            return {'status': 'E_MISSING_LINKS'}, 400
        graph = net_graph.NetGraph()
        for index, node in enumerate(body['nodes']):
            if "type" not in node or "id" not in node:
                logger.error(f'[REST] Node at index {index} is malformed: {node}')
                return {'status': 'E_INV_NODE'}, 400
            if node['type'] == 'h':
                net_node = net_graph.NetHost(node['id'])
            elif node['type'] == 's':
                net_node = net_graph.NetSwitch(node['id'])
            else:
                logger.error(f'[REST] Node at index {index} is malformed: {node}')
                return {'status': 'E_INV_NODE'}, 400
            if graph.contains_node(net_node):
                logger.error(f'[REST] Node at index {index} is repeated: {node}')
                return {'status': 'E_REP_NODE'}, 400
            graph.add_node(net_node)
        for index, link in enumerate(body['links']):
            try:
                node0 = link['node0']
                node1 = link['node1']
                if node0['type'] == 'h':
                    net_node0 = net_graph.NetHost(node0['id'])
                elif node0['type'] == 's':
                    net_node0 = net_graph.NetSwitch(node0['id'])
                else:
                    logger.error(f'[REST] Node 0 of link at index {index} is malformed: {node0}')
                    return {'status': 'E_INV_NODE'}, 400
                
                if node1['type'] == 'h':
                    net_node1 = net_graph.NetHost(node1['id'])
                elif node1['type'] == 's':
                    net_node1 = net_graph.NetSwitch(node1['id'])
                else:
                    logger.error(f'[REST] Node 1 of link at index {index} is malformed: {node1}')
                    return {'status': 'E_INV_NODE'}, 400
                
                if not isinstance(link['port0'], str):
                    link['port0'] = str(link['port0'])

                if not isinstance(link['port1'], str):
                    link['port1'] = str(link['port1'])

                if isinstance(link['delay'], str):
                    try:
                        if 'ms' in link['delay']:
                            link['delay'] = link['delay'].replace('ms', '')
                        link['delay'] = float(link['delay'])
                    except:
                        logger.error('[REST] Invalid delay')
                        return {'status': 'E_INV_DELAY'}, 400
                    
                if isinstance(link['bw'], str):
                    try:
                        link['bw'] = float(link['bw'])
                    except:
                        logger.error('[REST] Invalid bw')
                        return {'status': 'E_INV_BW'}, 400
                
                net_link = net_graph.NetLink(link['bw'], link['delay'], net_node0, net_node1, link['port0'], link['port1'])
                if graph.contains_link(net_link):
                    logger.error(f'[REST] Link at index {index} is repeated')
                    return {'status': 'E_REP_LINK'}, 400
                graph.add_link(net_link)
            except:
                logger.exception('[REST] Exception occurred while processing link')
                return {'status': 'E_INV_LINK'}, 400
        print(list(map(lambda node: str(node), graph.nodes)))
        print(list(map(lambda link: str(link), graph.links)))
        self.data['graph'] = graph
        return {'status': 'E_OK'}, 200
    
    @route_handler(http_method="POST")
    def handle_qos(self, req: Request, **_kwargs):
        body: typing.List[typing.Dict[str, float]] = json.loads(req.body.decode())
        if not isinstance(body, type([])):
            logger.error(f'[REST] Invalid body received: {body}')
            return {'status': 'E_INV_BODY'}, 400
        required_fields = ["min_bw", "max_bw", "min_delay", "max_delay"]
        required_types = {"min_bw": float, "max_bw": float, "min_delay": float, "max_delay": float}
        for index, qos in enumerate(body):
            has_fields = all(field in required_fields for field in qos)
            if not has_fields:
                missing = [field for field in required_fields if field not in qos]
                logger.error(f'[REST] QoS {index} is missing some fields: {missing}')
                return {'status': 'E_MISSING_FIELDS', 'qos': index, 'list': missing}, 400
            respects_types = all(isinstance(value, required_types[field]) for field, value in qos.items())
            if not respects_types:
                logger.error(f'[REST] QoS {index} is missing has some invalid fields')
                return {'status': 'E_INV_TYPES', 'qos': index}
        self.data['qos'] = body
        logger.info(f'[REST] Received queues: {body}')
        return {'status': 'E_OK'}, 200
    
    @route_handler(http_method="POST")
    def handle_init_end(self, req: Request, **_kwargs):
        body: typing.Dict[str, typing.Any] = json.loads(req.body.decode())
        if not isinstance(body, type({})):
            logger.error(f'[REST] Invalid body received: {body}')
            return {'status': 'E_INV_BODY'}, 400
        if not "default_qos" in body:
            logger.error(f'[REST] Missing default QoS')
            return {'status': 'E_MISSING_QOS'}, 400
        if not isinstance(body['default_qos'], int):
            logger.error(f'[REST] Invalid default QoS')
            return {'status': 'E_INV_QOS'}, 400
        self.data['default_qos'] = int(body['default_qos'])
        app: app_manager.RyuApp = self.data['app']
        app.send_event('SliceController', InitEvent())
        return {'status': 'E_OK'}, 200
    
    @route_handler(http_method="POST")
    def handle_shutdown(self, req: Request, **_kwargs):
        app: app_manager.RyuApp = self.data['app']
        app.send_event('SliceController', ShutdownEvent())
        return {'status': 'E_OK'}, 200

class SliceController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': wsgi.WSGIApplication,
        'dpset': dpset.DPSet
    }

    def __init__(self, *_args, **_kwargs):
        super(SliceController, self).__init__(*_args, **_kwargs)
        #All datapaths, needed to contact switches
        self.data: typing.Dict[str, typing.Any] = {}
        self.dpaths: dpset.DPSet = _kwargs['dpset']
        self.wsgi: wsgi.WSGIApplication = _kwargs['wsgi']
        self.created_paths: typing.Dict[typing.Tuple[str, str], typing.List] = {}
        self.path_cookies: typing.Dict[typing.Tuple[str, str], typing.List[typing.Tuple[net_graph.NetSwitch, typing.List[int]]]] = {}
        self.path_qos: typing.Dict[typing.Tuple[str, str], int] = {}
        self.curr_cookie: int = 0
        self.mapper = self.wsgi.mapper
        self.mapper.connect('/api/v0/slices', controller=RestServer, action='handle_slices', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/graph', controller=RestServer, action='handle_net', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/qos', controller=RestServer, action='handle_qos', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/init', controller=RestServer, action='handle_init_end', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/shutdown', controller=RestServer, action='handle_shutdown', conditions=dict(method=['POST']))
        self.wsgi.registory['RestServer'] = self.data
        self.data['graph'] = None
        self.data['app'] = self

    def add_flow(self, dp: Datapath, match_rule, instructions, prio=0x7FFF, cookie=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        flow_mod = parser.OFPFlowMod(
            datapath=dp, match=match_rule, priority=prio,
            command=ofproto.OFPFC_ADD, instructions=instructions,
            cookie=cookie
        )
        dp.send_msg(flow_mod)
        return
    
    def remove_flow(self, dp: Datapath, match_rule, instructions, prio=0x7FFF, cookie=0, cookie_mask= 0xFFFFFFFFFFFFFFFF, table_id=ofproto_v1_3.OFPTT_ALL, out_port=ofproto_v1_3.OFPP_ANY, out_group=ofproto_v1_3.OFPG_ANY):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        flow_mod = parser.OFPFlowMod(
            datapath=dp, match=match_rule, priority=prio,
            command=ofproto.OFPFC_DELETE, instructions=instructions,
            cookie=cookie,
            table_id=table_id,
            out_port=out_port,
            out_group=out_group,
            cookie_mask=cookie_mask
        )
        dp.send_msg(flow_mod)
        return

    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev: ofp_event.EventOFPMsgBase):
        """
        Event handler for switch features, called when a new switch
        connects to the controller. It saves the datapath of the
        switch and installs a fallback flow rule 
        """
        dp: Datapath = ev.msg.datapath
        #if dp.id not in self.dpaths:
        #    self.dpaths[dp.id] = dp
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match_rule = parser.OFPMatch() 
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, \
                                                    action)]
        self.add_flow(dp, match_rule, instruction, 0)
        self.data['dpaths'] = self.dpaths
        return
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev: ofp_event.EventOFPMsgBase):
        msg = ev.msg
        dp: Datapath = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        _packet = packet.Packet(msg.data)
        _eth_protocols = _packet.get_protocols(ethernet.ethernet)

        #We don't support protocols other than ethernet (right ?)
        if len(_eth_protocols) == 0:
            logging.error(f'[CONTROLLER] Received non-ethernet packet from dpid {dp.id}')
            return
        _eth: ethernet.ethernet = _eth_protocols[0] 

        if _eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        return
    
    def create_route_flows(self, links: typing.List[net_graph.NetLink], begin: net_graph.NetHost, end: net_graph.NetHost, qos: int, cookies: typing.List[typing.Tuple[net_graph.NetSwitch, typing.List[int]]]):
        for link, next_link in zip(links, links[1:]):
            if isinstance(next_link.node0, net_graph.NetHost):
                logger.error('[CONTROLLER] Unexpected sequence in path')
                raise Exception("Invalid path")
            logger.info(f'Add {begin} -> {end} to {link.node1.dpid}, in port: {link.port2}, out port: {next_link.port1}, first delay: {link.delay}, second delay: {next_link.delay}')
            dpid = int(link.node1.dpid, 16)
            dp: Datapath = self.dpaths.get(dpid)
            if dp is None:
                logger.info(f'But datapath has not been registered?')
                raise Exception("Invalid dpid")
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            #First direction
            matches = parser.OFPMatch(in_port=int(link.port2), ipv4_src=begin.ip, ipv4_dst=end.ip, eth_type=0x800)
            actions = [parser.OFPActionSetQueue(qos), parser.OFPActionOutput(int(next_link.port1))]
            instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, \
                                                    actions)]
            self.add_flow(dp, matches, instruction, 10, cookie=self.curr_cookie)
            #Opposite direction
            matches = parser.OFPMatch(in_port=int(next_link.port1), ipv4_src=end.ip, ipv4_dst=begin.ip, eth_type=0x800)
            actions = [parser.OFPActionSetQueue(qos), parser.OFPActionOutput(int(link.port2))]
            instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, \
                                                    actions)]
            self.add_flow(dp, matches, instruction, 10, cookie=self.curr_cookie + 1)
            
            #Repeat for ARP packets
            
            #First direction
            matches = parser.OFPMatch(in_port=int(link.port2), arp_spa=begin.ip, arp_tpa=end.ip, eth_type=0x0806)
            actions = [parser.OFPActionSetQueue(qos), parser.OFPActionOutput(int(next_link.port1))]
            instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, \
                                                    actions)]
            self.add_flow(dp, matches, instruction, 10, cookie=self.curr_cookie + 2)
            #Opposite direction
            matches = parser.OFPMatch(in_port=int(next_link.port1), arp_spa=end.ip, arp_tpa=begin.ip, eth_type=0x0806)
            actions = [parser.OFPActionSetQueue(qos), parser.OFPActionOutput(int(link.port2))]
            instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, \
                                                    actions)]
            self.add_flow(dp, matches, instruction, 10, cookie=self.curr_cookie + 3)
            cookies.append((copy.deepcopy(link.node1), [self.curr_cookie, self.curr_cookie + 1, self.curr_cookie + 2, self.curr_cookie + 3]))
            self.curr_cookie += 4
        return
    
    def remove_route_flows(self, begin: net_graph.NetHost, end: net_graph.NetHost, cookies: typing.List[typing.Tuple[net_graph.NetSwitch, typing.List[int]]]):
        for switch, cookie_list in cookies:
            dpid = int(switch.dpid, 16)
            dp: Datapath = self.dpaths.get(dpid)
            if dp is None:
                logger.info(f'But datapath has not been registered?')
                raise Exception("Invalid dpid")
            #ofproto = dp.ofproto
            #parser = dp.ofproto_parser
            #matches = parser.OFPMatch() #Match any
            #actions = []
            #instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, \
            #                                        actions)]
            logger.info(f"Remove {begin} -> {end} from {switch}")
            for cookie in cookie_list:
                self.remove_flow(dp, None, None, cookie=cookie)
        return

    def create_route(self, begin: net_graph.NetHost, end: net_graph.NetHost, qos: int, best_effort: bool):
        if begin == end:
            return True
        if (begin.ip, end.ip) in self.created_paths or (end.ip, begin.ip) in self.created_paths:
            return True
        qos_config: list[typing.Dict[str, typing.Any]] = self.data['qos']
        logger.info(f"{begin} -> {end}, max delay: {qos_config[qos]['max_delay']}, min bw: {qos_config[qos]['min_bw']}")
        self.created_paths[(begin.ip, end.ip)] = self.data['graph'].find_path(begin, end, opt="hops", max_delay=qos_config[qos]["max_delay"], min_bw=qos_config[qos]['min_bw'])
        if self.created_paths[(begin.ip, end.ip)] == None:
            logger.info(f'QoS requirements not met')
            if best_effort:
                logger.info(f'Attempting best effort')
                self.created_paths[(begin.ip, end.ip)] = self.data['graph'].find_path(begin, end, opt="hops")
        if self.created_paths[(begin.ip, end.ip)] != None:
            self.path_cookies[(begin.ip, end.ip)] = []
            self.create_route_flows(self.created_paths[(begin.ip, end.ip)], begin, end, qos, self.path_cookies[(begin.ip, end.ip)])
        else:
            del self.created_paths[(begin.ip, end.ip)]
            return False
        self.path_qos[(begin.ip, end.ip)] = qos
        return True
    
    def remove_route(self, begin: net_graph.NetHost, end: net_graph.NetHost):
        if begin == end:
            return True
        if (begin.ip, end.ip) not in self.created_paths and (end.ip, begin.ip) not in self.created_paths:
            return True
        if (end.ip, begin.ip) in self.created_paths:
            temp_host = begin 
            begin = end 
            end = temp_host
        if (begin.ip, end.ip) not in self.path_cookies:
            raise Exception(f"path_cookies does not contain {begin} -> {end}")
        logger.info(f"Delete path {begin} -> {end}")
        self.remove_route_flows(begin, end, self.path_cookies[(begin.ip, end.ip)])
        del self.path_cookies[(begin.ip, end.ip)]
        del self.created_paths[(begin.ip, end.ip)]
        del self.path_qos[(begin.ip, end.ip)]
        return True
    
    @set_ev_cls(InitEvent, MAIN_DISPATCHER)
    def init_handler(self, ev: ofp_event.EventOFPMsgBase):
        logger.info('[CONTROLLER] Init event')
        slices: typing.Dict[str, typing.List[str]] = self.data['slices']
        for slice_name, hosts in slices.items():
            for host in hosts:
                for other_host in hosts:
                    success = self.create_route(net_graph.NetHost(host), net_graph.NetHost(other_host), self.data['default_qos'], False)
                    if not success:
                        success = self.create_route(net_graph.NetHost(host), net_graph.NetHost(other_host), self.data['default_qos'], True)
                    if not success:
                        logger.info(f'{host} -> {other_host} not possible')      
        #path_list = [(begin, end) for begin, end in self.created_paths.keys()]
        #self.remove_route(net_graph.NetHost(path_list[0][0]), net_graph.NetHost(path_list[0][1]))
        return
    
    @set_ev_cls(ShutdownEvent, MAIN_DISPATCHER)
    def shutdown_handler(self, ev: ofp_event.EventOFPMsgBase):
        logger.info('[CONTROLLER] Shutdown event')
        for host_pair, _path in copy.deepcopy(self.created_paths).items():
            self.remove_route(net_graph.NetHost(host_pair[0]), net_graph.NetHost(host_pair[1]))
        if len(self.created_paths) != 0:
            raise Exception("Not all paths deleted!")
        del self.data['qos']
        del self.data['slices']
        del self.data['graph']

    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_state_change_handler(self, ev: ofp_event.EventOFPMsgBase):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'

        logger.info('OFPPortStatus received: reason=%s desc=%s',
                          reason, msg.desc)
        return