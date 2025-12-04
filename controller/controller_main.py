from ryu.base import app_manager
from ryu.controller import ofp_event
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
        node_type = typing.Dict[str, str]
        link_type = typing.Dict[str, typing.Any]
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

class SliceController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': wsgi.WSGIApplication
    }

    def __init__(self, *_args, **_kwargs):
        super(SliceController, self).__init__(*_args, **_kwargs)
        #All datapaths, needed to contact switches
        self.data: typing.Dict[str, typing.Any] = {}
        self.dpaths = []
        self.wsgi: wsgi.WSGIApplication = _kwargs['wsgi']
        self.mapper = self.wsgi.mapper
        self.mapper.connect('/api/v0/slices', controller=RestServer, action='handle_slices', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/graph', controller=RestServer, action='handle_net', conditions=dict(method=['POST']))
        self.wsgi.registory['RestServer'] = self.data
        self.data['graph'] = None

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

    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev: ofp_event.EventOFPMsgBase):
        """
        Event handler for switch features, called when a new switch
        connects to the controller. It saves the datapath of the
        switch and installs a fallback flow rule 
        """
        dp: Datapath = ev.msg.datapath
        if dp not in self.dpaths:
            self.dpaths.append(dp)
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match_rule = parser.OFPMatch() 
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, \
                                                    action)]
        self.add_flow(dp, match_rule, instruction, 0)
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