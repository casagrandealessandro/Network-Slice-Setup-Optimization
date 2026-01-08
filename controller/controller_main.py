from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import lldp
from ryu.lib import hub
from threading import Lock


from ryu.app import wsgi
from ryu.app.wsgi import Request, Response

import subprocess
import logging
import typing
import json
import copy

import net_graph

from stats_monitor import StatsMonitor, RouteReevaluateEvent
from service import Service, ServiceList
import dns_api

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def route_handler(http_method: str):
    """
    Return an handler for the specified HTTP method, which will
    perform some pre and post processing around the
    true handler. 
    """
    def route_handler_wrap(method):
        def wrapper(self, req: Request, *args, **kwargs):
            if req.method != http_method:
                return Response(content_type='application/json', body=json.dumps({'status': 'E_INV_METHOD'}), status=400)
            if req.method == 'POST' or req.method == 'PUT':
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
    """
    HTTP Server associated to the controller
    """
    def __init__(self, req, link, data: typing.Dict, **config):
        super(RestServer, self).__init__(req, link, data, **config)

    @route_handler(http_method="POST")
    def handle_qos_update(self, req: Request, **_kwargs):
        body = json.loads(req.body.decode())

        required = ["queue_id", "min_bw", "max_bw"]
        if not all(k in body for k in required):
            return {"status": "E_MISSING_FIELDS"}, 400

        app: SliceController = self.data['app']
        app.update_queue(
            int(body["queue_id"]),
            float(body["min_bw"]),
            float(body["max_bw"])
        )

        return {"status": "E_OK"}, 200


    @route_handler(http_method="POST")
    def handle_qos_queues(self, req: Request, **_kwargs):
        body = json.loads(req.body.decode())
        if "queue_uuids" not in body:
            return {"status": "E_MISSING_QUEUE_UUIDS"}, 400

        app: SliceController = self.data['app']
        app.queue_uuids = {int(k): v for k, v in body["queue_uuids"].items()}

        logger.info(f"[REST] Registered queue UUIDs: {app.queue_uuids}")
        return {"status": "E_OK"}, 200


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
        self.data['orig_qos'] = copy.deepcopy(body)
        logger.info(f'[REST] Received queues: {body}')
        return {'status': 'E_OK'}, 200
    
    @route_handler(http_method="POST")
    def handle_init_end(self, req: Request, **_kwargs):
        """
        Should be called after the previous three API endpoints. 
        Will kickstart the creation of flows between hosts
        in the same slice
        """
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
    
    #----------------------------------------------------------------------------------
    
    @route_handler(http_method="POST")
    def handle_service_create(self, req: Request, **_kwargs):
        """
        Creates a new service and returns the associated ID and
        IP address

        domain: str, subscriber: str, qos_index: int, service_type: str
        """
        body: typing.Dict = json.loads(req.body.decode())
        required = ["domain", "subscriber", "qos", "service_type"]
        has_required = all(required_param in body for required_param in required)
        if not has_required:
            return {'status': 'E_MISSING_PARAMS'}, 400
        wanted_types = [str, str, int, str]
        is_ok = all(type(body[param]) == required_type for param, required_type in zip(required, wanted_types))
        if not is_ok:
            return {'status': 'E_INV_PARAMS'}, 400
        the_service = Service(body['domain'], body['subscriber'], body['qos'], body['service_type'])
        app: SliceController = self.data['app']
        result = app.add_service(the_service)
        if result == None:
            return {'status': 'E_FAIL'}, 403
        return {'status': 'E_OK', 'service_id': result.id, 'service_ip': result.curr_ip}, 200
    
    @route_handler(http_method="GET")
    def handle_service_get(self, req: Request, **_kwargs):
        #get list of services
        app: SliceController = self.data['app']
        with app.service_lock:
            services = copy.deepcopy(app.services)
        return {'status': 'E_OK', "services": services}, 200
    
    @route_handler(http_method="DELETE")
    def handle_service_remove(self, req: Request, **_kwargs):
        #remove a service
        if not "id" in _kwargs:
            return {'status': 'E_MISSING_ID'}, 400
        app: SliceController = self.data['app']
        with app.service_lock:
            services = copy.deepcopy(app.services)
        logger.info(f"[REST] Attempt removing service {_kwargs['id']}")
        if services.get_service_by_id(int(_kwargs["id"])) == None:
            return {'status': 'E_INV_SERVICE'}, 403
        app: SliceController = self.data['app']
        result = app.remove_service(int(_kwargs['id']))
        if not result:
            return {'status': 'E_FAIL'}, 403
        return {'status': 'E_OK'}, 200
    
    #------------------------------------------------
    #UNUSED

    @route_handler(http_method="POST")
    def handle_service_add_client(self, req: Request, **_kwargs):
        return {'status': 'E_OK'}, 200
    
    @route_handler(http_method="DELETE")
    def handle_service_remove_client(self, req: Request, **_kwargs):
        return {'status': 'E_OK'}, 200

# Attempt to reoptimize routes every interval seconds
ROUTE_OPT_INTERVAL = 10
# 
BW_UPDATE_THRESHOLD_RATIO = 0.1

COMMON_CONFIG_FILE = "./config/common.json"

MAX_LINK_USED_BW_PERCENT = 0.1

class SliceController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': wsgi.WSGIApplication,
        'dpset': dpset.DPSet
    }

    SERVICE_QOS_INTERVAL = 10  # seconds

    def _service_qos_loop(self):
        while True:
            hub.sleep(SliceController.SERVICE_QOS_INTERVAL)
            #self.evaluate_services_qos()

    def evaluate_services_qos(self):
        if not hasattr(self, "paths_without_qos"):
            return
        
        if 'graph' not in self.data:
            return

        with self.service_lock:
            services = copy.deepcopy(self.services.services)

        for service in services:
            self.check_single_service(service)

    def check_single_service(self, service: Service):
        if service.curr_ip is None:
            return

        begin = service.curr_ip
        end = service.subscriber

        degraded = (
            (begin, end) in self.paths_without_qos or
            (end, begin) in self.paths_without_qos
        )

        graph: net_graph.NetGraph = self.data['graph']
        link_with_subscriber: net_graph.NetLink = graph.get_links_with_node(net_graph.NetHost(end))[0]

        if link_with_subscriber.is_down():
            logger.warning(f"[SERVICE] Subscriber of service {service.domain} is not connected to the network, migration useless")
            return

        dead = (
            (begin, end) in self.unrouted_paths or 
            (end, begin) in self.unrouted_paths
        )

        if dead:
            logger.info(f"[SERVICE] Service {service.domain} is inaccessible, force migrate")
            self.reset_service_violations(service)
            self.migrate_service(service)
            return

        if not degraded:
            self.reset_service_violations(service)
            return

        logger.warning(f"[SERVICE] QoS degraded for {service.domain}")
        self.handle_qos_violation(service)

    def handle_qos_violation(self, service: Service):
        with self.service_lock:
            stored = self.services.get_service_by_id(service.id)
            if stored is None:
                return

            stored.qos_violations += 1
            self.services.dump(self.data['conf']['service_list_file'])

        if stored.qos_violations == 1:
            logger.info(f"[SERVICE] Trying QoS tuning for {service.domain}")
            self.try_improve_queue(stored.qos_index)
            return

        if not stored.migratable:
            logger.info(f"[SERVICE] {service.domain} high priority → no migration")
            return

        if stored.qos_violations >= 3:
            logger.warning(f"[SERVICE] {service.domain} will be migrated")
            #self.reset_service_violations(service)
            self.migrate_service(stored)


    def try_improve_queue(self, qos_index: int):
        qos = self.data['qos'][qos_index]
        new_max = qos['max_bw'] * 1.2

        graph: net_graph.NetGraph = self.data['graph']
        if any(link.max_bw < new_max for link in graph.links):
            logger.warning("[QoS] QoS limited at max link speed")
            return

        try:
            self.update_queue(qos_index, qos['min_bw'], new_max)
        except Exception:
            logger.error("[QoS] Queue update failed")

    def reset_service_violations(self, service: Service):
        logger.info(f"[SERVICE] Reset violations for {service.domain}")
        with self.service_lock:
            stored = self.services.get_service_by_id(service.id)
            if stored and stored.qos_violations != 0:
                stored.qos_violations = 0
                self.services.dump(self.data['conf']['service_list_file'])


    def assign_new_ip(self, service: Service) -> str:
        """
        Assign a new IP to a service, avoiding conflicts with already assigned IPs.
        Chooses IPs only from the same slice as the subscriber.
        """
        # Find the slice of the subscriber
        slice_name = None
        for name, ips in self.data['slices'].items():
            if service.subscriber in ips:
                slice_name = name
                break

        if slice_name is None:
            raise Exception(f"Subscriber {service.subscriber} non trovato in nessuno slice")
        
        logger.info(f"[SERVICE] Service {service.domain} is in slice {slice_name}")

        # List of already used IPs
        used_ips = {s.curr_ip for s in self.services.services if s.curr_ip != None}
        used_ips = used_ips.union({s.subscriber for s in self.services.services})

        logger.info(f"[SERVICE] Used IPs: {used_ips}")

        # Find a free IP in the slice
        for candidate in self.data['slices'][slice_name]:
            if candidate not in used_ips:
                service.curr_ip = candidate
                logger.info(f"[SERVICE] Assigned new IP {candidate} to {service.domain} in slice {slice_name}")
                return candidate

        raise Exception(f"Nessun IP disponibile nel slice {slice_name} per {service.domain}")
    
    def reset_queue(self, qos_index: int):
        orig = self.data['orig_qos'][qos_index]
        self.update_queue(qos_index, orig['min_bw'], orig['max_bw'])


    def migrate_service(self, service: Service):
        """
        Perform migration of a service:
        - Assign a new IP (from the same slice as the subscriber)
        - Update DNS record with correct zone
        - Reset slice info
        """
        old_ip = service.curr_ip
        try:
            new_ip = self.assign_new_ip(service)
        except Exception as e:
            logger.error(f"[SERVICE] Could not assign new IP for {service.domain}: {e}")
            return

        if self.dns_conn:
            try:
                zone = ".".join(service.domain.split(".")[1:])
                logger.info(f"[SERVICE] Possible zone: {zone}")
                self.dns_conn.update_record(
                    domain=service.domain,
                    zone=zone,
                    oldip=old_ip,
                    newip=new_ip
                )
                logger.info(f"[SERVICE] DNS updated for {service.domain}: {old_ip} -> {new_ip}")
            except Exception as e:
                logger.error(f"[SERVICE] DNS update failed for {service.domain}: {e}")

        with self.service_lock:
            stored = self.services.get_service_by_id(service.id)
            if stored:
                stored.curr_ip = new_ip
                stored.qos_violations = 0
                self.services.dump(self.data['conf']['service_list_file'])
                logger.info(f"[SERVICE] {service.domain} migration completed: new IP {new_ip}")

        self.reset_queue(service.qos_index)


    def __init__(self, *_args, **_kwargs):
        self.queue_uuids: dict[int, str] = {}
        self.qos_lock = Lock()
        self.service_lock = Lock()

        super(SliceController, self).__init__(*_args, **_kwargs)
        # Data that needs to be shared with the REST server
        self.data: typing.Dict[str, typing.Any] = {}
        # All datapaths
        self.dpaths: dpset.DPSet = _kwargs['dpset']
        self.wsgi: wsgi.WSGIApplication = _kwargs['wsgi']
        # All currently established paths between endpoints
        self.created_paths: typing.Dict[typing.Tuple[str, str], typing.List] = {}
        # All cookies associated to each path (useful for modifying/deleting flows)
        self.path_cookies: typing.Dict[typing.Tuple[str, str], typing.List[typing.Tuple[net_graph.NetSwitch, typing.List[int]]]] = {}
        # QoS associated to each path
        self.path_qos: typing.Dict[typing.Tuple[str, str], int] = {}
        # All paths that could not be routed, with their QoS
        self.unrouted_paths: typing.Dict[typing.Tuple[str, str], int] = {}
        # All routed paths not respecting QoS
        self.paths_without_qos: typing.Dict[typing.Tuple[str, str], int] = {}
        # All port stats changes not already applied to th graph
        self.port_stat_changes: typing.Dict[str, typing.List[int]] = {}

        self.services: ServiceList = ServiceList()
        # Incrementing value used to set cookies for flows
        # Start from one since cookies with value zero
        # are used for default flows
        self.curr_cookie: int = 1
        self.mapper: wsgi.Mapper = self.wsgi.mapper
        self.mapper.connect('/api/v0/slices', controller=RestServer, action='handle_slices', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/graph', controller=RestServer, action='handle_net', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/qos', controller=RestServer, action='handle_qos', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/init', controller=RestServer, action='handle_init_end', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/shutdown', controller=RestServer, action='handle_shutdown', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/service/create', controller=RestServer, action='handle_service_create', conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/service/list', controller=RestServer, action='handle_service_get', conditions=dict(method=['GET']))
        self.mapper.connect('/api/v0/service/:id/remove', controller=RestServer, action='handle_service_remove', conditions=dict(method=['DELETE']))
        
        #self.mapper.connect('/api/v0/service/:id/clientadd/:clientip', controller=RestServer, action='handle_service_add_client', conditions=dict(method=['POST']))
        #self.mapper.connect('/api/v0/service/:id/clientremove/:clientip', controller=RestServer, action='handle_service_remove_client', conditions=dict(method=['DELETE']))
        
        self.mapper.connect('/api/v0/qos/queues',controller=RestServer,action='handle_qos_queues',conditions=dict(method=['POST']))
        self.mapper.connect('/api/v0/qos/update',controller=RestServer,action='handle_qos_update',conditions=dict(method=['POST']))

        self.wsgi.registory['RestServer'] = self.data
        self.data['graph'] = None
        self.data['app'] = self
        self.data['stat_monitor'] = StatsMonitor(self, poll_interval=10)

        #self.route_opt_thread = hub.spawn(self._route_reevaluate_loop)
        #self.service_qos_thread = hub.spawn(self._service_qos_loop)

        with open(COMMON_CONFIG_FILE) as conf_file:
            self.data['conf'] = json.load(conf_file)

        self.dns_conn: typing.Optional[dns_api.DNSServer] = None

    def update_queue(self, queue_id: int, min_bw: float, max_bw: float):
        if queue_id not in self.queue_uuids:
            raise Exception(f"Queue {queue_id} not registered")

        uuid = self.queue_uuids[queue_id]

        with self.qos_lock:
            # 1) update OVS
            subprocess.run([
                "ovs-vsctl", "set", "queue", uuid,
                f"other-config:min-rate={int(min_bw * 1e6)}",
                f"other-config:max-rate={int(max_bw * 1e6)}"
            ], check=True)

            # 2) update controller QoS state
            self.data['qos'][queue_id]['min_bw'] = float(min_bw)
            self.data['qos'][queue_id]['max_bw'] = float(max_bw)

        logger.info(
            f"[QoS] Updated queue {queue_id}: min={min_bw}Mbps max={max_bw}Mbps"
        )

        # 3) remove affected routes
        affected_paths = [
            (begin, end)
            for (begin, end), qos in list(self.path_qos.items())
            if qos == queue_id
        ]

        for begin, end in affected_paths:
            self.remove_route(
                net_graph.NetHost(begin),
                net_graph.NetHost(end),
                True
            )

        # 4) reroute everything
        self.attempt_rerouting()



    def add_flow(self, dp: Datapath, match_rule, instructions, prio=0x7FFF, cookie=0):
        """
        Add flow to datapath, with given match and instructions, plus priority
        and cookie
        """
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
        """
        Remove flow from datapath, also based on cookie
        """
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

        #Forward to controller with higher priority
        match_lldp_nearest_bridge = parser.OFPMatch(in_port=ofproto_v1_3.OFPP_ANY, eth_type=ether_types.ETH_TYPE_LLDP, eth_dst=lldp.LLDP_MAC_NEAREST_BRIDGE)
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, \
                                                    action)]
        self.add_flow(dp, match_lldp_nearest_bridge, instruction, 2)

        #still higher priority than base rule, but lower than the last one
        match_lldp_general = parser.OFPMatch(in_port=ofproto_v1_3.OFPP_ANY, eth_type=ether_types.ETH_TYPE_LLDP)
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        self.add_flow(dp, match_lldp_general, instruction, 1)

        self.data['dpaths'] = self.dpaths
        stat_monitor: StatsMonitor = self.data['stat_monitor']
        stat_monitor.register_datapath(dp)
        return
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev: ofp_event.EventOFPMsgBase):
        """
        Handler for switch-forwarded packets. Ideally it should use LLDP
        packets to learn the layout of the  network, but for now
        we will use a static graph (e.g. static from the point
        of view of the nodes and the connections between them)
        """
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
            _lldp_protocol: lldp.lldp = _packet.get_protocols(lldp.lldp)[0]
            logger.info(f"[CONTROLLER] Received LLDP packet from switch {dp.id:016x}, dst MAC: {_eth.dst}")
            logger.info(f"[CONTROLLER] LLDP packet with {len(_lldp_protocol.tlvs)} TLVs")
            #for tlv in _lldp_protocol.tlvs:
            #    print(tlv.tlv_type)
            return
        return
    
    def create_route_flows(self, links: typing.List[net_graph.NetLink], begin: net_graph.NetHost, end: net_graph.NetHost, qos: int, cookies: typing.List[typing.Tuple[net_graph.NetSwitch, typing.List[int]]]):
        """
        Create all flows to make communication work between two endpoints while respecting QoS, will put all
        used cookies inside the provided list
        """
        for link, next_link in zip(links, links[1:]):
            if isinstance(next_link.node0, net_graph.NetHost): #Expect that the two endpoints are the hosts
                logger.error('[CONTROLLER] Unexpected sequence in path')
                raise Exception("Invalid path")
            logger.info(f'[CONTROLLER] Add {begin} -> {end} to {link.node1.dpid}, in port: {link.port2}, out port: {next_link.port1}, first delay: {link.delay}, second delay: {next_link.delay}')
            dpid = int(link.node1.dpid, 16)
            dp: Datapath = self.dpaths.get(dpid)
            if dp is None:
                logger.info(f'[CONTROLLER] But datapath has not been registered?')
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
        """
        Remove all flows associated to a path, using the provided cookie list
        """
        for switch, cookie_list in cookies:
            dpid = int(switch.dpid, 16)
            dp: Datapath = self.dpaths.get(dpid)
            if dp is None:
                logger.info(f'[CONTROLLER] But datapath has not been registered?')
                raise Exception("Invalid dpid")
            #ofproto = dp.ofproto
            #parser = dp.ofproto_parser
            #matches = parser.OFPMatch() #Match any
            #actions = []
            #instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, \
            #                                        actions)]
            logger.info(f"[CONTROLLER] Remove {begin} -> {end} from {switch}")
            for cookie in cookie_list:
                self.remove_flow(dp, None, None, cookie=cookie)
        return

    def create_route(self, begin: net_graph.NetHost, end: net_graph.NetHost, qos: int, best_effort: bool, max_used_bw_percent: float = float('inf')):
        if begin == end:
            return True
        if (begin.ip, end.ip) in self.created_paths or (end.ip, begin.ip) in self.created_paths:
            return True
        qos_config: list[typing.Dict[str, typing.Any]] = self.data['qos']
        logger.info(f"[CONTROLLER] {begin} -> {end}, max delay: {qos_config[qos]['max_delay']}, min bw: {qos_config[qos]['min_bw']}")
        self.created_paths[(begin.ip, end.ip)] = self.data['graph'].find_path(begin, end, opt="hops", max_delay=qos_config[qos]["max_delay"], min_bw=qos_config[qos]['min_bw'], used_bw_bercent=max_used_bw_percent)
        if self.created_paths[(begin.ip, end.ip)] == None:
            logger.info(f'[CONTROLLER] QoS requirements not met')
            if best_effort:
                logger.info(f'[CONTROLLER] Attempting best effort')
                self.created_paths[(begin.ip, end.ip)] = self.data['graph'].find_path(begin, end, opt="hops")
                if self.created_paths[(begin.ip, end.ip)] != None:
                    self.paths_without_qos[(begin.ip, end.ip)] = qos

        if self.created_paths[(begin.ip, end.ip)] != None:
            if (begin.ip, end.ip) in self.unrouted_paths:
                del self.unrouted_paths[(begin.ip, end.ip)]
            if (end.ip, begin.ip) in self.unrouted_paths:
                del self.unrouted_paths[(end.ip, begin.ip)]
            self.path_cookies[(begin.ip, end.ip)] = []
            self.create_route_flows(self.created_paths[(begin.ip, end.ip)], begin, end, qos, self.path_cookies[(begin.ip, end.ip)])
        else:
            del self.created_paths[(begin.ip, end.ip)]
            return False
        self.path_qos[(begin.ip, end.ip)] = qos
        return True
    
    def remove_route(self, begin: net_graph.NetHost, end: net_graph.NetHost, keep_endpoints: bool = False):
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
        logger.info(f"[CONTROLLER] Delete path {begin} -> {end}")

        graph: net_graph.NetGraph = self.data['graph']
        if not graph.free_path_used_bw(self.created_paths[(begin.ip, end.ip)]):
            logger.error(f"[CONTROLLER] Could not free bandwidth")
        self.remove_route_flows(begin, end, self.path_cookies[(begin.ip, end.ip)])
        del self.path_cookies[(begin.ip, end.ip)]
        del self.created_paths[(begin.ip, end.ip)]
        prev_qos = self.path_qos[(begin.ip, end.ip)]
        del self.path_qos[(begin.ip, end.ip)]
        
        if not graph.cache_invalidate_path(begin, end):
            logger.info("[CONTROLLER] Path already invalidated in cache")
        if (begin.ip, end.ip) in self.paths_without_qos:
            del self.paths_without_qos[(begin.ip, end.ip)]
        if keep_endpoints:
            self.unrouted_paths[(begin.ip, end.ip)] = prev_qos
        return True
    
    @set_ev_cls(InitEvent, MAIN_DISPATCHER)
    def init_handler(self, ev: ofp_event.EventOFPMsgBase):
        logger.info("[CONTROLLER] ******** INIT ********")
        slices: typing.Dict[str, typing.List[str]] = self.data['slices']
        dns_ip: str = self.data['conf']['dns_ip']
        logger.info(f'[CONTROLLER] DNS IP: {dns_ip}')
        for slice_name, hosts in slices.items():
            for host in hosts:
                for other_host in hosts:
                    success = self.create_route(net_graph.NetHost(host), net_graph.NetHost(other_host), self.data['default_qos'], False)
                    if not success:
                        success = self.create_route(net_graph.NetHost(host), net_graph.NetHost(other_host), self.data['default_qos'], True)
                    if not success:
                        logger.info(f'{host} -> {other_host} not possible')
                self.create_route(net_graph.NetHost(host), net_graph.NetHost(dns_ip), self.data['default_qos'], True)
        self.dns_conn = dns_api.DNSServer.connect('admin', 'admin', f"127.0.0.1:{self.data['conf']['dns_api_port']}")
        logger.info("[CONTROLLER] ******** END ********")
        return
    
    @set_ev_cls(ShutdownEvent, MAIN_DISPATCHER)
    def shutdown_handler(self, ev: ofp_event.EventOFPMsgBase):
        logger.info("[CONTROLLER] ******** SHUTDOWN ********")
        for host_pair, _path in copy.deepcopy(self.created_paths).items():
            self.remove_route(net_graph.NetHost(host_pair[0]), net_graph.NetHost(host_pair[1]))
        if len(self.created_paths) != 0:
            raise Exception("Not all paths deleted!")
        del self.data['qos']
        del self.data['slices']
        del self.data['graph']
        self.unrouted_paths.clear()
        self.paths_without_qos.clear()
        self.created_paths.clear()
        self.path_cookies.clear()
        self.path_qos.clear()
        stat_monitor: StatsMonitor = self.data['stat_monitor']
        stat_monitor.stop_monitor()
        del self.dns_conn
        self.dns_conn = None
        logger.info("[CONTROLLER] ******** END ********")


    def attempt_rerouting(self):
        if not 'graph' in self.data or 'qos' not in self.data:
            return
        
        # Apply changes to stats received from StatsMonitor,
        # we get a list of paths that we may need to change
        old_paths = self.apply_port_changes()

        logger.info("[CONTROLLER] ******** REROUTING ********")

        graph: net_graph.NetGraph = self.data['graph']

        logger.debug("[CONTROLLER] ******** PATHS USING BW ********")
        for begin, end in self.created_paths.keys():
            used_bw = graph.get_path_used_bw(self.created_paths[(begin, end)])
            logger.debug(f"[CONTROLLER] Path {begin} -> {end} uses {used_bw} Mb/s")
        logger.debug("[CONTROLLER] ********      END       ********")

        qos_config: list[typing.Dict[str, typing.Any]] = self.data['qos']
        paths_without_qos_temp = copy.deepcopy(self.paths_without_qos)
        logger.info(f"[CONTROLLER] Found {len(paths_without_qos_temp)} routed paths not respecting QoS")

        def reroute_paths(self: SliceController, paths: typing.Dict[typing.Tuple[str, str], int], has_qos: bool):
            for (begin, end), qos in paths.items():
                begin_host = net_graph.NetHost(begin)
                end_host = net_graph.NetHost(end)

                used_bw = graph.get_path_used_bw(self.created_paths[(begin, end)])

                logger.info(f"[CONTROLLER] Path {begin} -> {end} uses {used_bw} Mb/s")

                if has_qos:
                    logger.debug(f"[CONTROLLER] Attempting to reroute {begin} -> {end}, attempt to find unused path")
                else:
                    logger.debug(f"[CONTROLLER] Attempting to reroute {begin} -> {end}, QoS not met")
                alternative_path = graph.find_path(begin_host, end_host, opt="hops", max_delay=qos_config[qos]["max_delay"], 
                                                   min_bw=qos_config[qos]['min_bw'], ignore_cache=True, keep_cache=True,
                                                   old_path=self.created_paths[(begin, end)], used_bw_bercent=MAX_LINK_USED_BW_PERCENT)


                begin_end_in_old_paths = (begin_host, end_host) in old_paths
                end_begin_in_old_paths = (end_host, begin_host) in old_paths

                if alternative_path == None:
                    if has_qos:
                        logger.debug("[CONTROLLER] Could not find unused path")
                    else:
                        logger.debug(f"[CONTROLLER] Reroute failed, continue")
                    
                    graph._cache_add(begin_host, end_host, self.created_paths[(begin, end)], "hops") # Yes, we should still try rerouting
                                                                                                     # for "best effort", but for now we will do this

                    with self.service_lock:
                        services = copy.deepcopy(self.services.services)

                    has_service = False
                    for service in services:
                        if (service.curr_ip == begin and service.subscriber == end) or \
                            (service.curr_ip == end and service.subscriber == begin):
                            has_service = True
                            break

                    if has_service and (not (begin, end) in self.paths_without_qos and not (end, begin) in self.paths_without_qos):
                        logger.info(f"[CONTROLLER] Add {begin} -> {end} to paths not respecting QoS")
                        self.paths_without_qos[(begin, end)] = qos
                else:
                    if alternative_path == self.created_paths[(begin, end)]:
                        logger.info(f"[CONTROLLER] Graph computed same path, reinsert in cache")
                        graph._cache_add(begin_host, end_host, self.created_paths[(begin, end)], "hops") # Well this can happen
                                                                                                         # especially if the path was invalidated by a stat update

                        if (begin, end) in self.paths_without_qos:
                            logger.debug(f"[CONTROLLER] Remove {begin} -> {end} from paths not respcting QoS")
                            del self.paths_without_qos[(begin, end)]
                        if (end, begin) in self.paths_without_qos:
                            logger.debug(f"[CONTROLLER] Remove {begin} -> {end} from paths not respcting QoS")
                            del self.paths_without_qos[(end, begin)]
                    else:
                        logger.info(f"[CONTROLLER] Reroute success, removing previous path")
                        self.remove_route(net_graph.NetHost(begin), net_graph.NetHost(end), True)
                        if not self.create_route(net_graph.NetHost(begin), net_graph.NetHost(end), qos, False, MAX_LINK_USED_BW_PERCENT):
                            logger.error(f"[CONTROLLER] But it failed? Fallback to best effort")
                            if not self.create_route(net_graph.NetHost(begin), net_graph.NetHost(end), qos, True, MAX_LINK_USED_BW_PERCENT):
                                logger.info(f'[CONTROLLER] {begin} -> {end} not possible, maybe one end-point is isolated?')

                if begin_end_in_old_paths:
                    del old_paths[(begin_host, end_host)]
                if end_begin_in_old_paths:
                    del old_paths[(begin_host, end_host)]

        #typing.Dict[typing.Tuple[str, str], int]
        reroute_paths(self, paths_without_qos_temp, False)
        old_paths_endpoints = [(begin.ip, end.ip) for begin, end in old_paths.keys()]
        old_paths_endpoints = list(map(lambda path: (path[1], path[0]) if (path[1], path[0]) in self.path_qos else path, old_paths_endpoints))
        old_paths_with_qos = {path: self.path_qos[path] for path in old_paths_endpoints}
        logger.info(f"[CONTROLLER] Found {len(old_paths_with_qos)} paths invalidated by port stats")
        reroute_paths(self, old_paths_with_qos, True)

        if len(old_paths) != 0:
            logger.error(f"[CONTROLLER] Not all modified paths have been re-evaluated")

        # Perform routing of unrouted paths AFTER trying to optimize paths
        # that do not meet QoS, otherwise we might end up trying
        # to optimize paths that have been just created and do not
        # meet QoS, which would end up giving the same result
        unrouted_paths_temp = copy.deepcopy(self.unrouted_paths)
        logger.info(f"[CONTROLLER] Found {len(unrouted_paths_temp)} unrouted paths")
        for (begin, end), qos in unrouted_paths_temp.items():
            begin_host = net_graph.NetHost(begin)
            end_host = net_graph.NetHost(end)
            if (begin_host, end_host) in old_paths or (end_host, begin_host) in old_paths:
                logger.error(f"[CONTROLLER] Unrouted path marked as invalid")
            logger.info(f"[CONTROLLER] Attempting to route {begin} -> {end}")
            success = self.create_route(begin_host, end_host, qos, False, MAX_LINK_USED_BW_PERCENT)
            if not success:
                success = self.create_route(begin_host, end_host, qos, True, MAX_LINK_USED_BW_PERCENT)
            if not success:
                logger.info(f'[CONTROLLER] {begin} -> {end} not possible, maybe one end-point is isolated?')

        logger.info("[CONTROLLER] ******** END ********")
        
        return

    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_state_change_handler(self, ev: ofp_event.EventOFPMsgBase):
        msg = ev.msg
        dp: Datapath = msg.datapath
        ofp = dp.ofproto

        if msg.reason != ofp.OFPPR_MODIFY:
            return 
        
        logger.info("[CONTROLLER] ******** PORT STATUS UPDATE ********")
        
        port = msg.desc
        port_no: int = port.port_no
        is_port_down: bool = (port.state & ofproto_v1_3.OFPPS_LINK_DOWN) != 0

        dpid_str = f"{dp.id:016x}"
        logger.info(f"[CONTROLLER] Switch({dpid_str}) port {port_no} status changed, is now {'down' if is_port_down else 'up'}")

        if 'graph' not in self.data or self.data['graph'] == None:
            return
        
        graph: net_graph.NetGraph = self.data['graph']

        switch_node = net_graph.NetSwitch(dpid_str)
        all_links = graph.get_links_with_node(switch_node)

        if len(all_links) == 0:
            return
        
        links_with_port = list(filter(lambda link: link.get_node_port(switch_node)[0] == str(port_no), all_links))

        if len(links_with_port) != 1:
            logger.error(f"{list(map(lambda link: str(link), links_with_port))}")
            return

        modified_link = links_with_port[0]
        port_id = modified_link.get_node_port(switch_node)[1]

        if port_id != 0 and port_id != 1:
            logger.error("[CONTROLLER] Nani?")
            return

        if port_id == 0:
            mod_paths = graph.modify_link(modified_link, port1_down=is_port_down)
        else:
            mod_paths = graph.modify_link(modified_link, port2_down=is_port_down)

        logger.info("[CONTROLLER] ******** END ********")

        if len(mod_paths) != 0:
            logger.info(f"[CONTROLLER] Link status change caused {len(mod_paths)} to be invalidated")
            for begin, end, path in mod_paths:
                logger.info(f"[CONTROLLER] {begin} -> {end} invalidated")
                self.remove_route(begin, end, True) 
            self.attempt_rerouting()
        return
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def handle_port_stats_reply(self, ev: ofp_event.EventOFPMsgBase):
        stat_monitor: StatsMonitor = self.data['stat_monitor']
        changes = stat_monitor.handle_port_stats_reply(ev)
        self.port_stat_changes[changes[0]] = changes[1]

    def _route_reevaluate_loop(self):
        while True:
            hub.sleep(ROUTE_OPT_INTERVAL)
            self.send_event('SliceController', RouteReevaluateEvent())

    def apply_port_changes(self) -> typing.Dict[typing.Tuple[net_graph.NetHost, net_graph.NetHost], typing.List[net_graph.NetLink]]:
        if len(self.port_stat_changes) == 0:
            return {}

        if "graph" not in self.data:
            self.port_stat_changes.clear()
            return {}
        
        logger.info("[CONTROLLER] ******** APPLY PORT STATS ********")

        graph: net_graph.NetGraph = self.data['graph']
        stat_monitor: StatsMonitor = self.data['stat_monitor']

        all_modified_links: list[net_graph.NetLink] = []

        inv_paths: typing.Dict[typing.Tuple[net_graph.NetHost, net_graph.NetHost], typing.List[net_graph.NetLink]] = {}

        for dpid, changed_ports in self.port_stat_changes.items():
            dpid_str = f"{int(dpid):016x}"
            switch_node = net_graph.NetSwitch(dpid_str)
            all_links = graph.get_links_with_node(switch_node)

            logger.info(f"[CONTROLLER] Applying changes for switch {dpid_str}, {len(changed_ports)} influenced")
            if len(all_links) == 0:
                continue

            for port_no in changed_ports:
                links_with_port = list(filter(lambda link: link.get_node_port(switch_node)[0] == str(port_no), all_links))

                if len(links_with_port) != 1:
                    logger.error(f"{list(map(lambda link: str(link), links_with_port))}")
                    continue

                modified_link = links_with_port[0]
                port_id = modified_link.get_node_port(switch_node)[1]

                if port_id != 0 and port_id != 1:
                    logger.error("[CONTROLLER] Nani?")
                    continue

                curr_bw = stat_monitor.get_bandwidth(dpid, port_no)

                logger.debug(f"[CONTROLLER] Modify port link {modified_link}, used bw: {curr_bw}")

                if modified_link in all_modified_links:
                    logger.debug(f"[CONTROLLER] Link already modified")
                    continue

                old_used_bw = float(modified_link.max_bw) - float(modified_link.last_update_bw)
                bw_ratio = (abs(float(curr_bw) - old_used_bw) / float(modified_link.max_bw))
                if bw_ratio >= BW_UPDATE_THRESHOLD_RATIO:
                    logger.debug(f"[CONTROLLER] Bandwidth ratio {bw_ratio:.4f} >= {BW_UPDATE_THRESHOLD_RATIO:.4f}")
                else :
                    if len(graph.modify_curr_link_bw(modified_link, curr_bw, True)) != 0:
                        logger.error(f"[CONTROLLER] Update link invalidated cache even though it wasn't requested")
                    logger.debug(f"[CONTROLLER] Bandwidth ratio not reached, skipping")
                    continue

                graph.set_last_update_bw(modified_link, curr_bw)

                all_modified_links.append(modified_link)
                for begin, end, path in graph.modify_curr_link_bw(modified_link, curr_bw):
                    if (begin, end) in inv_paths or (end, begin) in inv_paths:
                        logger.error(f"[CONTROLLER] Link not considered modified, but path already marked as invalid")
                    else:
                        logger.debug(f"[CONTROLLER] Path invalidated")
                        inv_paths[(begin, end)] = path

        self.port_stat_changes.clear()

        if len(all_modified_links) == 0:
            return {}
        
        logger.info(f"[CONTROLLER] Stat update caused {len(inv_paths)} paths to be invalidated")
        logger.info("[CONTROLLER] ******** END ********")
        return inv_paths

    @set_ev_cls(RouteReevaluateEvent, MAIN_DISPATCHER)
    def handle_route_reevaluate(self, ev: ofp_event.EventOFPMsgBase):
        logger.info("\n[CONTROLLER] ******** ROUTE AND SERVICE EVALUATION ********")
        self.attempt_rerouting()
        self.evaluate_services_qos()
        logger.info("[CONTROLLER] ********            END               ********")

    
    def add_service(self, service: Service) -> typing.Optional[Service]:
    #1. try to place it in the network
    #2. Set DNS entry
    #3. Save to file
    #Use lock to manage routes?
        logger.info(f"\n[CONTROLLER] ******** ADD SERVICE {service.domain} ********")
        service_file_path: str = self.data['conf']['service_list_file']
        if not 'qos' in self.data:
            logger.error("[CONTROLLER] Net not available")
            return None
        qos_config: list[typing.Dict[str, typing.Any]] = self.data['qos']
        qos = service.qos_index
        with self.service_lock:
            if not 'slices' in self.data or not 'graph' in self.data:
                logger.error("[CONTROLLER] Net not available")
                return None
            slices: typing.Dict[str, typing.List[str]] = self.data['slices']
            rem_slice = dict(filter(lambda the_slice: service.subscriber in the_slice[1], slices.items()))
            if len(rem_slice) != 1:
                logger.error("[CONTROLLER] Could not create service, subscriber ip does not exist")
                return None
            slice_id = list(rem_slice.keys())[0]
            used_hosts = set(filter(lambda ip: ip != None, map(lambda service: service.curr_ip, self.services.services)))
            used_hosts = used_hosts.union(map(lambda service: service.subscriber, self.services.services))
            logger.info(f"[CONTROLLER] Used hosts: {used_hosts}")
            possible_hosts = list(filter(lambda ip: ip != service.subscriber and not ip in used_hosts, slices[slice_id]))
            logger.info(f"[CONTROLLER] Service slice id: {slice_id}")
            logger.info(f"[CONTROLLER] Possible hosts: {possible_hosts}")
            if len(possible_hosts) == 0:
                logger.error("[CONTROLLER] Could not create service, no available hosts")
                return None
            service.slice = slice_id
            graph: net_graph.NetGraph = self.data['graph']
            for host in possible_hosts:
                possible_path = graph.find_path(net_graph.NetHost(host), net_graph.NetHost(service.subscriber), opt="hops", max_delay=qos_config[qos]["max_delay"], 
                                                   min_bw=qos_config[qos]['min_bw'], ignore_cache=True, keep_cache=True,
                                                   old_path=self.created_paths[(host, service.subscriber)])
                if possible_path != None:
                    selected_host = host
                    break 

            use_best_effort = False
            
            if possible_path == None:
                logger.warning("[CONTROLLER] Could not find host that satisfies QoS")
                all_paths: list[tuple[str, str, list[net_graph.NetLink]]] = []
                for host in possible_hosts:
                    possible_path = graph.find_path(net_graph.NetHost(host), net_graph.NetHost(service.subscriber), opt="hops", 
                                                   ignore_cache=True, keep_cache=True,
                                                   old_path=self.created_paths[(host, service.subscriber)])
                    if possible_path != None:
                        all_paths.append((host, service.subscriber, possible_path))
                if len(all_paths) == 0:
                    logger.error("[CONTROLLER] Could not find valid host")
                    return None
                all_paths = sorted(all_paths, key=lambda entry: min(entry[2], key=lambda link: link.bw), reverse=True)
                max_bw = max(all_paths[0][2], key=lambda link: link.bw).bw
                all_paths = list(filter(lambda entry: min(entry[2], key=lambda link: link.bw).bw == max_bw, all_paths))
                all_paths = sorted(all_paths, key=lambda entry: sum(map(lambda link: link.delay, entry[2])))
                selected_host = all_paths[0][0]
                possible_path = all_paths[0][2]
                use_best_effort = True

            if possible_path != None:
                logger.info(f"[CONTROLLER] Selected host: {selected_host}")
                if ((selected_host, service.subscriber) in self.created_paths and self.path_qos[(selected_host, service.subscriber)] == qos) \
                    or ((service.subscriber, selected_host) in self.created_paths and self.path_qos[(service.subscriber, selected_host)] == qos):
                    logger.info("[CONTROLLER] Path already exists with required QoS, not changing")
                else:
                    self.remove_route(net_graph.NetHost(selected_host), net_graph.NetHost(service.subscriber), True)
                    if not self.create_route(net_graph.NetHost(selected_host), net_graph.NetHost(service.subscriber), qos, use_best_effort):
                        logger.error("[CONTROLLER] Unexpected, could not create route")
                        return None
                service.curr_ip = selected_host
            else:
                logger.error("[CONTROLLER] Could not find host")
                return None
            
            zone_name = '.'.join(service.domain.split('.')[1:])
            logger.info(f"[CONTROLLER] Possible zone name: {zone_name}")
            result = self.dns_conn.create_zone_for_net(zone_name)
            if isinstance(result, str):
                logger.warning(f"[CONTROLLER] Create zone failed: {result}")
            else:
                logger.info("[CONTROLLER] Zone created")

            result = self.dns_conn.add_record(service.domain, zone_name, 3600, service.curr_ip)
            if isinstance(result, str):
                logger.error(f"[CONTROLLER] Add record to DNS failed: {result}")
                return None
            else:
                logger.info("[CONTROLLER] New DNS record added")
            
            errored = False
            try:
                result = self.services.add_service(copy.deepcopy(service))
                self.services.dump(service_file_path)
            except:
                logger.exception("Exception occurred")
                errored = True
            
            if errored or not result:
                logger.error("[CONTROLLER] Could not create service, cannot add to list")
                return None
            logger.info("[CONTROLLER] ******** END ********")
        return service
    
    def remove_service(self, id: int) -> bool:
        logger.info("[CONTROLLER] ******** REMOVE SERVICE ********")
        service_file_path: str = self.data['conf']['service_list_file']
        logger.info(f"[CONTROLLER] Remove service with ID {id}")
        with self.service_lock:
            service = self.services.get_service_by_id(id)
            if service == None:
                logger.error("[CONTROLLER] Service does not exist")
                return False
            begin = service.curr_ip
            end = service.subscriber

            qos = self.data['default_qos']

            if ((begin, end) in self.created_paths and self.path_qos[(begin, end)] == qos) or \
                ((end, begin) in self.created_paths and self.path_qos[(end, begin)] == qos):
                logger.info("[CONTROLLER] Path already uses default QoS, skip update")
            else:
                self.remove_route(net_graph.NetHost(begin), net_graph.NetHost(end), True)
                success = self.create_route(net_graph.NetHost(begin), net_graph.NetHost(end), qos, False)
                if not success:
                    success = self.create_route(net_graph.NetHost(begin), net_graph.NetHost(end), qos, True)
                if not success:
                    logger.error(f'{begin} -> {end} not possible')

            zone_name = '.'.join(service.domain.split('.')[1:])
            logger.info(f"[CONTROLLER] Possible zone name: {zone_name}")
            logger.info(f"[CONTROLLER] Remove record with ip: {service.curr_ip}")

            result = self.dns_conn.delete_record(service.domain, zone_name, service.curr_ip)
            if isinstance(result, str):
                logger.error(f"[CONTROLLER] Remove DNS record failed: {result}")
            else:
                logger.info("[CONTROLLER] DNS record removed")

            result = self.services.remove_service_by_id(id)
            if not result:
                logger.error("[CONTROLLER] Remove failed")
                return False 
            try:
                self.services.dump(service_file_path)
            except:
                logger.error("[CONTROLLER] File update failed")
                return False
        logger.info("[CONTROLLER] ******** END ********")
        return True