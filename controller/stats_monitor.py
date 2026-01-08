import time
import logging
from typing import Dict, Tuple, Optional, List
from ryu.controller.controller import Datapath
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib import hub
from ryu.base import app_manager

from threading import Lock
import copy

class RouteReevaluateEvent(ofp_event.event.EventBase):
    def __init__(self):
        super().__init__()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class LinkStats:
    """Statistics for a single link/port"""
    def __init__(self, dpid: str, port_no: int):
        self.dpid = dpid
        self.port_no = port_no
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.rx_packets = 0
        self.tx_packets = 0
        self.timestamp = time.time()
        self.bandwidth_bps = 0.0  # bits per second
        
    def update(self, rx_bytes: int, tx_bytes: int, rx_packets: int, tx_packets: int):
        """Update statistics and calculate bandwidth"""
        current_time = time.time()
        time_delta = current_time - self.timestamp
        
        if time_delta > 0 and self.tx_bytes > 0 and self.rx_bytes > 0:
            # Calculate bandwidth based on transmitted bytes
            bytes_delta = (tx_bytes - self.tx_bytes) + (rx_bytes - self.rx_bytes)
            self.bandwidth_bps = (bytes_delta * 8) / time_delta  # bits per second
        
        self.rx_bytes = rx_bytes
        self.tx_bytes = tx_bytes
        self.rx_packets = rx_packets
        self.tx_packets = tx_packets
        self.timestamp = current_time


class StatsMonitor:
    """Statistics monitor for network links"""
    
    def __init__(self, controller: app_manager.RyuApp, poll_interval: int = 10):
        # Key: (dpid, port_no), Value: LinkStats
        self.link_stats: Dict[Tuple[str, int], LinkStats] = {}
        self.datapaths: List[Datapath] = []
        self.poll_interval = poll_interval
        self.dp_lock = Lock()
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.controller = controller

    def register_datapath(self, datapath: Datapath):
        """Register a datapath for monitoring"""
        with self.dp_lock:
            if datapath not in self.datapaths:
                self.datapaths.append(datapath)
                logger.info(f"[MONITOR] Registered datapath {datapath.id} for monitoring")

    def stop_monitor(self):
        self.monitor_thread.kill()
    
    def _monitor_loop(self):
        """Periodically request statistics from all datapaths"""
        while True:
            self.controller.send_event('SliceController', RouteReevaluateEvent())
            with self.dp_lock:
                for dp in self.datapaths:
                    self._request_stats(dp)
            hub.sleep(self.poll_interval)
        
    def update_port_stats(self, dpid: str, port_no: int, rx_bytes: int, tx_bytes: int, 
                         rx_packets: int, tx_packets: int):
        """Update statistics for a specific port"""
        key = (dpid, port_no)
        
        if key not in self.link_stats:
            self.link_stats[key] = LinkStats(dpid, port_no)
        
        self.link_stats[key].update(rx_bytes, tx_bytes, rx_packets, tx_packets)
        
    def get_bandwidth(self, dpid: str, port_no: int) -> Optional[float]:
        """Get current bandwidth in Mb per second for a link"""
        key = (dpid, port_no)
        if key in self.link_stats:
            return self.link_stats[key].bandwidth_bps / 1_000_000 # in Mbps
        return None
    
    def get_stats(self, dpid: str, port_no: int) -> Optional[LinkStats]:
        """Get full statistics for a link"""
        key = (dpid, port_no)
        return self.link_stats.get(key)
    
    def get_all_stats(self) -> Dict[Tuple[str, int], LinkStats]:
        """Get all link statistics"""
        return self.link_stats.copy()
    
    def _request_stats(self, datapath: Datapath):
        """Request port statistics from a datapath"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    def handle_port_stats_reply(self, ev: ofp_event.EventOFPPortStatsReply) -> Tuple[str, List[int]]:
        """Handle port statistics reply from a switch"""
        datapath = ev.msg.datapath
        dpid = str(datapath.id)

        ports: list[int] = []
        
        for stat in ev.msg.body:
            port_no = stat.port_no
            # Skip special ports (LOCAL, CONTROLLER, etc.)
            if port_no > 0xffffff00:
                continue
                
            self.update_port_stats(
                dpid=dpid,
                port_no=port_no,
                rx_bytes=stat.rx_bytes,
                tx_bytes=stat.tx_bytes,
                rx_packets=stat.rx_packets,
                tx_packets=stat.tx_packets
            )

            ports.append(port_no)
            logger.debug(f"[MONITOR] Updated stats for datapath {dpid} port {port_no}, curr bw: {self.get_bandwidth(dpid, port_no):.2f}, rx errors: {stat.rx_errors}, tx errors: {stat.tx_errors}")

        return (dpid, ports)