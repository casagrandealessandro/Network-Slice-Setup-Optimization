import requests
from typing import Optional, Tuple
import traceback
import logging

logger = logging.getLogger('DNS')
logger.setLevel(logging.DEBUG)

"""
Module used to communicate with the DNS server
"""

"""
API methods:
- GET
- POST

Always uses application/x-www-form-urlencoded

Responses always use application/json
"""

class DNSServer:
    def __init__(self, user: str, password: str, server_url: str):
        self.user = user 
        self.password = password
        self.server_url = server_url
        self.token: Optional[str] = None

    def __del__(self):
        """http://server_url/api/user/logout?token="""
        request_result = requests.post(f"http://{self.server_url}/api/user/logout?token={self.token}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
        if request_result.status_code != 200:
            logger.error(f"Logout: {request_result.json()}")
            return 
        logger.info("Logout success")


    @classmethod
    def connect(cls, user: str, password: str, server_url: str):
        conn = DNSServer(user, password, server_url)
        try:
            """API format: http://server_url/api/user/login?user=user&pass=pass"""
            request_result = requests.post(f"http://{server_url}/api/user/login?user={user}&pass={password}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
        
            if request_result.status_code != 200: 
                return request_result.json()
            conn.token = request_result.json()["token"]
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        logger.info(f"Connected, token: {conn.token}")
        return conn
    
    def get_session_info(self):
        try:
            request_result = requests.get(f"http://{self.server_url}/api/user/session/get?token={self.token}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["info"]
    
    def get_user_profile(self):
        try:
            request_result = requests.get(f"http://{self.server_url}/api/user/profile/get?token={self.token}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["response"]
    
    def get_stats(self, stat_type: str = "LastHour"):
        try:
            request_result = requests.get(f"http://{self.server_url}/api/dashboard/stats/get?token={self.token}&type={stat_type}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["response"]["stats"]
    
    def get_zones(self):
        try:
            request_result = requests.get(f"http://{self.server_url}/api/zones/list?token={self.token}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["response"]["zones"]
    
    def create_zone_for_net(self, name: str):
        old_zones = self.get_zones()
        if not isinstance(old_zones, list):
            return "Could not get zones"
        
        zone_names = [zone["name"] for zone in old_zones]
        
        if name in zone_names:
            return "Zone already exists"
        
        try:
            request_result = requests.post(f"http://{self.server_url}/api/zones/create?token={self.token}&zone={name}&type=Primary", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["response"]["domain"]
    
    def delete_zone(self, name: str):
        old_zones = self.get_zones()
        if not isinstance(old_zones, list):
            return "Could not get zones"
        
        zone_names = [zone["name"] for zone in old_zones]
        
        if name not in zone_names:
            return "Zone does not exist"
        
        try:
            request_result = requests.post(f"http://{self.server_url}/api/zones/delete?token={self.token}&zone={name}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["status"]
    
    def get_zone_records(self, name: str):
        try:
            request_result = requests.get(f"http://{self.server_url}/api/zones/records/get?token={self.token}&domain={name}&listZone=true", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["response"]["records"]
    
    def add_record(self, domain: str, zone: str, ttl: int, ip: str):
        old_records = self.get_zone_records(zone)
        if not isinstance(old_records, list):
            return "Could not get records"
        
        record_names = [record["name"] for record in old_records]
        if domain in record_names:
            return "Record already exists"
        
        try:
            request_result = requests.post(f"http://{self.server_url}/api/zones/records/add?token={self.token}&domain={domain}&zone={zone}&type=A&ttl={ttl}&ipAddress={ip}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["response"]["addedRecord"]
    
    def delete_record(self, domain: str, zone: str, ip: str):
        old_records = self.get_zone_records(zone)
        if not isinstance(old_records, list):
            return "Could not get records"
        
        record_names = [record["name"] for record in old_records]
        if domain not in record_names:
            return "Record does not exist"
        
        try:
            request_result = requests.post(f"http://{self.server_url}/api/zones/records/delete?token={self.token}&domain={domain}&zone={zone}&type=A&ipAddress={ip}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["response"]
    
    def update_record(self, domain: str, zone: str, oldip: str, newip: str):
        old_records = self.get_zone_records(zone)
        if not isinstance(old_records, list):
            return "Could not get records"
        
        record_names = [record["name"] for record in old_records]
        if domain not in record_names:
            return "Record does not exist"
        
        try:
            request_result = requests.post(f"http://{self.server_url}/api/zones/records/update?token={self.token}&domain={domain}&zone={zone}&type=A&ipAddress={oldip}&newIpAddress={newip}", 
                                       headers={'ContentType': 'application/x-www-form-urlencoded'})
            if request_result.status_code != 200:
                return request_result.json()
        except:
            logger.error(traceback.format_exc())
            return "Exception occurred"
        return request_result.json()["response"]["updatedRecord"]
