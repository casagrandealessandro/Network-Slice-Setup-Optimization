import pickle
import argparse
import os

from typing import Optional, Any

"""
1. Domain name
2. Subcriber
3. Quality of service (index in QoS array)
4. Quality of service (type: best effort, ...)
5. Type of service
6. Current IP of service
"""

class Service:
    service_id = 0

    def __init__(self, domain: str, subscriber: str, qos_index: int, service_type: str):
        self.domain = domain
        self.subscriber = subscriber
        self.qos_index = qos_index
        self.service_type = service_type
        self.slice: Optional[str] = None
        self.curr_ip: Optional[str] = None
        self.id = Service.service_id
        Service.service_id += 1

    def __str__(self):
        as_dict = {"id": self.id, "domain": self.domain, "subscriber": self.subscriber, "qos": self.qos_index, "type": self.service_type, "ip": self.curr_ip}
        return f"{as_dict}"

class ServiceList:
    def __init__(self):
        self.services: list[Service] = []

    def dump(self, path: str):
        if not os.path.exists(path):
            _f = open(path, 'w')
            _f.close()
        with open(path, 'w+b') as service_file:
            pickle.dump(self.services, service_file)

    def __str__(self):
        return f"{self.services}"
    
    def get_service_by_id(self, id: int) -> Optional[Service]:
        services_with_id = list(filter(lambda service: service.id == id, self.services))
        if len(services_with_id) == 0:
            return None 
        return services_with_id[0]
    
    def add_service(self, new_service: Service) -> bool:
        services_with_domain = list(filter(lambda service: service.domain == new_service.domain, self.services))
        if len(services_with_domain) != 0:
            return False 
        self.services.append(new_service)
        return True
    
    def remove_service_by_id(self, id: int) -> bool:
        if self.get_service_by_id(id) == None:
            return False 
        self.services = list(filter(lambda service: service.id != id, self.services))
        return True
    
def add_service(domain: str, subscriber: str, qos: int, type: str, controller_ip: str, controller_port: int) -> tuple[Optional[Any], Optional[Any]]:
    import requests
    """
    "domain": Domain of the service
    "subscriber": IP of the user
    "qos": Index of QoS used by the service
    "type": Type of the service
    """
    response = requests.post(f"http://{controller_ip}:{controller_port}/api/v0/service/create", headers={'ContentType': 'application/json'}, 
                             json={"domain": domain, "subscriber": subscriber, "qos": qos, "type": type})
    if response.status_code != 200:
        return None, response.json()
    return response.json(), None

def remove_service(service_id: int, controller_ip: str, controller_port: int) -> tuple[Optional[Any], Optional[Any]]:
    import requests
    response = requests.delete(f"http://{controller_ip}:{controller_port}/api/v0/service/{service_id}/remove", 
                               headers={'ContentType': 'application/json'})
    if response.status_code != 200:
        return None, response.json()
    return response.json(), None
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Services',
                    description='Add new service')
    parser.add_argument("--domain", required=True)
    parser.add_argument("--sub", required=True)
    parser.add_argument("--qos", required=True)
    parser.add_argument("--type", required=True)
    parser.add_argument("--ip", default="127.0.0.1")
    parser.add_argument("--port", default=8080)
    args = parser.parse_args()
    print(f"Domain: {args.domain}, Subsrciber: {args.sub}, QoS: {args.qos}, Type: {args.type}")
    result = add_service(args.domain, args.sub, int(args.qos), args.type, args.ip, int(args.port))
    if result[1] == None:
        print(f"OK: {result[0]}")
    else:
        print(f"Error: {result[1]}")