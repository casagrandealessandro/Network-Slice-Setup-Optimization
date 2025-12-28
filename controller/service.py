import pickle

from typing import Optional

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
        self.slice: Optional[int] = None
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
        with open(path) as service_file:
            pickle.dump(self.services, service_file)

    def __str__(self):
        return f"{self.services}"
    
    def get_service_by_id(self, id: int) -> Optional[Service]:
        services_with_id = list(filter(lambda service: service.id == id, self.services))
        if len(services_with_id):
            return None 
        return services_with_id[0]