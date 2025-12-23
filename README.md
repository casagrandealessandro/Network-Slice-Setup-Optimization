## NB: All steps to be done in the Mininet VM

# Setup
Pull DNS container image from Docker:
```
docker pull technitium/dns-server
```

Build image:
```
cd dns_docker
docker build -t dns-mn .
cd ..
```

# Run
Make sure that port 53 is free for binding:
```
sudo sh dns_docker/stop_systemd_resolve.sh
```

Backup /etc/resolv.conf if necessary, because the script will overwrite it.
    
In a terminal:
```
ryu run controller/controller_main.py
```

In a second terminal:
```
sudo python3 topology.py
```