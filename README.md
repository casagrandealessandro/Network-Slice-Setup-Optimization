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

Check the presence of dev_test image (from comnetsemu)
```
docker images | grep dev_test
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

# Check mininet-host connectivity and services
let this be the output of the service start phase:
```
Web Server: h13 (10.0.0.13)                      
Web Client: h4 (10.0.0.4)                       
Stream Server: h18 (10.0.0.18)                   
Stream Client: h11 (10.0.0.11)                   
                                                                                                                      
Starting web server on h13...
Starting stream server on h18...
Creating video file...

Starting client services...

*** Services started ***
```

Check services connectivity
Web service:
```
mininet> h13 netstat -tlnp | grep 80
mininet> h4 curl -I http://10.0.0.13:80
```
Streaming service (the download takes a while):
```
mininet> h18 netstat -tlnp | grep 80
mininet> h11 curl -o /dev/null http://10.0.0.18:80/video.dat
```

# Every time you restart make sure to clean all the previous stroz
```
sudo mn -c
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
```