# Network Slice Setup Optimization

SDN-based network slicing with QoS management, service migration, and dynamic DNS resolution.

This is a project developed for the Networking Mod. 2 course (University of Trento), by the students
- Casagrande Alessandro
- Lechthaler Niccolò 
- Vozza	Claudio

## Architecture
- **Topology**: Spine-leaf with redundancy
    - K spine switches
    - 2*K leaf switches
    - K hosts per leaf
    - each leaf is connected to all spines
    - every T seconds a random spine–leaf link fails in the env_events scenario (see below)
- **Slices**: 2 slices created statically (even and odd hosts), with possibility to create them dinamically
- **QoS Levels**: 3 tiers with bandwidth/delay guarantees
- **Services**: Dynamic placement with DNS integration
- **Migration**: Automatic service relocation on QoS degradation (3 violations → migrate)
- **QoS Tuning**: Bandwidth increase on first violation (+20%)
- **Scenarios**: based on type of traffic to generate ("default", "iperf_web", "iperf_stream", "env_events")

---

## Prerequisites

- ComNetsEmu VM running
- Docker installed
- Python 3.9+

## Setup

**All steps must be executed in the ComNetsEmu VM**

### 1. Install Dependencies

```bash
sudo pip3 install 'urllib3<2.0'
```

### 2. Build Docker Images

```bash
# Pull DNS server image
docker pull technitium/dns-server

# Build DNS container for Mininet
cd dns_docker
docker build -t dns-mn .
cd ..

# Build custom nginx
cd custom_nginx
docker build -t custom_nginx .
cd ..

# Build dev_test
cd dev_test_build
docker build -t dev_test .
cd ..
```

## Running the Network

### 1. Prepare DNS Port

Free port 53 for DNS binding:

```bash
sudo sh dns_docker/stop_systemd_resolve.sh
```

⚠️ **Warning**: This overwrites `/etc/resolv.conf`. Back it up if needed.

### 2. Start Controller

In terminal 1:

```bash
sudo ryu run controller/controller_main.py
```

### 3. Start Network Topology

In terminal 2:

```bash
sudo bash run_net.sh [scenario]
```

Available scenarios:
- `default` - No extra traffic
- `iperf_web` - Saturate web service link
- `iperf_stream` - Saturate streaming service link
- `env_events` - Random link failures with auto-recovery

### 4. Cleanup

Cleanup is automatic when exiting Mininet CLI with `quit`. Manual cleanup:

```bash
sudo mn -c
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
rm -rf config/dns_config/zones/*
```

## Controller REST API

Base URL: `http://127.0.0.1:8080/api/v0`

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/service/list` | List all services |
| POST | `/service/create` | Create new service |
| DELETE | `/service/:id/remove` | Remove service by ID |

### Create Service

**Request:**
```json
POST /api/v0/service/create
Content-Type: application/json

{
  "domain": "example.service.mn",
  "subscriber": "10.0.0.4",
  "qos": 1,
  "service_type": "browsing"
}
```

**Response:**
```json
{
  "status": "E_OK",
  "service_id": 3,
  "service_ip": "10.0.0.15"
}
```
