# GML to Mininet Network Converter

This tool converts GML (Graph Modeling Language) network topologies into Mininet network simulations. It provides a flexible way to simulate complex network topologies with customizable parameters.

## Prerequisites

- Oracle VirtualBox (latest version recommended)
- Mininet VM Image
- SSH Client (PuTTY recommended for Windows users)
- Python 3.x
- Required Python packages:
  - networkx
  - matplotlib
  - mininet

## Installation Steps

1. **Install VirtualBox**
   - Download VirtualBox from [official website](https://www.virtualbox.org/)
   - Install following your operating system's standard procedure

2. **Set up Mininet VM**
   - Download Mininet VM from [Mininet website](http://mininet.org/download/)
   - Import the .ova file into VirtualBox
   - Configure VM Network Settings:
     - Go to VM Settings > Network
     - Enable Network Adapter 1
     - Set to NAT
     - Click on Port Forwarding
     - Add new rule:
       - Name: SSH
       - Protocol: TCP
       - Host Port: 2223
       - Guest Port: 22

3. **Start Mininet VM**
   - Start the VM from VirtualBox
   - Wait for the login prompt
   - Default credentials:
     - Username: `mininet`
     - Password: `mininet`

## Connecting to Mininet VM

### Using SSH (Command Line)

```bash
# For Windows (PowerShell/CMD)
ssh -p 2223 mininet@localhost

# For Linux/Mac
ssh -p 2223 mininet@localhost
```

### Using PuTTY (Windows)
1. Open PuTTY
2. Enter connection details:
   - Host Name: `localhost`
   - Port: `2223`
   - Connection type: `SSH`
3. Click 'Open'
4. Login with credentials:
   - Username: `mininet`
   - Password: `mininet`

## Using the Converter

### Basic Usage

1. Transfer your GML file to VM:
```bash
scp -P 2223 your_topology.gml mininet@localhost:~/
```

2. Run the converter:
```bash
python gml_to_mininet.py your_topology.gml
```

### Advanced Usage

The script supports various command-line options:

```bash
python gml_to_mininet.py your_topology.gml [OPTIONS]

Options:
  --simplify            Simplify topology for large networks
  --max-nodes N        Maximum number of nodes (default: 30)
  --visualize          Create topology visualization
  --controller TYPE    Controller type (default/ryu/pox/onos)
  --link-bw BW        Link bandwidth in Mbps (default: 100)
  --link-delay DELAY   Link delay (default: 5ms)
  --enable-stp        Enable Spanning Tree Protocol
```

### Example Commands

1. Basic conversion:
```bash
python gml_to_mininet.py topology.gml
```

2. With custom parameters:
```bash
python gml_to_mininet.py topology.gml --link-bw 1000 --link-delay 2ms --visualize
```

3. Using specific controller:
```bash
python gml_to_mininet.py topology.gml --controller ryu
```

## File Transfer Between Host and VM

### From Host to VM
```bash
scp -P 2223 local_file mininet@localhost:~/
```

### From VM to Host
```bash
scp -P 2223 mininet@localhost:~/remote_file local_destination
```

## Troubleshooting

1. **Connection Issues**
   - Verify VM is running
   - Check port forwarding settings in VirtualBox
   - Ensure correct port (2223) is used
   - Verify no firewall blocking

2. **Script Errors**
   - Check Python dependencies are installed
   - Verify GML file format is correct
   - Check file permissions

3. **Network Simulation Issues**
   - Use `mn -c` to clean up previous sessions
   - Check controller settings
   - Verify link parameters are within reasonable ranges

## Common Commands in Mininet

```bash
# Clean up previous sessions
sudo mn -c

# Check network connectivity
pingall

# Show switch connections
net

# Display link information
links

# Exit Mininet
exit
```

## Visualization

The tool generates two types of output files:
- `topology.png`: Visual representation of the network
- `topology.json`: Detailed network data in JSON format

To transfer visualization files to your host machine:
```bash
scp -P 2223 mininet@localhost:~/topology.png ./
```

## Support

For issues and questions:
1. Check the troubleshooting section
2. Verify prerequisites are met
3. Check Mininet documentation
4. Review error messages carefully

