#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GML-to-Mininet Converter (GMC)
-------------------------------
This tool converts any GML network topology into a Mininet network simulation.
It allows you to configure various network parameters and run different test scenarios.

Example Usage:

1. scp -P 2223 any.gml mininet@localhost: "need to upload the gml file to the server"
2. ssh -p 2223 mininet@localhost "connect to the server"
3. python gml_to_mininet.py any.gml --max-nodes=20 --visualize --controller=ryu "run the script"

Author: [Emre_Turkoglu/Hafize_Sanli]
"""

import sys
import os
import time
import argparse
import json
import networkx as nx
import matplotlib.pyplot as plt
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error, warn
from mininet.clean import cleanup
import subprocess

# Default values
DEFAULT_LOG_LEVEL = 'info'
DEFAULT_MAX_NODES = 30
DEFAULT_CONTROLLER_TYPE = 'default'
DEFAULT_CONTROLLER_IP = '127.0.0.1'
DEFAULT_CONTROLLER_PORT = 6653
DEFAULT_LINK_BANDWIDTH = 100  # Mbps
DEFAULT_LINK_DELAY = '5ms'
DEFAULT_HOST_BANDWIDTH = 1000  # Mbps
DEFAULT_HOST_DELAY = '1ms'
DEFAULT_STP_TIMEOUT = 30  # seconds
DEFAULT_OUTPUT_FORMAT = 'png'

def run_cmd(cmd, verbose=False):
    """Execute command and return output"""
    if verbose:
        info(f'Running: {cmd}\n')
    try:
        result = subprocess.check_output(cmd, shell=True).decode('utf-8')
        if verbose:
            info(f'Result: {result}\n')
        return result
    except subprocess.CalledProcessError as e:
        if verbose:
            error(f'Error: {e.output.decode("utf-8")}\n')
        return e.output.decode('utf-8')

def diagnose_connectivity(net, host1, host2):
    """Diagnose connectivity issues between two hosts"""
    info(f'*** Diagnosing connectivity between {host1.name} and {host2.name}\n')
    
    # Check interface status
    info(f'  {host1.name} interfaces:\n')
    info(f'    {host1.cmd("ifconfig")}\n')
    
    info(f'  {host2.name} interfaces:\n')
    info(f'    {host2.cmd("ifconfig")}\n')
    
    # Check routing tables
    info(f'  {host1.name} routing table:\n')
    info(f'    {host1.cmd("route -n")}\n')
    
    info(f'  {host2.name} routing table:\n')
    info(f'    {host2.cmd("route -n")}\n')
    
    # Check if hosts can ping their default gateway
    if len(host1.intfs) > 0:
        switch_ip = host1.defaultIntf().updateIP()
        info(f'  {host1.name} pinging gateway: ')
        result = host1.cmd(f'ping -c1 -W1 {switch_ip}')
        info('SUCCESS\n' if '1 received' in result else 'FAILED\n')
    
    if len(host2.intfs) > 0:
        switch_ip = host2.defaultIntf().updateIP()
        info(f'  {host2.name} pinging gateway: ')
        result = host2.cmd(f'ping -c1 -W1 {switch_ip}')
        info('SUCCESS\n' if '1 received' in result else 'FAILED\n')
    
    # Try traceroute
    info(f'  {host1.name} -> {host2.name} traceroute:\n')
    info(f'    {host1.cmd("traceroute -n " + host2.IP())}\n')
    
    # Check ARP tables
    info(f'  {host1.name} ARP table:\n')
    info(f'    {host1.cmd("arp -n")}\n')
    
    info(f'  {host2.name} ARP table:\n')
    info(f'    {host2.cmd("arp -n")}\n')

def configure_host_networking(host):
    """Configure host networking settings"""
    # Enable promiscuous mode
    for intf in host.intfs.values():
        host.cmd(f'ifconfig {intf.name} promisc')
    
    # Disable IPv6 (to prevent potential issues)
    host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    
    # Set higher MTU (in case of issues)
    for intf in host.intfs.values():
        host.cmd(f'ifconfig {intf.name} mtu 9000')
    
    # Enable IP forwarding
    host.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    # Explicitly allow ICMP traffic
    host.cmd('iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT')
    host.cmd('iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT')

def visualize_topology(G, output_file, format='png'):
    """Create visualization of the network topology"""
    plt.figure(figsize=(12, 8))
    
    # Check if nodes have position attributes
    has_positions = all('pos' in G.nodes[node] for node in G.nodes())
    
    if has_positions:
        # Use geographical positions if available
        pos = {node: G.nodes[node]['pos'] for node in G.nodes()}
    else:
        info('Not all nodes have geographic coordinates, using spring layout\n')
        pos = nx.spring_layout(G, seed=42)
    
    # Draw the network
    nx.draw(G, pos, with_labels=True, node_color='skyblue', 
            node_size=700, font_size=10, font_weight='bold')
    
    # Add edge properties (bandwidth and delay)
    edge_labels = {}
    for u, v, data in G.edges(data=True):
        bw = data.get('bandwidth', DEFAULT_LINK_BANDWIDTH)
        delay = data.get('delay', DEFAULT_LINK_DELAY)
        edge_labels[(u, v)] = f"{bw}Mbps\n{delay}"
    
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)
    
    # Save the image
    plt.savefig(f"{output_file}.{format}")
    info(f'Topology image saved to {output_file}.{format}\n')
    
    # Also save in JSON format (for detailed analysis)
    json_data = nx.node_link_data(G)
    with open(f"{output_file}.json", 'w') as f:
        json.dump(json_data, f, indent=2)
    info(f'Topology data saved to {output_file}.json\n')

def simplify_topology(G, max_nodes=None):
    """Simplify topology by keeping only the first max_nodes nodes"""
    if max_nodes and len(G.nodes()) > max_nodes:
        info(f'Network topology is too large. Simplifying to first {max_nodes} nodes\n')
        # Keep only the first max_nodes nodes
        nodes_to_keep = list(G.nodes())[:max_nodes]
        G = G.subgraph(nodes_to_keep).copy()
    return G

def enable_stp(switch_name, priority=None):
    """Enable Spanning Tree Protocol on a switch"""
    cmd = 'ovs-vsctl set bridge {} stp_enable=true'.format(switch_name)
    result = run_cmd(cmd)
    info('  STP enabled on {}\n'.format(switch_name))
    
    # Set STP priority
    if priority is not None:
        cmd = 'ovs-vsctl set bridge {} other-config:stp-priority=0x{:x}'.format(
            switch_name, priority)
        run_cmd(cmd)
        info(f'  {switch_name} STP priority set to 0x{priority:x}\n')
    
    return result

def setup_manual_arp_entries(net, hosts):
    """Set up manual ARP table entries to bypass ARP timeouts"""
    info('*** Setting up manual ARP entries\n')
    for src in hosts:
        for dst in hosts:
            if src != dst:
                info(f'  Adding {dst.IP()} -> {dst.MAC()} entry to {src.name}\n')
                src.setARP(ip=dst.IP(), mac=dst.MAC())

def start_remote_controller(controller_type, ip='127.0.0.1', port=6653):
    """Start a remote controller and return the controller object"""
    if controller_type.lower() == 'ryu':
        info('*** Starting Ryu controller\n')
        cmd = f"ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest &"
        proc = subprocess.Popen(cmd, shell=True)
        time.sleep(5)  # Wait for controller to start
        info('*** Ryu controller PID: {}\n'.format(proc.pid))
        return lambda name: RemoteController(name, ip=ip, port=port), proc
    elif controller_type.lower() == 'pox':
        info('*** Starting POX controller\n')
        cmd = f"pox.py openflow.discovery forwarding.l2_learning openflow.spanning_tree &"
        proc = subprocess.Popen(cmd, shell=True)
        time.sleep(5)  # Wait for controller to start
        info('*** POX controller PID: {}\n'.format(proc.pid))
        return lambda name: RemoteController(name, ip=ip, port=port), proc
    elif controller_type.lower() == 'onos':
        info('*** Using ONOS controller (must be manually started)\n')
        return lambda name: RemoteController(name, ip=ip, port=port), None
    else:
        info('*** Using default Mininet controller\n')
        return Controller, None

def test_network_connectivity(net, ping_count=3, timeout=2):
    """Test network connectivity and report results"""
    info('*** Testing network connectivity\n')
    
    results = {}
    
    # Perform ping tests between all hosts
    for src in net.hosts:
        results[src.name] = {}
        for dst in net.hosts:
            if src != dst:
                info(f'  {src.name} --> {dst.name}: ')
                cmd = f'ping -c{ping_count} -W{timeout} {dst.IP()}'
                output = src.cmd(cmd)
                
                # Analyze results
                if '0% packet loss' in output or ' 0% packet loss' in output:
                    info('SUCCESS\n')
                    results[src.name][dst.name] = {
                        'status': 'success',
                        'loss': 0
                    }
                else:
                    # Extract packet loss percentage
                    try:
                        loss = int(output.split('%')[0].split(' ')[-1])
                    except (IndexError, ValueError):
                        loss = 100
                    
                    if loss < 100:
                        info(f'PARTIAL ({loss}% loss)\n')
                        results[src.name][dst.name] = {
                            'status': 'partial',
                            'loss': loss
                        }
                    else:
                        info('FAILED\n')
                        results[src.name][dst.name] = {
                            'status': 'failed',
                            'loss': 100
                        }
    
    # Summary statistics
    total_tests = 0
    successful_tests = 0
    partial_tests = 0
    failed_tests = 0
    
    for src in results:
        for dst in results[src]:
            total_tests += 1
            if results[src][dst]['status'] == 'success':
                successful_tests += 1
            elif results[src][dst]['status'] == 'partial':
                partial_tests += 1
            else:
                failed_tests += 1
    
    success_rate = (successful_tests / total_tests) * 100 if total_tests > 0 else 0
    info(f'\n*** Connectivity Test Summary:\n')
    info(f'  Total tests: {total_tests}\n')
    info(f'  Successful: {successful_tests} ({success_rate:.1f}%)\n')
    info(f'  Partial: {partial_tests}\n')
    info(f'  Failed: {failed_tests}\n')
    
    # Save results to JSON file
    with open('connectivity_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    info('  Detailed results saved to connectivity_results.json\n')
    
    return results

def create_network(gml_file, options):
    """Create a Mininet network from a GML file"""
    # First run cleanup to ensure no old instances are running
    cleanup()
    
    # Parse GML file
    try:
        G = nx.read_gml(gml_file, label='id')
        info(f'GML file successfully read: {len(G.nodes())} nodes, {len(G.edges())} edges\n')
    except Exception as e:
        error(f'Error reading GML file: {e}\n')
        sys.exit(1)
    
    # Simplify topology if required
    if options.simplify:
        G = simplify_topology(G, options.max_nodes)
    
    # Visualize topology
    if options.visualize:
        visualize_topology(G, options.output, options.format)
    
    # Select controller
    controller_obj, controller_proc = start_remote_controller(
        options.controller,
        options.controller_ip,
        options.controller_port
    )
    
    # Create network
    info('*** Creating network\n')
    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')
    
    # Add controller
    if options.controller.lower() != 'default':
        net.addController('c0', controller=controller_obj)
    else:
        net.addController('c0')
    
    # Create nodes - Node IDs start from 1
    info('*** Adding switches\n')
    switches = {}
    node_mapping = {}  # Map original node IDs to sequential IDs
    
    # Create mapping from original node IDs to sequential IDs
    for i, node in enumerate(G.nodes(), 1):
        node_mapping[node] = i
        
    # Create switches with sequential IDs
    for node, seq_id in node_mapping.items():
        switches[node] = net.addSwitch(f's{seq_id}', cls=OVSSwitch, failMode=options.switch_mode)
        info(f'  Added switch s{seq_id}\n')
    
    # Create hosts with sequential IDs
    info('*** Adding hosts\n')
    hosts = {}
    for node, seq_id in node_mapping.items():
        # Create hosts with specific MAC addresses to avoid conflicts
        mac_addr = '00:00:00:00:{:02x}:{:02x}'.format(seq_id // 256, seq_id % 256)
        hosts[node] = net.addHost(f'h{seq_id}', ip=f'10.0.0.{seq_id}/8', mac=mac_addr)
        info(f'  Added host h{seq_id}: 10.0.0.{seq_id}/8 (MAC: {mac_addr})\n')
    
    # Add host-switch links first
    info('*** Adding host-switch links\n')
    for node in G.nodes():
        seq_id = node_mapping[node]
        net.addLink(hosts[node], switches[node], bw=options.host_bw, delay=options.host_delay)
        info(f'  h{seq_id} <-> s{seq_id} (BW: {options.host_bw}Mbps, Delay: {options.host_delay})\n')
    
    # Add switch-switch links with delay and bandwidth
    info('*** Adding switch-switch links\n')
    for edge in G.edges():
        src, dst = edge
        src_id = node_mapping[src]
        dst_id = node_mapping[dst]
        
        # Default parameters
        bw = options.link_bw
        delay = options.link_delay
        
        # Extract edge properties if available
        if 'bandwidth' in G[src][dst]:
            bw = G[src][dst]['bandwidth']
        if 'delay' in G[src][dst]:
            delay = G[src][dst]['delay']
        
        # Create link with TCLink for bandwidth/delay control
        net.addLink(switches[src], switches[dst], cls=TCLink, bw=bw, delay=delay, loss=0)
        info(f'  s{src_id} <-> s{dst_id} (BW: {bw}Mbps, Delay: {delay})\n')
    
    # Build and start the network
    info('*** Starting network\n')
    net.build()
    net.start()
    
    # Configure all host networking
    if options.configure_hosts:
        info('*** Configuring host networking\n')
        for host in net.hosts:
            info(f'  Configuring {host.name}\n')
            configure_host_networking(host)
    
    # Set up manual ARP entries
    if options.manual_arp:
        setup_manual_arp_entries(net, net.hosts)
    
    # Enable STP on all switches
    if options.enable_stp:
        info('*** Enabling STP on all switches (to prevent loops)\n')
        for i, s in enumerate(net.switches, 1):
            # Give different STP priorities to different switches
            priority = i * 1000  # s1 = 1000, s2 = 2000, ...
            enable_stp(s.name, priority)
        
        # Wait for STP to converge
        info(f'*** Waiting {options.stp_timeout} seconds for STP to converge...\n')
        time.sleep(options.stp_timeout)
    
    # Configure switches as standalone L2 devices
    if options.switch_mode == 'standalone':
        info('*** Configuring switches as standalone L2 devices\n')
        for s in net.switches:
            cmd = 'ovs-vsctl set bridge {} fail-mode=standalone'.format(s.name)
            run_cmd(cmd)
            info('  {} configured as standalone switch\n'.format(s.name))
    
    # Set MAC learning timeout
    info('*** Configuring MAC address learning with shorter timeout\n')
    for s in net.switches:
        cmd = 'ovs-vsctl set bridge {} other-config:mac-aging-time=30'.format(s.name)
        run_cmd(cmd)
        info('  MAC aging time set to 30 seconds on {}\n'.format(s.name))
    
    # Flood network to build MAC tables
    if options.flood_network:
        info('*** Initial network flood to build MAC tables\n')
        for host in net.hosts:
            host.cmd('ping -c 3 -b 10.255.255.255')
        time.sleep(2)
    
    # Test network connectivity
    if options.test_connectivity:
        test_network_connectivity(net, options.ping_count, options.ping_timeout)
    
    # Display flow tables
    if options.show_flows:
        info('*** Checking switch flow tables\n')
        for s in net.switches:
            info('  Flow table for {}:\n'.format(s.name))
            flows = run_cmd('ovs-ofctl dump-flows {}'.format(s.name))
            info('    {}\n'.format(flows))
            
            # Check MAC address table
            info('  MAC address table for {}:\n'.format(s.name))
            macs = run_cmd('ovs-appctl fdb/show {}'.format(s.name))
            info('    {}\n'.format(macs))
    
    # Print STP status
    if options.enable_stp:
        info('*** STP Status for all switches\n')
        for s in net.switches:
            stp_status = run_cmd('ovs-vsctl get bridge {} stp_enable'.format(s.name))
            info('  {}: STP {}\n'.format(s.name, "enabled" if stp_status.strip() == "true" else "disabled"))
            
            # Print STP bridge info
            info('  STP details for {}:\n'.format(s.name))
            stp_info = run_cmd('ovs-appctl stp/show {}'.format(s.name))
            info('    {}\n'.format(stp_info))
    
    info('*** Network is ready\n')
    info('*** Starting Mininet CLI...\n')
    
    # Start CLI
    CLI(net)
    
    # Clean up after CLI exit
    info('*** Stopping network\n')
    net.stop()
    
    # Stop controller process
    if controller_proc:
        info('*** Stopping controller\n')
        os.system(f'kill {controller_proc.pid}')
    
    return net

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Convert GML network topologies to Mininet networks',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('gml_file', help='GML file to convert')
    
    parser.add_argument('--simplify', action='store_true', default=True,
                        help='Simplify topology (for very large networks)')
    
    parser.add_argument('--max-nodes', type=int, default=DEFAULT_MAX_NODES,
                        help='Maximum number of nodes in simplified topology')
    
    parser.add_argument('--visualize', action='store_true', default=True,
                        help='Visualize network topology')
    
    parser.add_argument('--output', type=str, default='topology',
                        help='Output file name (without extension)')
    
    parser.add_argument('--format', type=str, default=DEFAULT_OUTPUT_FORMAT,
                        choices=['png', 'pdf', 'svg'],
                        help='Visualization output format')
    
    parser.add_argument('--controller', type=str, default=DEFAULT_CONTROLLER_TYPE,
                        choices=['default', 'ryu', 'pox', 'onos', 'remote'],
                        help='Controller type to use')
    
    parser.add_argument('--controller-ip', type=str, default=DEFAULT_CONTROLLER_IP,
                        help='Remote controller IP address')
    
    parser.add_argument('--controller-port', type=int, default=DEFAULT_CONTROLLER_PORT,
                        help='Remote controller port number')
    
    parser.add_argument('--switch-mode', type=str, default='standalone',
                        choices=['standalone', 'secure'],
                        help='OVS switch operation mode')
    
    parser.add_argument('--link-bw', type=int, default=DEFAULT_LINK_BANDWIDTH,
                        help='Default bandwidth for switch-switch links (Mbps)')
    
    parser.add_argument('--link-delay', type=str, default=DEFAULT_LINK_DELAY,
                        help='Default delay for switch-switch links')
    
    parser.add_argument('--host-bw', type=int, default=DEFAULT_HOST_BANDWIDTH,
                        help='Default bandwidth for host-switch links (Mbps)')
    
    parser.add_argument('--host-delay', type=str, default=DEFAULT_HOST_DELAY,
                        help='Default delay for host-switch links')
    
    parser.add_argument('--enable-stp', action='store_true', default=True,
                        help='Enable Spanning Tree Protocol')
    
    parser.add_argument('--stp-timeout', type=int, default=DEFAULT_STP_TIMEOUT,
                        help='Wait time for STP convergence (seconds)')
    
    parser.add_argument('--configure-hosts', action='store_true', default=True,
                        help='Automatically configure host networking')
    
    parser.add_argument('--manual-arp', action='store_true', default=True,
                        help='Add manual ARP entries')
    
    parser.add_argument('--flood-network', action='store_true', default=True,
                        help='Flood network to build MAC tables')
    
    parser.add_argument('--test-connectivity', action='store_true', default=True,
                        help='Test network connectivity')
    
    parser.add_argument('--ping-count', type=int, default=3,
                        help='Number of pings in connectivity test')
    
    parser.add_argument('--ping-timeout', type=int, default=2,
                        help='Ping timeout (seconds)')
    
    parser.add_argument('--show-flows', action='store_true', default=True,
                        help='Show switch flow tables')
    
    parser.add_argument('--log-level', type=str, default=DEFAULT_LOG_LEVEL,
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Logging level')
    
    return parser.parse_args()

def print_header():
    """Print header information"""
    header = """
    ################################################
    #                                              #
    #       GML-to-Mininet Converter (GMC)        #
    #                                              #
    #    Convert any GML topology to Mininet      #
    #                                              #
    ################################################
    """
    print(header)

def main():
    """Main function"""
    print_header()
    
    # Parse command line arguments
    options = parse_arguments()
    
    # Set log level
    setLogLevel(options.log_level)
    
    # Print script info
    info('Script starting...\n')
    info(f'GML file: {options.gml_file}\n')
    info(f'Controller: {options.controller}\n')
    
    # Create network
    create_network(options.gml_file, options)
    
    # Success message
    info('Operation completed.\n')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        info("\nOperation cancelled by user. Exiting...\n")
        # Clean up
        cleanup()
    except Exception as e:
        error(f"Error occurred: {e}\n")
        # Clean up
        cleanup()
        sys.exit(1) 