import pyshark
import pandas as pd
import os
import time
from datetime import datetime

def convert_to_epoch(timestamp):
    """Convert timestamp to epoch format"""
    if isinstance(timestamp, str):
        try:
            dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
            return dt.timestamp()
        except:
            return time.time()
    return timestamp.timestamp()

def get_protocol_number(protocol_name):
    """Convert protocol name to number"""
    protocol_map = {
        'TCP': 6,
        'UDP': 17,
        'ICMP': 1,
        'IGMP': 2
    }
    return protocol_map.get(protocol_name.upper(), 0)

def capture_traffic(interface, output_file):
    """Capture network traffic and save to CSV with required format"""
    # Define column names matching the analysis requirements
    columns = [
        'timestamp',
        'source_ip',
        'dest_ip',
        'protocol',
        'frame_length',
        'tcp_src_port',
        'tcp_dst_port',
        'udp_src_port',
        'udp_dst_port',
        'ip_length'
    ]
    
    # Create capture object with specific display filters
    capture = pyshark.LiveCapture(
        interface=interface,
        display_filter='ip'  # Only capture IP packets
    )
    
    packet_data = []
    print(f"Starting capture on interface: {interface}")
    
    try:
        for packet in capture.sniff_continuously():
            if 'IP' in packet:
                # Extract packet information
                packet_info = {
                    'timestamp': convert_to_epoch(packet.sniff_time),
                    'source_ip': packet.ip.src,
                    'dest_ip': packet.ip.dst,
                    'protocol': get_protocol_number(packet.transport_layer if hasattr(packet, 'transport_layer') else 'UNKNOWN'),
                    'frame_length': int(packet.length),
                    'tcp_src_port': getattr(packet.tcp, 'srcport', 0) if hasattr(packet, 'tcp') else 0,
                    'tcp_dst_port': getattr(packet.tcp, 'dstport', 0) if hasattr(packet, 'tcp') else 0,
                    'udp_src_port': getattr(packet.udp, 'srcport', 0) if hasattr(packet, 'udp') else 0,
                    'udp_dst_port': getattr(packet.udp, 'dstport', 0) if hasattr(packet, 'udp') else 0,
                    'ip_length': int(packet.ip.len) if hasattr(packet.ip, 'len') else 0
                }
                
                packet_data.append(packet_info)
                
                # Save data periodically to avoid memory issues
                if len(packet_data) >= 100:
                    df = pd.DataFrame(packet_data, columns=columns)
                    
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                    
                    # Save to CSV
                    df.to_csv(
                        output_file,
                        mode='a',
                        header=not os.path.exists(output_file),
                        index=False
                    )
                    
                    # Clear packet data
                    packet_data = []
                    
                    # Print status
                    print(f"Saved {len(df)} packets to {output_file}")
    
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as e:
        print(f"Error during capture: {str(e)}")
    finally:
        # Save any remaining packets
        if packet_data:
            df = pd.DataFrame(packet_data, columns=columns)
            df.to_csv(
                output_file,
                mode='a',
                header=not os.path.exists(output_file),
                index=False
            )
            print(f"Saved final {len(df)} packets to {output_file}")

def list_interfaces():
    """List all available network interfaces"""
    try:
        interfaces = pyshark.capture.capture.get_capture_interfaces()
        print("\nAvailable interfaces:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx}: {iface}")
        return interfaces
    except Exception as e:
        print(f"Error listing interfaces: {str(e)}")
        return []

if __name__ == "__main__":
    # List available interfaces
    interfaces = list_interfaces()
    
    if not interfaces:
        print("No interfaces found!")
        exit(1)
    
    # Get user selection
    while True:
        try:
            selection = int(input("\nSelect interface number: "))
            if 0 <= selection < len(interfaces):
                selected_iface = interfaces[selection]
                break
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a valid number.")
    
    # Set output file path
    output_dir = 'data'
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'captured_traffic.csv')
    
    print(f"\nOutput will be saved to: {output_file}")
    print("Press Ctrl+C to stop capture.")
    
    # Start capturing traffic
    capture_traffic(selected_iface, output_file)