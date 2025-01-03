from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
import os
import time
from datetime import datetime
import logging
import numpy as np
from collections import defaultdict

def calculate_bulk_statistics(packets, timestamps):
    """Calculate bulk transfer statistics"""
    if not packets:
        return {
            'avg_bytes_bulk': 0,
            'avg_packets_bulk': 0,
            'avg_bulk_rate': 0,
            'bulk_size': 0
        }
    
    bulk_starts = []
    bulk_sizes = []
    bulk_durations = []
    bulk_packets = []
    
    current_bulk = []
    current_start = None
    
    for i, (packet, timestamp) in enumerate(zip(packets, timestamps)):
        if len(packet) > 0:
            if not current_bulk:
                current_start = timestamp
            current_bulk.append(len(packet))
        elif current_bulk:
            if len(current_bulk) >= 4:  # Minimum bulk size
                bulk_starts.append(current_start)
                bulk_sizes.append(sum(current_bulk))
                bulk_durations.append(timestamp - current_start)
                bulk_packets.append(len(current_bulk))
            current_bulk = []
            current_start = None
    
    if not bulk_sizes:
        return {
            'avg_bytes_bulk': 0,
            'avg_packets_bulk': 0,
            'avg_bulk_rate': 0,
            'bulk_size': 0
        }
    
    return {
        'avg_bytes_bulk': np.mean(bulk_sizes),
        'avg_packets_bulk': np.mean(bulk_packets),
        'avg_bulk_rate': sum(bulk_sizes) / sum(bulk_durations) if sum(bulk_durations) > 0 else 0,
        'bulk_size': sum(bulk_sizes)
    }

def calculate_active_idle_times(timestamps, threshold=2.0):
    """Calculate active and idle times"""
    if len(timestamps) < 2:
        return {
            'active_mean': 0,
            'active_std': 0,
            'active_max': 0,
            'active_min': 0,
            'idle_mean': 0,
            'idle_std': 0,
            'idle_max': 0,
            'idle_min': 0
        }
    
    gaps = np.diff(timestamps)
    active_times = gaps[gaps <= threshold]
    idle_times = gaps[gaps > threshold]
    
    return {
        'active_mean': np.mean(active_times) if len(active_times) > 0 else 0,
        'active_std': np.std(active_times) if len(active_times) > 1 else 0,
        'active_max': np.max(active_times) if len(active_times) > 0 else 0,
        'active_min': np.min(active_times) if len(active_times) > 0 else 0,
        'idle_mean': np.mean(idle_times) if len(idle_times) > 0 else 0,
        'idle_std': np.std(idle_times) if len(idle_times) > 1 else 0,
        'idle_max': np.max(idle_times) if len(idle_times) > 0 else 0,
        'idle_min': np.min(idle_times) if len(idle_times) > 0 else 0
    }

def calculate_flow_statistics(flow):
    """Calculate statistics for a flow"""
    result = {}
    
    # Basic flow information
    result['Destination Port'] = flow['dst_port']
    duration = flow['end_time'] - flow['start_time'] if flow['end_time'] and flow['start_time'] else 0
    result['Flow Duration'] = duration
    
    # Packet counts
    fwd_packets = len(flow['forward_packets'])
    bwd_packets = len(flow['backward_packets'])
    result['Total Fwd Packets'] = fwd_packets
    result['Total Backward Packets'] = bwd_packets
    
    # Packet lengths
    fwd_lengths = flow['forward_lengths']
    bwd_lengths = flow['backward_lengths']
    fwd_times = flow['forward_timestamps']
    bwd_times = flow['backward_timestamps']
    
    # Calculate length statistics
    if fwd_lengths:
        result['Total Length of Fwd Packets'] = sum(fwd_lengths)
        result['Fwd Packet Length Max'] = max(fwd_lengths)
        result['Fwd Packet Length Min'] = min(fwd_lengths)
        result['Fwd Packet Length Mean'] = np.mean(fwd_lengths)
        result['Fwd Packet Length Std'] = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
    else:
        result['Total Length of Fwd Packets'] = 0
        result['Fwd Packet Length Max'] = 0
        result['Fwd Packet Length Min'] = 0
        result['Fwd Packet Length Mean'] = 0
        result['Fwd Packet Length Std'] = 0
    
    if bwd_lengths:
        result['Total Length of Bwd Packets'] = sum(bwd_lengths)
        result['Bwd Packet Length Max'] = max(bwd_lengths)
        result['Bwd Packet Length Min'] = min(bwd_lengths)
        result['Bwd Packet Length Mean'] = np.mean(bwd_lengths)
        result['Bwd Packet Length Std'] = np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0
    else:
        result['Total Length of Bwd Packets'] = 0
        result['Bwd Packet Length Max'] = 0
        result['Bwd Packet Length Min'] = 0
        result['Bwd Packet Length Mean'] = 0
        result['Bwd Packet Length Std'] = 0
    
    # Flow rates
    duration = max(duration, 1)  # Avoid division by zero
    total_bytes = result['Total Length of Fwd Packets'] + result['Total Length of Bwd Packets']
    total_packets = fwd_packets + bwd_packets
    
    result['Flow Bytes/s'] = total_bytes / duration
    result['Flow Packets/s'] = total_packets / duration
    
    # Calculate IAT (Inter Arrival Time) statistics
    if len(fwd_times) > 1:
        fwd_iats = np.diff(fwd_times)
        result['Fwd IAT Total'] = np.sum(fwd_iats)
        result['Fwd IAT Mean'] = np.mean(fwd_iats)
        result['Fwd IAT Std'] = np.std(fwd_iats)
        result['Fwd IAT Max'] = np.max(fwd_iats)
        result['Fwd IAT Min'] = np.min(fwd_iats)
    else:
        result['Fwd IAT Total'] = 0
        result['Fwd IAT Mean'] = 0
        result['Fwd IAT Std'] = 0
        result['Fwd IAT Max'] = 0
        result['Fwd IAT Min'] = 0
    
    if len(bwd_times) > 1:
        bwd_iats = np.diff(bwd_times)
        result['Bwd IAT Total'] = np.sum(bwd_iats)
        result['Bwd IAT Mean'] = np.mean(bwd_iats)
        result['Bwd IAT Std'] = np.std(bwd_iats)
        result['Bwd IAT Max'] = np.max(bwd_iats)
        result['Bwd IAT Min'] = np.min(bwd_iats)
    else:
        result['Bwd IAT Total'] = 0
        result['Bwd IAT Mean'] = 0
        result['Bwd IAT Std'] = 0
        result['Bwd IAT Max'] = 0
        result['Bwd IAT Min'] = 0
    
    # Flow IAT statistics
    all_times = sorted(fwd_times + bwd_times)
    if len(all_times) > 1:
        flow_iats = np.diff(all_times)
        result['Flow IAT Mean'] = np.mean(flow_iats)
        result['Flow IAT Std'] = np.std(flow_iats)
        result['Flow IAT Max'] = np.max(flow_iats)
        result['Flow IAT Min'] = np.min(flow_iats)
    else:
        result['Flow IAT Mean'] = 0
        result['Flow IAT Std'] = 0
        result['Flow IAT Max'] = 0
        result['Flow IAT Min'] = 0
    
    # Flag counts
    flags = flow['flags']
    result['Fwd PSH Flags'] = flags.get('PSH', 0)
    result['Bwd PSH Flags'] = 0  # Typically not tracked separately
    result['Fwd URG Flags'] = flags.get('URG', 0)
    result['Bwd URG Flags'] = 0  # Typically not tracked separately
    result['FIN Flag Count'] = flags.get('FIN', 0)
    result['SYN Flag Count'] = flags.get('SYN', 0)
    result['RST Flag Count'] = flags.get('RST', 0)
    result['PSH Flag Count'] = flags.get('PSH', 0)
    result['ACK Flag Count'] = flags.get('ACK', 0)
    result['URG Flag Count'] = flags.get('URG', 0)
    result['CWE Flag Count'] = flags.get('CWE', 0)
    result['ECE Flag Count'] = flags.get('ECE', 0)
    
    # Header lengths
    result['Fwd Header Length'] = flow.get('fwd_header_length', 0)
    result['Bwd Header Length'] = flow.get('bwd_header_length', 0)
    
    # Packet rates
    result['Fwd Packets/s'] = fwd_packets / duration
    result['Bwd Packets/s'] = bwd_packets / duration
    
    # Packet length statistics
    all_lengths = fwd_lengths + bwd_lengths
    if all_lengths:
        result['Min Packet Length'] = min(all_lengths)
        result['Max Packet Length'] = max(all_lengths)
        result['Packet Length Mean'] = np.mean(all_lengths)
        result['Packet Length Std'] = np.std(all_lengths) if len(all_lengths) > 1 else 0
        result['Packet Length Variance'] = np.var(all_lengths) if len(all_lengths) > 1 else 0
    else:
        result['Min Packet Length'] = 0
        result['Max Packet Length'] = 0
        result['Packet Length Mean'] = 0
        result['Packet Length Std'] = 0
        result['Packet Length Variance'] = 0
    
    # Additional metrics
    result['Down/Up Ratio'] = bwd_packets / max(fwd_packets, 1)
    result['Average Packet Size'] = total_bytes / max(total_packets, 1)
    result['Avg Fwd Segment Size'] = result['Total Length of Fwd Packets'] / max(fwd_packets, 1)
    result['Avg Bwd Segment Size'] = result['Total Length of Bwd Packets'] / max(bwd_packets, 1)
    result['Fwd Header Length.1'] = result['Fwd Header Length']
    
    # Bulk statistics
    fwd_bulk = calculate_bulk_statistics(flow['forward_packets'], fwd_times)
    bwd_bulk = calculate_bulk_statistics(flow['backward_packets'], bwd_times)
    
    result['Fwd Avg Bytes/Bulk'] = fwd_bulk['avg_bytes_bulk']
    result['Fwd Avg Packets/Bulk'] = fwd_bulk['avg_packets_bulk']
    result['Fwd Avg Bulk Rate'] = fwd_bulk['avg_bulk_rate']
    result['Bwd Avg Bytes/Bulk'] = bwd_bulk['avg_bytes_bulk']
    result['Bwd Avg Packets/Bulk'] = bwd_bulk['avg_packets_bulk']
    result['Bwd Avg Bulk Rate'] = bwd_bulk['avg_bulk_rate']
    
    # Subflow statistics
    result['Subflow Fwd Packets'] = fwd_packets
    result['Subflow Fwd Bytes'] = result['Total Length of Fwd Packets']
    result['Subflow Bwd Packets'] = bwd_packets
    result['Subflow Bwd Bytes'] = result['Total Length of Bwd Packets']
    
    # Init window sizes
    result['Init_Win_bytes_forward'] = flow.get('init_win_bytes_forward', 0)
    result['Init_Win_bytes_backward'] = flow.get('init_win_bytes_backward', 0)
    
    # Active data packets and segment size
    result['act_data_pkt_fwd'] = len([p for p in flow['forward_packets'] if len(p) > 0])
    result['min_seg_size_forward'] = min(fwd_lengths) if fwd_lengths else 0
    
    # Active/Idle times
    active_idle = calculate_active_idle_times(all_times)
    result.update(active_idle)
    
    return result

def save_flows_to_csv(flows, output_file, columns):
    """Save flows to CSV file"""
    try:
        flow_data = []
        for flow in flows.values():
            flow_stats = calculate_flow_statistics(flow)
            flow_data.append(flow_stats)
        
        df = pd.DataFrame(flow_data)
        
        # Ensure all required columns are present
        for col in columns:
            if col not in df.columns:
                df[col] = 0
        
        # Reorder columns to match expected format
        df = df[columns]
        
        # Append to existing file if it exists
        mode = 'a' if os.path.exists(output_file) else 'w'
        header = not os.path.exists(output_file)
        
        df.to_csv(output_file, mode=mode, header=header, index=False)
        return True
    except Exception as e:
        logging.error(f"Error saving flows to CSV: {str(e)}")
        return False

def capture_traffic(interface, output_file, stop_event):
    """Capture network traffic and save to CSV with required format"""
    columns = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets',
        'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Fwd Packet Length Max',
        'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
        'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
        'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total',
        'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
        'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
        'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
        'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
        'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
        'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
        'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
        'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
        'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
        'Avg Bwd Segment Size', 'Fwd Header Length.1',
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
        'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
        'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
        'act_data_pkt_fwd', 'min_seg_size_forward',
        'Active Mean', 'Active Std', 'Active Max', 'Active Min',
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]

    flows = defaultdict(lambda: {
        'start_time': None,
        'end_time': None,
        'forward_packets': [],
        'backward_packets': [],
        'forward_lengths': [],
        'backward_lengths': [],
        'forward_timestamps': [],
        'backward_timestamps': [],
        'flags': defaultdict(int),
        'protocol': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'fwd_header_length': 0,
        'bwd_header_length': 0,
        'init_win_bytes_forward': 0,
        'init_win_bytes_backward': 0
    })

    def packet_callback(packet):
        if stop_event.is_set():
            return

        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                timestamp = float(packet.time)
                
                if TCP in packet:
                    protocol = 'TCP'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = packet[TCP].flags
                    header_length = len(packet[TCP])
                    if not hasattr(packet[TCP], 'window'):
                        window_size = 0
                    else:
                        window_size = packet[TCP].window
                elif UDP in packet:
                    protocol = 'UDP'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    flags = 0
                    header_length = len(packet[UDP])
                    window_size = 0
                else:
                    return

                packet_length = len(packet)
                flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
                flow = flows[flow_key]

                if flow['start_time'] is None:
                    flow['start_time'] = timestamp
                    flow['src_ip'] = src_ip
                    flow['dst_ip'] = dst_ip
                    flow['src_port'] = src_port
                    flow['dst_port'] = dst_port
                    flow['protocol'] = protocol
                    flow['init_win_bytes_forward'] = window_size

                flow['end_time'] = timestamp

                is_forward = (src_ip == flow['src_ip'] and src_port == flow['src_port'])
                
                if is_forward:
                    flow['forward_packets'].append(packet)
                    flow['forward_lengths'].append(packet_length)
                    flow['forward_timestamps'].append(timestamp)
                    flow['fwd_header_length'] += header_length
                else:
                    flow['backward_packets'].append(packet)
                    flow['backward_lengths'].append(packet_length)
                    flow['backward_timestamps'].append(timestamp)
                    flow['bwd_header_length'] += header_length
                    if flow['init_win_bytes_backward'] == 0:
                        flow['init_win_bytes_backward'] = window_size

                if protocol == 'TCP':
                    if flags & 0x02:  # SYN
                        flow['flags']['SYN'] += 1
                    if flags & 0x01:  # FIN
                        flow['flags']['FIN'] += 1
                    if flags & 0x04:  # RST
                        flow['flags']['RST'] += 1
                    if flags & 0x08:  # PSH
                        flow['flags']['PSH'] += 1
                    if flags & 0x10:  # ACK
                        flow['flags']['ACK'] += 1
                    if flags & 0x20:  # URG
                        flow['flags']['URG'] += 1
                    if flags & 0x40:  # ECE
                        flow['flags']['ECE'] += 1
                    if flags & 0x80:  # CWR
                        flow['flags']['CWE'] += 1

                if len(flows) >= 100:
                    save_flows_to_csv(flows, output_file, columns)
                    flows.clear()
                    logging.info(f"Saved flows to {output_file}")

        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    logging.info(f"Starting capture on interface: {interface}")
    try:
        sniff(iface=interface, prn=packet_callback, store=0, 
              stop_filter=lambda x: stop_event.is_set())
    except Exception as e:
        logging.error(f"Error during capture: {str(e)}")
    finally:
        if flows:
            save_flows_to_csv(flows, output_file, columns)
            logging.info(f"Saved final flows to {output_file}")

if __name__ == "__main__":
    import threading
    
    logging.basicConfig(level=logging.INFO)
    interface = "Wi-Fi"  # Change this to match your interface
    output_file = "captured_traffic.csv"
    stop_event = threading.Event()
    
    try:
        capture_traffic(interface, output_file, stop_event)
    except KeyboardInterrupt:
        print("\nStopping capture...")
        stop_event.set()