import streamlit as st
import pandas as pd
import time
import os
import psutil
from scripts.analyze_packets import analyze_packets
import subprocess
import threading
import winreg
from streamlit.runtime.scriptrunner import add_script_run_ctx

def get_network_interfaces():
    """Get list of available network interfaces"""
    try:
        # Get all network interfaces
        interfaces = psutil.net_if_addrs()
         
        # Filter and format interface names
        interface_names = []
        for interface in interfaces.keys():
            # Skip loopback interface
            if interface != 'lo' and interface != 'Loopback Pseudo-Interface 1':
                interface_names.append(interface)
             
        return interface_names
    except Exception as e:
        st.error(f"Error getting network interfaces: {str(e)}")
        return []

def find_wireshark_path():
    """Find Wireshark installation path from Windows Registry"""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wireshark")
        install_path = winreg.QueryValueEx(key, "InstallPath")[0]
        winreg.CloseKey(key)
        return install_path
    except:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Wireshark")
            install_path = winreg.QueryValueEx(key, "InstallPath")[0]
            winreg.CloseKey(key)
            return install_path
        except:
            common_paths = [
                r"C:\Program Files\Wireshark",
                r"C:\Program Files (x86)\Wireshark",
            ]
            for path in common_paths:
                if os.path.exists(path):
                    return path
    return None

class CaptureManager:
    def __init__(self):
        self.process = None
        self.is_running = False
        self.wireshark_path = find_wireshark_path()
        if self.wireshark_path:
            self.tshark_path = os.path.join(self.wireshark_path, "tshark.exe")
        else:
            self.tshark_path = None

    def start_capture(self, interface, output_file):
        if not self.tshark_path or not os.path.exists(self.tshark_path):
            st.error("Could not find tshark.exe. Please verify Wireshark installation.")
            return

        # Modified tshark command with more detailed output
        command = [
            self.tshark_path,
            '-i', interface,
            '-T', 'fields',
            '-E', 'header=y',
            '-E', 'separator=,',
            '-E', 'quote=d',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'ip.proto',
            '-e', 'frame.len',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'ip.len',
            '-f', 'ip'  # Filter for IP packets only
        ]
         
        try:
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Start capture process with pipe
            st.write(f"Starting capture on interface: {interface}")
            st.write(f"Debug: Running command: {' '.join(command)}")
            
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            self.is_running = True
            
            # Open output file for writing
            with open(output_file, 'w', buffering=1) as f:
                # Write header
                header = "timestamp,source_ip,dest_ip,protocol,frame_length,src_port,dst_port,udp_src_port,udp_dst_port,ip_length\n"
                f.write(header)
                
                # Process output line by line
                while self.is_running:
                    line = self.process.stdout.readline()
                    if line:
                        st.write(f"Debug: Captured packet: {line.strip()}")  # Debug output
                        f.write(line)
                        f.flush()  # Ensure data is written to disk
                    
                    # Check for process termination
                    if self.process.poll() is not None:
                        error = self.process.stderr.read()
                        if error:
                            st.error(f"Capture error: {error}")
                        break
                    
                    # Small delay to prevent high CPU usage
                    time.sleep(0.1)
                    
        except Exception as e:
            st.error(f"Capture error: {str(e)}")
        finally:
            self.stop_capture()

    def stop_capture(self):
        self.is_running = False
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None

def load_alerts(file_path):
    try:
        if os.path.exists(file_path):
            return pd.read_csv(file_path)
        return pd.DataFrame()
    except Exception as e:
        st.error(f"Error loading alerts: {str(e)}")
        return pd.DataFrame()

def main():
    st.title('Network Threat Detection Dashboard')
    
    # Initialize capture manager
    if 'capture_manager' not in st.session_state:
        st.session_state.capture_manager = CaptureManager()
    
    # Display Wireshark information
    if st.session_state.capture_manager.wireshark_path:
        st.success(f"Found Wireshark at: {st.session_state.capture_manager.wireshark_path}")
    else:
        st.error("Wireshark installation not found! Please install Wireshark first.")
        st.stop()
    
    # Interface selection
    interfaces = get_network_interfaces()
    if not interfaces:
        st.error("No network interfaces found!")
        st.stop()
        
    selected_interface = st.selectbox('Select Network Interface', interfaces)
    
    # File paths
    output_file = os.path.join('data', 'captured_traffic.csv')
    alerts_file = os.path.join('data', 'alerts.csv')
    model_file = os.path.join('models', 'random_forest_model.pkl')
    
    # Ensure directories exist
    os.makedirs('data', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    # Display current capture file size
    if os.path.exists(output_file):
        file_size = os.path.getsize(output_file)
        st.write(f"Current capture file size: {file_size/1024:.2f} KB")
    
    # Start/Stop buttons
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button('Start Capture'):
            if not st.session_state.capture_manager.is_running:
                capture_thread = threading.Thread(
                    target=st.session_state.capture_manager.start_capture,
                    args=(selected_interface, output_file)
                )
                add_script_run_ctx(capture_thread)
                capture_thread.start()
                st.success("Capture started!")
    
    with col2:
        if st.button('Stop Capture'):
            if st.session_state.capture_manager.is_running:
                st.session_state.capture_manager.stop_capture()
                st.success("Capture stopped!")
    
    # Status indicator
    st.markdown("---")
    st.write("Status: " + 
             ("Capturing" if st.session_state.capture_manager.is_running 
              else "Stopped"))
    
    # Analysis section
    if st.button('Analyze Captured Traffic'):
        if os.path.exists(output_file):
            with st.spinner('Analyzing traffic...'):
                analyze_packets(output_file, model_file, alerts_file)
            st.success('Analysis complete!')
        else:
            st.warning('No captured traffic data found.')
    
    # Display results
    st.markdown("---")
    st.subheader("Latest Alerts")
    
    if st.button('Refresh Alerts'):
        st.rerun()  # Changed from st.experimental_rerun() to st.rerun()
    
    alerts_df = load_alerts(alerts_file)
    if not alerts_df.empty:
        st.dataframe(alerts_df)
        
        st.subheader("Statistics")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Alerts", len(alerts_df))
        with col2:
            if 'prediction' in alerts_df.columns:
                st.metric("Threat Ratio", 
                         f"{(alerts_df['prediction'] == 1).mean():.2%}")
    else:
        st.info("No alerts to display")

if __name__ == "__main__":
    main()