import streamlit as st
import pandas as pd
import time
import os
import psutil
from scripts.capture_traffic import capture_traffic
from scripts.analyze_packets import analyze_packets
import threading
import logging
from streamlit.runtime.scriptrunner import add_script_run_ctx

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

class CaptureManager:
    def __init__(self):
        self.is_running = False
        self.capture_thread = None
        self.stop_event = threading.Event()

    def start_capture(self, interface, output_file):
        """Start packet capture"""
        if self.is_running:
            st.warning("Capture is already running!")
            return

        self.is_running = True
        self.stop_event.clear()
        
        def run_capture():
            try:
                capture_traffic(interface, output_file, self.stop_event)
            except Exception as e:
                logging.error(f"Error in capture thread: {str(e)}")
            finally:
                self.is_running = False

        # Create and start capture thread
        self.capture_thread = threading.Thread(
            target=run_capture,
            daemon=True
        )
        add_script_run_ctx(self.capture_thread)
        self.capture_thread.start()
        logging.info(f"Capture started on interface: {interface}")
        st.success(f"Capture started on interface: {interface}")

    def stop_capture(self):
        """Stop packet capture"""
        if self.is_running:
            self.stop_event.set()
            if self.capture_thread:
                self.capture_thread.join(timeout=5)
            self.is_running = False
            logging.info("Capture stopped!")
            st.success("Capture stopped!")
        else:
            st.warning("No capture is currently running.")

def load_alerts(file_path):
    """Load alerts from a CSV file"""
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
        if file_size < 1024 * 1024:  # Less than 1 MB
            st.write(f"Current capture file size: {file_size/1024:.2f} KB")
        else:
            st.write(f"Current capture file size: {file_size/(1024 * 1024):.2f} MB")
    
    # Start/Stop buttons
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button('Start Capture'):
            st.session_state.capture_manager.start_capture(selected_interface, output_file)
    
    with col2:
        if st.button('Stop Capture'):
            st.session_state.capture_manager.stop_capture()
    
    # Status indicator
    st.markdown("---")
    status_placeholder = st.empty()
    status_placeholder.write("Status: " + 
        ("📊 Capturing..." if st.session_state.capture_manager.is_running 
         else "⏹️ Stopped"))
    
    # Analysis section
    if st.button('Analyze Captured Traffic'):
        if os.path.exists(output_file):
            with st.spinner('Analyzing traffic...'):
                try:
                    success = analyze_packets(output_file, model_file, alerts_file)
                    if success:
                        st.success('Analysis complete!')
                    else:
                        st.error('Analysis failed. Check the logs for details.')
                except Exception as e:
                    st.error(f"Error during analysis: {str(e)}")
        else:
            st.warning('No captured traffic data found.')
    
    # Display results
    st.markdown("---")
    st.subheader("Latest Alerts")
    
    if st.button('Refresh Alerts'):
        st.rerun()
    
    alerts_df = load_alerts(alerts_file)
    if not alerts_df.empty:
        # Add color coding based on prediction
        def color_code(row):
            return ['background-color: #ff000033' if row['prediction'] == 1 
                   else 'background-color: #00ff0033' for _ in row]
        
        styled_df = alerts_df.style.apply(color_code, axis=1)
        st.dataframe(styled_df)
        
        # Display statistics
        st.subheader("Statistics")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Alerts", len(alerts_df))
        with col2:
            if 'prediction' in alerts_df.columns:
                threat_ratio = (alerts_df['prediction'] == 1).mean()
                st.metric("Threat Ratio", f"{threat_ratio:.2%}")
        
        # Add threat distribution visualization
        if 'prediction' in alerts_df.columns:
            st.subheader("Threat Distribution")
            threat_counts = alerts_df['prediction'].value_counts()
            st.bar_chart(threat_counts)
    else:
        st.info("No alerts to display")

    # Add auto-refresh functionality
    if st.session_state.capture_manager.is_running:
        time.sleep(1)  # Add a small delay
        st.rerun()

if __name__ == "__main__":
    main()