import pandas as pd

# Function to generate reports
def generate_report(alerts_file, report_file):
    # Load alerts
    df_alerts = pd.read_csv(alerts_file)
    
    # Generate report (example: count of alerts per source IP)
    report = df_alerts['source_ip'].value_counts().reset_index()
    report.columns = ['source_ip', 'alert_count']
    
    # Save report
    report.to_csv(report_file, index=False)

if __name__ == "__main__":
    alerts_file = '../data/alerts.csv'
    report_file = '../data/report.csv'
    
    generate_report(alerts_file, report_file)