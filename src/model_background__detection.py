import time
import numpy as np
import pandas as pd
import joblib
from tensorflow.keras.models import load_model
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
from pathlib import Path

# Configuration
FEATURES_CSV = Path.home() / 'OneDrive' / 'Desktop' /'botnet_attack'/ 'network_traffic.csv'
PREDICTIONS_CSV = FEATURES_CSV.parent / 'network_predictions.csv'
IP_MAP_CSV = FEATURES_CSV.parent / 'ip_mappings.csv'

FEATURE_COLUMNS = [
    'flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate',
    'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'psh_flag_number', 'ack_flag_number', 'ece_flag_number', 'cwr_flag_number',
    'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count', 'HTTP',
    'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
    'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size',
    'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight'
]

class TrafficAnalyzer:
    def __init__(self):
        self.model = load_model('model.h5')
        self.scaler = joblib.load('scaler.pkl')
        self.label_encoder = joblib.load('encoder.pkl')
        self.last_processed = 0
        logging.info("ML components loaded successfully")

    def process_features(self, features):
        try:
            scaled = self.scaler.transform([features])
            return scaled.reshape(1, -1, 1)
        except Exception as e:
            logging.error(f"Feature scaling error: {e}")
            return None

    def predict_traffic(self, features):
        try:
            processed = self.process_features(features)
            if processed is None:
                return "ERROR", 0.0
            prediction = self.model.predict(processed, verbose=0)
            label_idx = np.argmax(prediction)
            return self.label_encoder.inverse_transform([label_idx])[0], float(np.max(prediction))
        except Exception as e:
            logging.error(f"Prediction failed: {e}")
            return "ERROR", 0.0

class CsvMonitor(FileSystemEventHandler):
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.processed_rows = 0

    def on_modified(self, event):
        if not event.src_path.endswith(FEATURES_CSV.name):
            return

        try:
            df = pd.read_csv(FEATURES_CSV)
            new_rows = df.iloc[self.processed_rows:]
            
            if new_rows.empty:
                return

            predictions = []
            ip_mappings = []

            for idx, row in new_rows.iterrows():
                try:
                    features = row[FEATURE_COLUMNS].values.astype(float)
                    prediction, confidence = self.analyzer.predict_traffic(features)
                    
                    predictions.append({
                        **row.to_dict(),
                        'prediction': prediction,
                        'confidence': confidence
                    })
                    
                    ip_mappings.append({
                        'destination_ip': row['destination_ip'],
                        'prediction': prediction,
                        'timestamp': pd.Timestamp.now()
                    })

                    if prediction not in ["BenignTraffic", "ERROR"]:
                        self.trigger_alert(row['source_ip'], row['destination_ip'], prediction, confidence)

                except Exception as e:
                    logging.error(f"Row {idx} error: {e}")

            # Append predictions
            if predictions:
                pd.DataFrame(predictions).to_csv(PREDICTIONS_CSV, mode='a', header=False, index=False)
                logging.info(f"Added {len(predictions)} predictions")

            # Append IP mappings in same order
            if ip_mappings:
                pd.DataFrame(ip_mappings).to_csv(IP_MAP_CSV, mode='a', header=False, index=False)
                logging.info(f"Mapped {len(ip_mappings)} IPs")

            self.processed_rows += len(new_rows)

        except Exception as e:
            logging.error(f"CSV processing error: {e}")

    def trigger_alert(self, src, dst, attack, confidence):
        alert_msg = f"""\n
        *******************************************
        SECURITY ALERT: {attack} detected!
        From: {src}
        To: {dst}
        Confidence: {confidence:.2%}
        Timestamp: {pd.Timestamp.now()}
        *******************************************
        """
        logging.warning(alert_msg)
        print(alert_msg)

def initialize_files():
    for path in [PREDICTIONS_CSV, IP_MAP_CSV]:
        if not path.exists():
            pd.DataFrame(columns=(['source_ip', 'destination_ip'] + FEATURE_COLUMNS + ['prediction', 'confidence'] 
                        if path == PREDICTIONS_CSV else ['destination_ip', 'prediction', 'timestamp'])
                       ).to_csv(path, index=False)

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler('traffic_analysis.log'), logging.StreamHandler()]
    )

    initialize_files()
    analyzer = TrafficAnalyzer()
    
    observer = Observer()
    observer.schedule(CsvMonitor(analyzer), path=str(FEATURES_CSV.parent))
    
    try:
        logging.info("Starting monitoring service...")
        observer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping monitoring service...")
    finally:
        observer.stop()
        observer.join()

if __name__ == '__main__':
    main()