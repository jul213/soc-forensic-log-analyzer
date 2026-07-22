import re
import sqlite3
import json
from datetime import datetime
import os

# Configuración de umbrales forenses
FAILED_ATTEMPTS_THRESHOLD = 5
LOG_FILE_PATH = "data/sample_auth.log"
DB_FILE_PATH = "forensic_audit.db"

class ForensicLogAnalyzer:
    def __init__(self, log_path, db_path):
        self.log_path = log_path
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Crea la tabla de incidentes forenses en SQL si no existe."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS forensic_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                failed_count INTEGER NOT NULL,
                severity TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def parse_logs(self):
        """Analiza el log buscando patrones de intentos fallidos de login (SSH/Auth)."""
        failed_logins = {}

        if not os.path.exists(self.log_path):
            print(f"[!] Error: El archivo de log '{self.log_path}' no existe.")
            return {}

        # RegEx para capturar IP y Fecha en logs de autenticación estándar
        log_pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Failed password.*from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        )

        with open(self.log_path, 'r') as file:
            for line in file:
                match = log_pattern.search(line)
                if match:
                    ip = match.group('ip')
                    timestamp = match.group('timestamp')

                    if ip not in failed_logins:
                        failed_logins[ip] = {
                            'count': 0,
                            'first_seen': timestamp,
                            'last_seen': timestamp
                        }
                    failed_logins[ip]['count'] += 1
                    failed_logins[ip]['last_seen'] = timestamp

        return failed_logins

    def save_incidents_to_sql(self, incidents):
        """Registra las amenazas detectadas en la base de datos SQL."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for ip, details in incidents.items():
            if details['count'] >= FAILED_ATTEMPTS_THRESHOLD:
                # Asignación de Severidad Forense
                severity = "HIGH" if details['count'] > 15 else "MEDIUM"
                
                cursor.execute('''
                    INSERT INTO forensic_incidents (ip_address, failed_count, severity, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip, details['count'], severity, details['first_seen'], details['last_seen']))

        conn.commit()
        conn.close()
        print("[+] Análisis forense completado. Resultados guardados en SQL.")

    def generate_json_report(self, incidents):
        """Genera un informe en JSON para integración con SIEM o dashboards."""
        report_data = {
            "audit_timestamp": datetime.now().isoformat(),
            "threats_detected": [
                {
                    "ip": ip,
                    "attempts": data["count"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"]
                }
                for ip, data in incidents.items() if data["count"] >= FAILED_ATTEMPTS_THRESHOLD
            ]
        }
        
        with open("forensic_report.json", "w") as json_file:
            json.dump(report_data, json_file, indent=4)
        print("[+] Reporte JSON generado: 'forensic_report.json'.")

if __name__ == "__main__":
    analyzer = ForensicLogAnalyzer(LOG_FILE_PATH, DB_FILE_PATH)
    detected_threats = analyzer.parse_logs()
    
    if detected_threats:
        analyzer.save_incidents_to_sql(detected_threats)
        analyzer.generate_json_report(detected_threats)