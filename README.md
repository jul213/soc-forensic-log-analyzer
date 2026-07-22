# 🛡️ SOC Forensic Log Analyzer & Threat Detector

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Cybersecurity](https://img.shReviields.io/badge/Cybersecurity-Red-EE3124?style=for-the-badge)

## 📌 Descripción del Proyecto

Herramienta de automatización forense desarrollada en **Python** para análisis de logs del sistema (`/var/log/auth.log`) y detección proactiva de ataques de fuerza bruta (Brute-Force Attack Detection).

Permite procesar archivos de registro, correlacionar eventos por dirección IP, clasificar el nivel de severidad del incidente y estructurar las evidencias en una **base de datos relacional SQL** e informes JSON listos para integración con sistemas SIEM.

---

## ⚙️ Arquitectura de la Solución

```text
[ Linux Auth Logs ] ---> ( Python Parser / RegEx ) 
                                  |
            +---------------------+---------------------+
            |                                           |
    [ Base de Datos SQL ]                      [ Reporte JSON SIEM ]
  (Tabla: forensic_incidents)                 (forensic_report.json)