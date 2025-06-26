# 🔐 Real-Time IoT Botnet Detection System 

A real-time botnet detection system for IoT networks, developed as part of our 2CS Multidisciplinary Project at **ESI Sidi Bel Abbès**. This full-stack solution combines **AI**, **network traffic analysis**, and a **modern web dashboard** to detect botnet attacks in real time and visualize key metrics live.


---

## 🧠 What It Does

- 📡 Captures live IoT network traffic
- 🧠 Analyzes traffic using an **LSTM model** trained on the **CICIoT2023 dataset**
- 📨 Sends predictions to a **Django** backend via REST APIs
- 📊 Visualizes alerts, logs, and performance in real time using a **React.js dashboard**

---

## ⚙️ System Architecture

1. **Traffic Simulation:** Dockerized containers simulate IoT devices and attack traffic  
2. **Detection Engine:** A Python-based service captures flows, processes them using FlowMeter, and classifies them using an LSTM model  
3. **Backend API:** A Django REST API receives predictions, stores results, and manages device metadata  
4. **Dashboard:** A live React.js interface shows real-time logs, alerts, device health, and analytics  
5. **WebSockets + Redis:** Push live data updates to the frontend without polling

---

## 🧩 Tech Stack

| Component            | Technology                          |
|----------------------|-------------------------------------|
| Detection Engine     | Python, LSTM, CICIoT2023, FlowMeter |
| Backend              | Django, PostgreSQL, REST API        |
| Frontend             | React.js, Chart.js, WebSocket       |
| Live Messaging       | Redis, WebSocket                    |
| Deployment & DevOps  | Docker, Wireshark                   |

---

## 🧪 Dataset

- **CICIoT2023** from the Canadian Institute for Cybersecurity
- Preprocessed with **FlowMeter** to generate time-series features
- Contains both normal and attack traffic scenarios across various IoT devices

---

## 🖥️ Dashboard Features

- 📶 Real-time traffic capture and classification  
- 🚨 Live alert feed for detected attacks  
- 📈 Charts showing device activity and time-based patterns  
- 🔁 WebSocket-powered UI updates  
- 🌗 Dark/Light mode support

---

## 💡 Why LSTM?

Unlike traditional models, LSTM networks learn patterns **over time**. This memory allows the system to better detect stealthy botnet behaviors that evolve across multiple packets, rather than in isolated flows.

---

## 📂 Repository Structure

```bash
botnet-attack-detection/
│
├── detection_engine/         # LSTM model + flow processing
├── backend/                  # Django REST API & PostgreSQL DB
├── dashboard/                # React.js frontend with WebSocket
├── docker/                   # Simulation scripts & containers
└── README.md                 # You're here!
````

---

## 🚀 Getting Started

### Prerequisites

* Python 3.9+
* Node.js + npm
* Docker + Docker Compose
* PostgreSQL
* Redis
* Flutter (for optional mobile module)

### Setup (Quick Preview)

```bash
# Clone the project
git clone https://github.com/YacineHekkas/botnet-attack-detection.git
cd botnet-attack-detection

# Follow setup instructions in backend/ and dashboard/ folders
# Run docker containers and launch app
```

(Detailed installation instructions coming soon.)

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 📬 Contact

For more info or collaboration:

* GitHub: [@YacineHekkas](https://github.com/YacineHekkas)
* Email: [yac.hakkas@gmail.com](mailto:yac.hakkas@gmail.com)
