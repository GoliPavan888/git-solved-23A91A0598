# System Architecture

---

## Overview
DevOps Simulator uses a modular microservices architecture supporting high availability, multi-environment scaling, and AI-powered features for advanced use-cases.

---

## Architecture Versions

### v1.0 (Production/Development)

**Production:**  
- Node.js + Express application server (port 8080)  
- PostgreSQL 14 (master-slave), Prometheus/Grafana monitoring  
- Rolling updates, SSL/TLS, auto-scaling  
- Automated backups, load balancer, monitoring alerts  

**Development:**  
- Node.js + Express app (port 3000)  
- PostgreSQL development instance, Docker Compose  
- Debug mode, hot reload, mock APIs, CORS enabled

---

### v3.0 (Experimental/AI)

**AI/Experimental Build:**  
- **Server:** Node.js + Express + TensorFlow.js (main 9000, metrics 9001, AI API 9002)  
- **Scaling:** ML-powered auto-scaling, event-driven with Apache Kafka  
- **Database:** PostgreSQL cluster (5 nodes, distributed), Redis cache with ML optimization  
- **AI Pipeline:** TensorFlow, PyTorch, Scikit-learn  
    - Models: LSTM anomaly detection, XGBoost load prediction, RL auto-scaling  
    - Online, real-time inference under 50ms  
- **Orchestration:** Kubernetes, CRDs, GeoDNS, multi-cloud (AWS, Azure, GCP, DigitalOcean), cross-cloud failover  
- **Monitoring:** Prometheus + Thanos, ELK + AI log analysis  
- **Security:** Zero trust, AES-256 encryption, audit logging

---

## Component Map

- **Application Servers:** Horizontal scaling, ports assigned per environment  
- **Database Layer:** Master-slave/prod, local/dev, distributed+replication/experimental  
- **AI/ML Pipeline (Experimental):** Real-time and continuous training, predictive scaling  
- **Monitoring:** Production: Prometheus/Grafana, Dev: Console/verbose, Experimental: Extended+AI  
- **Orchestration/Security:** Automated rollback, global failover, encryption, audit trail

---

## Update and merge policy

**Always update within the matching version section and do not copy entire blocks.**  
For new features, expand only in the appropriate version subsection above. This standard ensures future merges and branches do not conflict.
