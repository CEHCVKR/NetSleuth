
# NetSleuth - Network Scanner and Port Monitor

> **NetSleuth**: Intelligent Network Scanner with MAC Vendor Lookup and Port Monitoring  
> **Author**: CHINNAPAREDDY VENKATA KARTHIK REDDY  
> **For Educational and Ethical Research Purposes Only**

NetSleuth is a Python-based network scanning and port monitoring tool designed to detect active devices on a local network, identify their vendors via MAC address, and scan common ports concurrently. It continuously monitors the network and logs new devices and port status changes.

---

## Features

- Automatic local subnet detection using `netifaces`
- ARP-based network scanning for active hosts
- MAC address vendor lookup using `manuf`
- Concurrent port scanning on common ports
- Logging with rotating file handler
- Detects new devices and changes in open ports in real-time
- Written in Python with minimal external dependencies

---

## Requirements

- Python 3.11 or above
- Dependencies (provided in `requirements.txt`):
  - scapy
  - manuf
  - netifaces (included as `netifaces-0.11.0-cp311-cp311-win_amd64.whl` in repo)

---

## Installation

1. Install Python 3.11+ from [python.org](https://www.python.org/downloads/).

2. Install dependencies using pip:

   ```bash
   pip install -r requirements.txt
   ```

3. Install `netifaces` wheel file included in this repository:

   ```bash
   pip install netifaces-0.11.0-cp311-cp311-win_amd64.whl
   ```

---

## Usage

Run the main script:

```bash
python main.py
```

The scanner will start detecting devices and open ports on your local subnet and log the results to `scanner.log`. To stop the scanner, press `Ctrl+C`.

---

## Logging

Logs are saved to `scanner.log` with rotation:

- Max size: 50KB
- 3 backup log files

---

## Contributing

Feel free to fork the repository, make changes, and submit pull requests. For issues, please open an issue ticket.

---

## 📬 Contact

- 📧 Email: [22bq1a4720@gmail.com](mailto:22bq1a4720@gmail.com)
- 🌐 GitHub: [@CEHCVKR](https://github.com/CEHCVKR)
- 💼 LinkedIn: [@cvkr](https://linkedin.com/in/cvkr)

---
