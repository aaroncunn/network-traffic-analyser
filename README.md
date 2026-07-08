# Network Traffic Analyser

A network traffic anaylser project that reads PCAP files and produces a basic traffic summary. 

## Features 

- Reads packet capture files ('.pcap')
- Counts the total amount of packets 
- Summaries the protocol such as UDP, TCP, ICMP 
- Shows top source and top destination IPS and ports
- Displays sample packet summaries 

## Structure 
- `main.py` - main analysis script
- `requirements.txt` - project dependencies
- `sample.pcap` - sample packet capture file
- `README.md` - project documentation

## Purpose
The main purpose of this project was to improve my practical skills of packet analysis, improve my python skills, and increase my portfolio of my cybersecurity projects. 

## Future Improvements

- Add better protocol detection
- Export results to a text or CSV report
- Add filtering by IP address or protocol
- Analyse DNS traffic in more detail
- Build a simple web interface