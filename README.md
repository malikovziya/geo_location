# IP Geolocation Client

## Overview
This Python-based GUI application allows users to connect to a server and search for IP geolocation information. The user can configure the server connection, search for an IP address or domain name, and view detailed geolocation information retrieved from the server. The results are displayed in a scrollable text area, with links to Google Maps for the corresponding IP.

## Features
- **Server Connection Setup**: Configure and connect to the server using the IP address and port.
- **IP Search**: Search for geolocation data by entering an IP address or domain name.
- **Geolocation Information Display**: Displays detailed geolocation information, including country, region, city, and more.
- **Google Maps Link**: Provides a clickable Google Maps link for the searched IP address.
- **Status Updates**: Displays real-time connection and search statuses.

## Prerequisites
- Python 3.x
- Required libraries: `tkinter`, `socket`, `pickle`, `ipaddress`, `threading`, `webbrowser`

To install the required libraries, you can use `pip`:
```bash
pip install tkinter

## Usage

1. Open a terminal/command prompt, navigate to the project directory, and run the following command to start the server:
python gui_client.py
2. In another terminal/host, run one of two client files according to your desire, enter valid information to see results.

