import socket
import requests
import pickle
import threading
import os

def recreate_logs_file():
    file_name = "logs.txt"
    
    # check if file exists
    if os.path.exists(file_name):
        os.remove(file_name)  # delete the file
    
    # create a new file
    with open(file_name, "w") as file:
        file.write("")  # create an empty file

def get_ip_info(ip=None):
    """Fetches geolocation data of the given IP address using ipinfo.io API."""
    try:
        if ip is None:
            ip = requests.get('https://api.ipify.org').text  # fetch public IP if none provided

        url = f"https://ipinfo.io/{ip}/json?token=bed19042a56091"
        response = requests.get(url)
        if response.status_code != 200:
            return {'error': f"Unable to fetch data for IP: {ip}"}

        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error fetching geolocation data: {e}")
        return {'error': str(e)}

def check_port(port):
    if not (1 <= port <= 65535):
        print("Port must be between 1 and 65535.\n")
        return False

    try:
        # try to bind the port to check if it's available
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))  # try binding to the port
            return True
    except OSError:
        print(f"Port {port} is already in use. Please try different port number.\n")
        return False
    
def handle_client(client_socket, address):
    """Handle communication with a single client."""
    try:
        while True:
            # receive the IP or domain name from the client
            data = client_socket.recv(1024)
            if not data:
                break

            input_data = pickle.loads(data)  # get the input sent by the client
            ip = None
            response = {}

            if input_data.strip():  # if input is provided
                # check if input is a domain name
                if not input_data.replace('.', '').isdigit():
                    try:
                        ip = socket.gethostbyname(input_data)
                    except socket.gaierror:
                        response['error'] = f"Invalid domain name: {input_data}"
                        ip = None
                else:
                    ip = input_data  # treat input as an IP address

                # validate IP if resolved successfully
                if ip and not (ip.count('.') == 3 and all(part.isdigit() and 0 <= int(part) <= 255 for part in ip.split('.'))):
                    response['error'] = f"Invalid IP address: {ip}"
                    ip = None
            else:
                # no input provided, fetch public IP
                ip = requests.get('https://api.ipify.org').text
                input_data = "Public IP"

            # fetch geolocation information for the resolved IP
            if ip:
                info = get_ip_info(ip)
                if 'error' in info:
                    response['error'] = info['error']
                else:
                    response = {
                        'input': input_data,
                        'resolved_ip': ip,
                        'hostname': info.get('hostname'),
                        'city': info.get('city'),
                        'region': info.get('region'),
                        'country': info.get('country'),
                        'location': info.get('loc'),
                        'timezone': info.get('timezone'),
                        'asn': info.get('asn', {}),
                        'company': info.get('company', {}),
                        'privacy': info.get('privacy', {}),
                        'abuse': info.get('abuse', {}),
                        'domains': info.get('domains', {})
                    }

                    # add Google Maps link if location data is available
                    if 'loc' in info:
                        lat, lon = info['loc'].split(',')
                        response['google_maps_link'] = f"https://www.google.com/maps?q={lat},{lon}"

            # log the request
            log_message = f"Requested: {input_data} ({ip or 'N/A'}) from {address[0]}"
            print(log_message)
            with open("logs.txt", "a") as file:
                file.write(log_message + "\n")

            # send the response to the client
            client_socket.send(pickle.dumps(response))
    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        client_socket.close()

def start_server(host='0.0.0.0'):
    recreate_logs_file()
    # ask for a port number to listen on
    while True:
        try:
            port = int(input("Enter port number to listen on: "))
            is_valid_port = check_port(port)
            if not is_valid_port:
                continue
        except ValueError:
            print("Invalid input! Please enter a number.")
            continue

        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((host, port))
            server.listen(5)
            print(f"\nServer started and running on port {port}: ")
            break
        except:
            print("Port is in use, please try different port number.\n")
        
    while True:
        client_socket, client_address = server.accept()
        print(f"Client connected: {client_address}")
        
        with open("logs.txt", "a") as file:
            file.write(f"Client connected: {client_address}\n")  # Write data to the file

        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    start_server()