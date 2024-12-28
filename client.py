import socket
import pickle
import ipaddress

def connect_to_server(server_ip, server_port):
    """Connects to the server and returns the client socket."""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, server_port))  # connect to the server using provided IP and port
        print(f"Connected to server {server_ip}:{server_port}")
        return client
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None

def is_valid_ip(ip):
    """Check if the given string is a valid IPv4 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_valid_server_ip():
    """Prompt the user for a valid server IP address."""
    while True:
        server_ip = input("Enter the server IP address (or press Enter for localhost): ").strip()
        if not server_ip:
            return "localhost"  # default to localhost
        if server_ip == "localhost":
            return server_ip  # accept localhost
        if is_valid_ip(server_ip):
            # validate if the input is a valid IP address
            return server_ip
        else:
            print("Invalid IP address. Please try again.")

def resolve_domain_to_ip(domain):
    """Resolve a domain name to its corresponding IP address."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def get_valid_ip_to_search():
    """
    Prompt the user for a valid IP address or domain name.
    Allow blank input to fetch the client's public IP.
    """
    while True:
        ip_or_domain = input("Enter IP address or domain (or press Enter for your public IP): ").strip()
        if not ip_or_domain:
            return ""  # blank input signifies the public IP of the client
        if is_valid_ip(ip_or_domain):
            return ip_or_domain  # valid IP address
        else:
            resolved_ip = resolve_domain_to_ip(ip_or_domain)
            if resolved_ip:
                print(f"Domain '{ip_or_domain}' resolved to IP: {resolved_ip}")
                return ip_or_domain  # return the domain name as the input (not the resolved IP)
            else:
                print(f"Invalid domain name or unable to resolve '{ip_or_domain}'. Please try again.")

def get_valid_port():
    """Prompt the user for a valid port number."""
    while True:
        try:
            port = int(input("Enter the server port: "))
            if 1 <= port <= 65535:
                return port
            else:
                print("Port number must be between 1 and 65535.")
        except ValueError:
            print("Invalid input! Please enter a valid integer.")

def get_geolocation(ip_or_domain, client):
    """Request geolocation information from the server."""
    try:
        # send the original input (IP or domain) to the server
        client.send(pickle.dumps(ip_or_domain))

        # receive the response (geolocation info or error)
        response = client.recv(1024)
        geolocation = pickle.loads(response)

        # display the geolocation information
        print("Geolocation Information:")
        if 'error' in geolocation:
            print(f"Error: {geolocation['error']}")
        else:
            # display the input (domain name or IP) and resolved IP separately
            print(f"Input: {geolocation.get('input')}")
            print(f"Resolved IP: {geolocation.get('resolved_ip')}")
            
            # display the rest of the geolocation information
            for key, value in geolocation.items():
                if key in ('input', 'resolved_ip', 'google_maps_link'):  
                    continue
                if isinstance(value, dict):
                    print(f"{key.capitalize()}:")
                    for subkey, subvalue in value.items():
                        print(f"  {subkey.capitalize()}: {subvalue}")
                else:
                    print(f"{key.capitalize()}: {value}")

            # print the Google Maps link
            if 'google_maps_link' in geolocation:
                print(f"Google Maps Link: {geolocation['google_maps_link']}")
    except Exception as e:
        print(f"Error during communication: {e}")
    finally:
        client.close()  # ensure socket is closed after communication

if __name__ == "__main__":
    # ask for the server's IP address and port first
    server_ip = get_valid_server_ip()
    server_port = get_valid_port()
    
    # connect to the server
    client = connect_to_server(server_ip, server_port)

    if client:
        # ask for the IP to get geolocation info for after the connection
        ip = get_valid_ip_to_search()
        get_geolocation(ip, client)
