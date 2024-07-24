import nmap
import socket

def scan_hl7(ip_range, port=2575):
    nm = nmap.PortScanner()
    hl7_devices = []

    print(f"Scanning IP range {ip_range} on port {port} for HL7 services...")
    nm.scan(hosts=ip_range, ports=str(port), arguments='-n -sT')

    for host in nm.all_hosts():
        if nm[host].has_tcp(port) and nm[host]['tcp'][port]['state'] == 'open':
            print(f"Found open HL7 port on {host}:{port}")
            if check_hl7_service(host, port):
                hl7_devices.append((host, port))
                print(f"HL7 service confirmed on {host}:{port}")

    return hl7_devices

def check_hl7_service(ip, port):
    hl7_message = "MSH|^~\\&|TEST|TEST|TEST|TEST|20230723120000||ACK^A01|12345|P|2.3.1\r"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            s.sendall(hl7_message.encode())
            data = s.recv(1024)
            if data:
                print(f"Received HL7 response from {ip}:{port}")
                return True
    except (socket.timeout, ConnectionRefusedError, socket.error):
        print(f"Failed to connect or receive HL7 response from {ip}:{port}")
    return False

if __name__ == "__main__":
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    hl7_devices = scan_hl7(ip_range)

    if hl7_devices:
        print("HL7 services found on the following devices:")
        for device in hl7_devices:
            print(f"IP: {device[0]}, Port: {device[1]}")
    else:
        print("No HL7 services found in the specified IP range.")
