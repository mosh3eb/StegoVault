"""
Launch script for StegoVault Web Interface
"""

import socket
from web.app import app

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

if __name__ == '__main__':
    default_port = 5000
    fallback_port = 5050
    
    target_port = default_port
    if is_port_in_use(default_port):
        target_port = fallback_port
        print(f"Port {default_port} is busy. Attempting to use port {target_port} instead.")

    print("Starting StegoVault Web Interface...")
    print(f"Open http://localhost:{target_port} in your browser")
    app.run(debug=True, host='0.0.0.0', port=target_port)
