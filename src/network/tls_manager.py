import socket
import ssl

# Class for tls manager
class TlsManager:
    def __init__(self, cert_path=None, key_path=None, ca_path=None):
        self.cert_path = cert_path  # Path to your .pem certificate
        self.key_path = key_path    # Path to your .pem private key
        self.ca_path = ca_path      # Path to the Certificate Authority file for verification

    # Method to create server context
    def create_server_context(self):
        # Creates a basic context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH) # Client_auth makes it expect a client
        # Loads the certificate and private key chain
        context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        # Returns the configured context
        return context
    
    # Creates a client context
    def create_client_context(self, verify=True):
        # Creates a basic context for server authentication
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH) # Server_auth makes it expect a server
        
        # Checks if verification should be bypassed
        if not verify:
            # Disables hostname checking (useful for local testing)
            context.check_hostname = False
            # Disables certificate validation entirely
            context.verify_mode = ssl.CERT_NONE
        # Checks if a CA file is provided for verification
        elif self.ca_path:
            # Loads the trusted CA file to verify the server's certificate
            context.load_verify_locations(cafile=self.ca_path)
            
        # Returns the client context
        return context
    
    # Runs the a secure server
    def run_secure_server(self, host='127.0.0.1', port=4433):
        """Starts a basic encrypted listener"""
        # Gets the server context configuration
        context = self.create_server_context()
        
        # Create a standard TCP socket using IPv4 and Streaming protocols
        with socket.socket(socket.AF_INET, socket.socket.SOCK_STREAM, 0) as sock:
            # Binds the socket to the specified host and port
            sock.bind((host, port))
            # Starts listening for incoming connections (queue of 5)
            sock.listen(5)
            # Notifies the user the server is active
            print(f"[*] Secure server listening on {host}:{port}")
            
            # Infinite loop to keep server alive after a connection
            while True:
                # Accepts a new raw socket connection
                newsock, addr = sock.accept()
                try:
                    # Wrap the raw socket with TLS encryption
                    with context.wrap_socket(newsock, server_side=True) as ssock:
                        # Prints the address of the connected client
                        print(f"[+] Encrypted connection from {addr}")
                        # Receives up to 1024 bytes of encrypted data
                        data = ssock.recv(1024)
                        # Decodes and prints the received data
                        print(f"Received: {data.decode(errors='replace')}")
                        # Sends an encrypted response back to the client
                        ssock.sendall(b"Connection Secure. Goodbye.")
                # Catch SSL-specific errors (like handshake failures)
                except ssl.SSLError as e:
                    print(f"[!] SSL Error: {e}")

    # Runs a secure client
    def run_secure_client(self, host='127.0.0.1', port=4433, message="Hello Server"):
        """Connects to a TLS server as a client"""
        # Gets the client context (set to False for CTF/self-signed testing)
        context = self.create_client_context(verify=False) 
        
        # Creates a connection to the target host and port
        with socket.create_connection((host, port)) as sock:
            # Wraps the connection in a TLS layer
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Prints the TLS version used (e.g., TLSv1.3)
                print(f"[+] Connected via {ssock.version()}")
                # Sends the encrypted message to the server
                ssock.sendall(message.encode())
                # Receives the encrypted response from the server
                response = ssock.recv(1024)
                # Decodes and prints the server's reply
                print(f"Server response: {response.decode()}")