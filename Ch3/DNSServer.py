
import threading
import socket
import socketserver
import dnslib



class TCPDNSHandler(socketserver.BaseRequestHandler):


    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(8192).strip()
        print("{} wrote:".format(self.client_address[0]))
        

        req = dnslib.DNSRecord.parse(self.data[2:])
        print(req)

        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())

if __name__ == "__main__":
    HOST, PORT = socket.gethostname(), 53

    # Create the server, binding to localhost on port 9999
    server = socketserver.TCPServer((HOST, PORT), TCPDNSHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()

