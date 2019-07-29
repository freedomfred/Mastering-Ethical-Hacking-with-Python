
import threading
import socket
import socketserver
import dnslib
import base64
from hashlib import md5
import argparse,sys,time


class TCPDNSHandler(socketserver.BaseRequestHandler):
    filesInProgress = {}

    def progressBar(self,c, tot, status):
        bar = 40
        filled = int(round(bar * c / float(tot)))

        pct = round(100.0 * c / float(tot), 1)
        barstr = '=' * filled + '-' * (bar - filled)

        sys.stdout.write('[%s] %s%s ...%s\r' % (barstr, pct, '%', status))
        sys.stdout.flush()
        
    def processRequest(self, questions):
        for question in questions:
            if (question.qtype == dnslib.QTYPE.TXT):
                #only process TXT record requests
                content = str(question.qname)[:-1]

                if self.client_address[0] in self.filesInProgress:
                    self.filesInProgress[self.client_address[0]][3] += content
                    self.filesInProgress[self.client_address[0]][1] -= len(content)
                    #print("Left: "+str(self.filesInProgress[self.client_address[0]][1]))
                    self.progressBar(self.filesInProgress[self.client_address[0]][1],self.filesInProgress[self.client_address[0]][4],"Receiving '"+self.filesInProgress[self.client_address[0]][0]+"' from "+self.client_address[0])
                    if (self.filesInProgress[self.client_address[0]][1] == 0):
                        #we have received the entire file. Time to write it.
                        content_decoded = base64.standard_b64decode(self.filesInProgress[self.client_address[0]][3])
                        with open(self.filesInProgress[self.client_address[0]][0],'wb') as newfile:
                            newfile.write(content_decoded)

                        hashedWord = md5(content_decoded).hexdigest()
                        if (self.filesInProgress[self.client_address[0]][2] == hashedWord):
                            print("File successfully received")
                        else:
                            print("File received but failed hash:")

                        del self.filesInProgress[self.client_address[0]]
                        
                
                    
                else:
                    # new connection. we expect a file name
                    print("new file upload: ",content)
                    parts = content.split("|")
                    self.filesInProgress[self.client_address[0]]= [parts[0],int(parts[1]),parts[2],"",int(parts[1])]


    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(8192).strip()
        #print("Request from {}".format(self.client_address[0]))
        

        req = dnslib.DNSRecord.parse(self.data[2:])
        #print(req.questions)
        
        self.processRequest(req.questions)

        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())

if __name__ == "__main__":
    HOST, PORT = socket.gethostname(), 53

    # Create the server, binding to localhost on port 9999
    server = socketserver.TCPServer((HOST, PORT), TCPDNSHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()

