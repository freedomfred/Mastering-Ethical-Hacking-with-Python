
import threading
import socket
import socketserver
import dnslib
import base64
from hashlib import md5
import argparse,sys,time, os

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


class BaseRequestHandler(socketserver.BaseRequestHandler):
    fIP = {}

    D = DomainName('0h0.us.')
    IP = '18.219.234.8'
    TTL = 60 * 5

    soa_record = dnslib.SOA(
        mname=D.ns1,  # primary name server
        rname=D.andrei,  # email of the domain administrator
        times=(
            201307231,  # serial number
            60 * 60 * 1,  # refresh
            60 * 60 * 3,  # retry
            60 * 60 * 24,  # expire
            60 * 60 * 1,  # minimum
        )
    )
    ns_records = [dnslib.NS(D.ns1), dnslib.NS(D.ns2)]
    records = {
        D: [dnslib.A(IP), dnslib.AAAA((0,) * 16), dnslib.MX(D.mail), soa_record] + ns_records,
        D.ns1: [dnslib.A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
        D.ns2: [dnslib.A(IP)],
        D.mail: [dnslib.A(IP)],
        D.andrei: [dnslib.CNAME(D)],
    }
    def progressBar(self,c, tot, status):
        bar = 40
        filled = int(round(bar * (tot-c) / float(tot)))

        pct = round(100.0 * (tot-c) / float(tot), 1)
        barstr =  '=' * filled + '-' * (bar - filled)

        sys.stdout.write('[%s] %s%s ...%s\r' % (barstr, pct, '%', status))
        sys.stdout.flush()

    def processRequest(self, questions):
        for question in questions:
            if (question.qtype == dnslib.QTYPE.A):
                reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

                for rdata in ns_records:
                    reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

                reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

            elif (question.qtype == dnslib.QTYPE.TXT):
                #only process TXT record requests
                content = str(question.qname)[:-1]

                sIP = self.client_address[0]

                if sIP in self.fIP:
                    self.fIP[sIP][3] += content
                    self.fIP[sIP][1] -= len(content)
                    #print("Left: "+str(self.fIP[sIP][1]))
                    self.progressBar(self.fIP[sIP][1],self.fIP[sIP][4],"Receiving '"+self.fIP[sIP][0]+"' from "+sIP)
                    if (self.fIP[sIP][1] == 0):
                        #we have received the entire file. Time to write it.
                        content_decoded = base64.standard_b64decode(self.fIP[sIP][3])
                        with open(self.fIP[sIP][0],'wb') as newfile:
                            newfile.write(content_decoded)

                        hashedWord = md5(content_decoded).hexdigest()
                        if (self.fIP[sIP][2] == hashedWord):
                            print("\nFile successfully received")
                        else:
                            print("\nFile received but failed hash:")

                        del self.fIP[sIP]
                        
                
                    
                else:
                    # new connection. we expect a file name
                    parts = content.split("|")
                    if (len(parts)==3):
                        #we have valid request
                        print("new file upload: ",content)
                        self.fIP[sIP]= [os.path.basename(parts[0]),int(parts[1]),parts[2],"",int(parts[1])]


class TCPDNSHandler(BaseRequestHandler):
    
    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(8192).strip()
        #print("Request from {}".format(self.client_address[0]))
        

        req = dnslib.DNSRecord.parse(self.data[2:])
        print("TCP: ",req)
        
        self.processRequest(req.questions)

        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())

class UDPDNSHandler(BaseRequestHandler):
    
    def handle(self):
        # self.request is the TCP socket connected to the client
        data = self.request[0].strip()
        #print("Request from {}".format(self.client_address[0]))
        

        req = dnslib.DNSRecord.parse(data)
        print("UDP: ",req)
        
        self.processRequest(req.questions)

        # just send back the same data, but upper-cased
        self.request[1].sendto(data.upper(), self.client_address)

if __name__ == "__main__":
    HOST, PORT = socket.gethostname(), 53

    # Create the server, binding to localhost on port 9999
    # serverTCP= socketserver.TCPServer((HOST, PORT), TCPDNSHandler)
    # serverUDP= socketserver.UDPServer(("127.0.0.1", PORT), UDPDNSHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    servers = []
    servers.append(socketserver.ThreadingUDPServer((HOST, PORT), UDPDNSHandler))
    servers.append(socketserver.ThreadingTCPServer((HOST, PORT),TCPDNSHandler))
    
    #serverTCP.serve_forever()
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()
