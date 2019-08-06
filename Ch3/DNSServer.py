
import threading
import socket
import socketserver
import dnslib
import base64
import binascii
from hashlib import md5
import argparse,sys,time, os

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


class BaseRequestHandler(socketserver.BaseRequestHandler):
    fIP = {}

    D = DomainName('0h0.us.')
    IP = '18.219.234.8'
    TTL = 60 * 1

    soa_record = dnslib.SOA(
        mname=D.ns1,  # primary name server
        times=(
            22118400,  # serial number
            60 * 60 * 1,  # refresh
            60 * 60 * 3,  # retry
            1 * 1 * 1,  # expire
            1 * 1 * 1,  # minimum
        )
    )
    ns_records = [dnslib.NS(D.ns1), dnslib.NS(D.ns2)]
    records = {
        D: [dnslib.A(IP), dnslib.AAAA((0,) * 16), soa_record] + ns_records,
        D.ns1: [dnslib.A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
        D.ns2: [dnslib.A(IP)]
    }
    def progressBar(self,c, tot, status):
        bar = 40
        filled = int(round(bar * (tot-c) / float(tot)))

        pct = round(100.0 * (tot-c) / float(tot), 1)
        barstr =  '=' * filled + '-' * (bar - filled)

        sys.stdout.write('[%s] %s%s ...%s\r' % (barstr, pct, '%', status))
        sys.stdout.flush()

    def processRequest(self, request):
        
        reply = dnslib.DNSRecord(dnslib.DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        
        qname = request.q.qname
        qn = str(qname)
        qtype = request.q.qtype
        qt = dnslib.QTYPE[qtype]
        if qn == self.D or qn.endswith('.' + self.D):
            
            for name, rrs in self.records.items():
                if name == qn:
                    for rdata in rrs:
                        rqt = rdata.__class__.__name__
                        if qt in ['*', rqt]:
                            reply.add_answer(dnslib.RR(rname=qname, rtype=getattr(dnslib.QTYPE, rqt), rclass=1, ttl=self.TTL, rdata=rdata))

            for rdata in self.ns_records:
                reply.add_ar(dnslib.RR(rname=self.D, rtype=dnslib.QTYPE.NS, rclass=1, ttl=self.TTL, rdata=rdata))

            reply.add_auth(dnslib.RR(rname=self.D, rtype=dnslib.QTYPE.SOA, rclass=1, ttl=self.TTL, rdata=self.soa_record))

        for question in request.questions:
            
            if (question.qtype == dnslib.QTYPE.TXT):
                #only process TXT record requests
                content = str(question.qname)[:-1]
                if content.endswith(self.D[:-1]):
                    content = content[:-len(self.D[:-1])-1]
                
                key = content[:4]

                if key in self.fIP:
                    content = str(content[4:])
                    self.fIP[key][3] += content
                    self.fIP[key][1] -= len(content)
                    #print(key, content,len(content),self.fIP[key][1] )
                    
                    #print("Left: "+str(self.fIP[sIP][1]))
                    self.progressBar(self.fIP[key][1],self.fIP[key][4],"Receiving '"+self.fIP[key][0]+"' with index "+key)
                    reply.add_answer(dnslib.RR(rname=qname, rtype=question.qtype, rclass=1, ttl=self.TTL, rdata=dnslib.TXT(content)))
                        #reply.add_answer(dnslib.RR(rname=qname, rtype=question.qtype, rclass=1, ttl=self.TTL, rdata=dnslib.TXT("OK")))
                    if (self.fIP[key][1] == 0):
                        #we have received the entire file. Time to write it.
                        content_decoded = base64.standard_b64decode(self.fIP[key][3])
                        with open(self.fIP[key][0],'wb') as newfile:
                            newfile.write(content_decoded)

                        hashedWord = md5(content_decoded).hexdigest()
                        if (self.fIP[key][2] == hashedWord):
                            print("\nFile successfully received")
                            reply.add_answer(dnslib.RR(rname=qname, rtype=question.qtype, rclass=1, ttl=self.TTL, rdata=dnslib.TXT("OK")))
                    
                        else:
                            print("\nFile received but failed hash:")
                            reply.add_answer(dnslib.RR(rname=qname, rtype=question.qtype, rclass=1, ttl=self.TTL, rdata=dnslib.TXT("FAIL HASH")))
                    

                        del self.fIP[key]
                    

                            
                else:
                    # new connection. we expect a file name
                    print("New file:",content)
                    parts = content.split("|")
                    if (len(parts)==3):
                        #we have valid request
                        print("new file upload: ",content)
                        self.fIP[parts[2][:4]]= [os.path.basename(parts[0]),int(parts[1]),parts[2],"",int(parts[1])]
                    reply.add_answer(dnslib.RR(rname=qname, rtype=question.qtype, rclass=1, ttl=self.TTL, rdata=dnslib.TXT("OK")))

                

            else:
                 reply.add_answer(dnslib.RR(rname=qname, rtype=question.qtype, rclass=1, ttl=self.TTL, rdata=dnslib.A(self.IP)))

            #print("responding:",reply)
            return reply.pack()


class TCPDNSHandler(BaseRequestHandler):
    
    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(8192).strip()
        sz = int(binascii.b2a_hex(self.data[:2]), 16)
        
        if sz < len(self.data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(self.data) - 2:
            raise Exception("Too big TCP packet")
        #print("Request from {}".format(self.client_address[0]))
        

        req = dnslib.DNSRecord.parse(self.data[2:])
        #print("TCP: ",req)
        
        reply = self.processRequest(req)
        #print(reply)
        

        sz = hex(len(reply))[2:].zfill(4)
        sb = bytearray.fromhex(sz)
        self.request.sendall(sb+reply)

class UDPDNSHandler(BaseRequestHandler):
    
    def handle(self):
        # self.request is the TCP socket connected to the client
        data = self.request[0].strip()
        #print("UDP Request from {}".format(self.client_address[0]))
        
        try:
            req = dnslib.DNSRecord.parse(data)
            #print("UDP: ",req)
            
            reply = self.processRequest(req)

            # just send back the same data, but upper-cased
            #print("responding:",reply)
            self.request[1].sendto(reply, self.client_address)
            #print("responded")
        except Exception as e:
            print(e)
            pass

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
