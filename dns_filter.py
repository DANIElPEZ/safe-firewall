import sqlite3, datetime, socket
from pathlib import Path
from dnslib import DNSRecord, QTYPE, RCODE
ROOT=Path(__file__).resolve().parent; DB=ROOT/"safeweb.db"; UPSTREAM=("1.1.1.1",53)
def rules():
    with sqlite3.connect(DB) as c:return [x[0].lower().rstrip(".") for x in c.execute("SELECT domain FROM rules WHERE enabled=1")]
def blocked(n,rs):
    n=n.lower().rstrip(".");return any(n==d or n.endswith("."+d) for d in rs)
def log(n,ip,t):
    now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB) as c:
        c.execute("CREATE TABLE IF NOT EXISTS dns_attempts(id INTEGER PRIMARY KEY,time TEXT,domain TEXT,client_ip TEXT,record_type TEXT)")
        c.execute("INSERT INTO dns_attempts(time,domain,client_ip,record_type) VALUES(?,?,?,?)",(now,n,ip,t))
        c.execute("INSERT INTO events(time,action,domain,detail) VALUES(?,?,?,?)",(now,"INTENTO DNS",n,f"Bloqueado desde {ip} ({t})"))
def main():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("127.0.0.1",53));print("SafeWeb DNS activo en 127.0.0.1:53")
    while True:
        data,addr=s.recvfrom(4096)
        try:
            req=DNSRecord.parse(data);n=str(req.q.qname).rstrip(".").lower();typ=QTYPE.get(req.q.qtype)
            if blocked(n,rules()):
                log(n,addr[0],typ);reply=req.reply();reply.header.rcode=RCODE.NXDOMAIN;s.sendto(reply.pack(),addr);print("[BLOCK]",n,addr[0],typ);continue
            u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(4)
            try:u.sendto(data,UPSTREAM);ans,_=u.recvfrom(4096);s.sendto(ans,addr)
            except Exception:reply=req.reply();reply.header.rcode=RCODE.SERVFAIL;s.sendto(reply.pack(),addr)
            finally:u.close()
        except Exception as e:print("Consulta inválida:",e)
if __name__=="__main__":main()
