from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from pathlib import Path
from datetime import datetime
import sqlite3, ctypes, os, re, shutil, subprocess, ipaddress, socket
ROOT=Path(__file__).resolve().parent
DB=ROOT/"safeweb.db"; REPORTS=ROOT/"reportes"; REPORTS.mkdir(exist_ok=True)
HOSTS=Path(os.environ.get("SystemRoot",r"C:\\Windows"))/"System32/drivers/etc/hosts"
START="# SAFEWEB START"; END="# SAFEWEB END"
app=Flask(__name__); app.secret_key="safeweb-local-demo-change-me"
def admin():
    try:return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except:return False
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY,domain TEXT UNIQUE,enabled INTEGER DEFAULT 1,created TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,time TEXT,action TEXT,domain TEXT,detail TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS dns_attempts(id INTEGER PRIMARY KEY,time TEXT,domain TEXT,client_ip TEXT,record_type TEXT)")
def log(a,d,msg):
    with db() as c:c.execute("INSERT INTO events(time,action,domain,detail) VALUES(?,?,?,?)",(datetime.now().strftime("%Y-%m-%d %H:%M:%S"),a,d,msg))

def clean_domain(x):
    x = (x or "").strip().lower().rstrip(".")

    if (
        "://" in x
        or "/" in x
        or ":" in x
        or not re.fullmatch(
            r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", x
        )
    ):
        raise ValueError(
            "Dominio inválido: usa dominio raíz sin protocolo ni ruta."
        )

    try:
        ipaddress.ip_address(x)
        raise ValueError("No se aceptan IP.")
    except ValueError as e:
        if str(e) == "No se aceptan IP.":
            raise

    return x


def sync_hosts():
    if os.name != "nt" or not admin():
        raise PermissionError(
            "Ejecuta la aplicación como administrador en Windows."
        )

    old = HOSTS.read_text(
        encoding="utf-8-sig",
        errors="replace"
    )

    if old.count(START) != old.count(END) or old.count(START) > 1:
        raise RuntimeError("Marcadores SAFEWEB inválidos en hosts.")

    if START in old:
        old = (
            old[:old.index(START)]
            + old[old.index(END) + len(END):]
        )

    with db() as c:
        domains = [
            r["domain"]
            for r in c.execute(
                "SELECT domain FROM rules WHERE enabled=1"
            )
        ]

    block = "\n".join(
        [START]
        + [f"0.0.0.0 {d} www.{d}" for d in domains]
        + [END]
    )

    backup = ROOT / "hosts_backup.txt"

    if not backup.exists():
        shutil.copy2(HOSTS, backup)

    updated = old.rstrip() + "\n\n" + block + "\n"

    with open(
        HOSTS,
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:
        f.write(updated)
        f.flush()
        os.fsync(f.fileno())

    subprocess.run(
        ["ipconfig", "/flushdns"],
        capture_output=True
    )

@app.route("/")
def home():
    with db() as c:
        rules=c.execute("SELECT * FROM rules ORDER BY domain").fetchall(); events=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 25").fetchall()
        total=c.execute("SELECT COUNT(*) FROM events").fetchone()[0]; attempts=c.execute("SELECT COUNT(*) FROM dns_attempts").fetchone()[0]
        top=c.execute("SELECT domain,COUNT(*) n FROM dns_attempts GROUP BY domain ORDER BY n DESC LIMIT 10").fetchall()
        recent=c.execute("SELECT * FROM dns_attempts ORDER BY id DESC LIMIT 30").fetchall()
    return render_template("index.html",rules=rules,events=events,total=total,administrator=admin(),attempts=attempts,top=top,recent=recent)
@app.post("/add")
def add():
    try:d=clean_domain(request.form.get("domain",""))
    except ValueError as e:flash(str(e),"error");return redirect(url_for("home"))
    try:
        with db() as c:c.execute("INSERT INTO rules(domain,enabled,created) VALUES(?,1,?)",(d,datetime.now().isoformat()))
        sync_hosts();log("AGREGAR",d,"Regla activa: DNS wildcard + hosts raíz/www");flash("Dominio agregado; DNS filter cubre subdominios si está activo.","ok")
    except Exception as e:log("ERROR",d,str(e));flash(str(e),"error")
    return redirect(url_for("home"))
@app.post("/toggle/<int:i>")
def toggle(i):
    with db() as c:r=c.execute("SELECT * FROM rules WHERE id=?",(i,)).fetchone()
    if r:
        try:
            with db() as c:c.execute("UPDATE rules SET enabled=? WHERE id=?",(0 if r["enabled"] else 1,i))
            sync_hosts();log("CAMBIAR",r["domain"],"Estado actualizado");flash("Regla actualizada","ok")
        except Exception as e:flash(str(e),"error")
    return redirect(url_for("home"))
@app.post("/delete/<int:i>")
def delete(i):
    with db() as c:r=c.execute("SELECT * FROM rules WHERE id=?",(i,)).fetchone()
    if r:
        try:
            with db() as c:c.execute("DELETE FROM rules WHERE id=?",(i,))
            sync_hosts();log("ELIMINAR",r["domain"],"Regla retirada");flash("Regla eliminada","ok")
        except Exception as e:flash(str(e),"error")
    return redirect(url_for("home"))
@app.post("/sync")
def sync():
    try:sync_hosts();log("SYNC","-","Hosts sincronizado");flash("Hosts sincronizado","ok")
    except Exception as e:flash(str(e),"error")
    return redirect(url_for("home"))
@app.post("/test")
def test():
    try:
        d=clean_domain(request.form.get("domain",""))
        with db() as c:active=c.execute("SELECT 1 FROM rules WHERE domain=? AND enabled=1",(d,)).fetchone()
        if not active:flash("Regla inactiva o inexistente","error");return redirect(url_for("home"))
        try:
            addresses={item[4][0] for item in socket.getaddrinfo(d,None,type=socket.SOCK_STREAM)}
            result="BLOQUEO DNS LOCAL CONFIRMADO" if addresses and addresses.issubset({"0.0.0.0","::"}) else "NO BLOQUEADO: "+", ".join(addresses);cat="ok" if "CONFIRMADO" in result else "error"
        except socket.gaierror:result="DOMINIO NO RESUELVE: no concluyente";cat="error"
        log("PRUEBA",d,result);flash(f"{d}: {result}",cat)
    except Exception as e:flash(str(e),"error")
    return redirect(url_for("home"))
@app.get("/report")
def report():
    from collections import Counter
    with db() as c:
        events=c.execute("SELECT * FROM events ORDER BY id DESC").fetchall();rules=c.execute("SELECT * FROM rules ORDER BY domain").fetchall()
        attempts=c.execute("SELECT * FROM dns_attempts ORDER BY id DESC").fetchall();top=c.execute("SELECT domain,COUNT(*) n FROM dns_attempts GROUP BY domain ORDER BY n DESC").fetchall()
    counts=Counter(e["action"] for e in events);stamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    html=render_template("report.html",events=events,rules=rules,counts=counts,generated=stamp,attempts=attempts,top=top)
    f=REPORTS/("informe_"+datetime.now().strftime("%Y%m%d_%H%M%S")+".html");f.write_text(html,encoding="utf-8");log("INFORME","-",f.name)
    return send_file(f,as_attachment=True,mimetype="text/html")
if __name__=="__main__":init();print("SafeWeb: http://127.0.0.1:3000");app.run(host="127.0.0.1",port=3000,debug=False)
