"""
CryptoValidator — Interface Graphique Tkinter
Dark cybersecurity theme | 4 onglets : RSA / ECC / Attaques / Rapport
"""
import sys, os, threading, io
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ── Palette ────────────────────────────────────────────────────────────────
BG       = "#0d1117"
BG2      = "#161b22"
BG3      = "#21262d"
ACCENT   = "#00ff88"
ACCENT2  = "#00b4d8"
WARN     = "#ff6b6b"
TEXT     = "#e6edf3"
GRAY     = "#8b949e"
FONT     = ("Consolas", 11)
FONT_B   = ("Consolas", 11, "bold")
FONT_H   = ("Consolas", 14, "bold")
FONT_T   = ("Consolas", 10)

# ── Helper : log vers un widget ScrolledText ───────────────────────────────
class TermCapture:
    def __init__(self, widget: scrolledtext.ScrolledText):
        self.w = widget
    def write(self, msg):
        self.w.configure(state="normal")
        self.w.insert(tk.END, msg)
        self.w.see(tk.END)
        self.w.configure(state="disabled")
    def flush(self): pass

def make_term(parent, height=18) -> scrolledtext.ScrolledText:
    t = scrolledtext.ScrolledText(parent, height=height, bg="#010409", fg=ACCENT,
                                   insertbackground=ACCENT, font=FONT_T,
                                   relief="flat", bd=0, state="disabled")
    return t

def clear_term(t: scrolledtext.ScrolledText):
    t.configure(state="normal"); t.delete("1.0", tk.END); t.configure(state="disabled")

def label(p, txt, **kw):
    return tk.Label(p, text=txt, bg=BG2, fg=TEXT, font=FONT, **kw)

def entry(p, width=12, **kw):
    e = tk.Entry(p, width=width, bg=BG3, fg=ACCENT, insertbackground=ACCENT,
                 font=FONT_B, relief="flat", bd=4, **kw)
    return e

def btn(p, txt, cmd, color=ACCENT):
    return tk.Button(p, text=txt, command=cmd, bg=color, fg=BG,
                     font=FONT_B, relief="flat", bd=0, padx=14, pady=6,
                     activebackground="#009955", cursor="hand2")

def section_frame(p, title):
    f = tk.LabelFrame(p, text=f"  {title}  ", bg=BG2, fg=ACCENT2,
                      font=FONT_B, relief="flat", bd=2,
                      highlightbackground=BG3, highlightthickness=1)
    return f

# ══════════════════════════════════════════════════════════════════════════════
#  TAB 1 — RSA
# ══════════════════════════════════════════════════════════════════════════════
def build_rsa_tab(nb):
    tab = tk.Frame(nb, bg=BG2); nb.add(tab, text="  🔐 RSA  ")

    top = tk.Frame(tab, bg=BG2); top.pack(fill="x", padx=16, pady=10)

    # Params frame
    pf = section_frame(top, "Parametres RSA"); pf.pack(side="left", padx=(0,12), pady=4)
    fields = {}
    for i,(k,v) in enumerate([("p (premier)","17"),("q (premier)","19"),
                                ("e (exposant)","7"),("message","42")]):
        label(pf, k+":").grid(row=i, column=0, sticky="w", padx=8, pady=4)
        e = entry(pf, width=10); e.insert(0, v)
        e.grid(row=i, column=1, padx=8, pady=4)
        fields[k] = e

    # Actions frame
    af = section_frame(top, "Actions"); af.pack(side="left", pady=4)
    term = make_term(tab, height=20); term.pack(fill="both", expand=True, padx=16, pady=(0,12))

    def run_rsa():
        clear_term(term)
        cap = TermCapture(term)
        old = sys.stdout; sys.stdout = cap
        try:
            from modules.rsa_module import RSAEngine
            p = int(fields["p (premier)"].get())
            q = int(fields["q (premier)"].get())
            e = int(fields["e (exposant)"].get())
            m = int(fields["message"].get())
            rsa = RSAEngine()
            rsa.set_params(p, q, e)
            c = rsa.encrypt(m)
            print(f"\n  [ENCRYPT] {m} --> {c}")
            d = rsa.decrypt(c)
            print(f"  [DECRYPT] {c} --> {d}")
            ok = "[OK]" if d == m else "[ERREUR]"
            print(f"  Integrite : {ok}")
            pub = rsa.get_public_key(); priv = rsa.get_private_key()
            print(f"\n  Cle publique  (e,n) = {pub}")
            print(f"  Cle privee   (d,n) = {priv}")
        except Exception as ex:
            print(f"\n  [ERREUR] {ex}")
        finally:
            sys.stdout = old

    def run_euclide():
        clear_term(term)
        cap = TermCapture(term); old = sys.stdout; sys.stdout = cap
        try:
            from modules.rsa_module import extended_gcd, mod_inverse
            e = int(fields["e (exposant)"].get())
            p = int(fields["p (premier)"].get())
            q = int(fields["q (premier)"].get())
            phi = (p-1)*(q-1)
            g, x, y = extended_gcd(e, phi)
            print(f"\n  Euclide Etendu : gcd({e}, {phi})")
            print(f"  gcd = {g}")
            print(f"  Bezout : {e}*({x}) + {phi}*({y}) = {g}")
            d = mod_inverse(e, phi)
            print(f"\n  Inverse modulaire :")
            print(f"  d = {e}^(-1) mod {phi} = {d}")
            print(f"  Verification : ({e} * {d}) mod {phi} = {(e*d)%phi}")
        except Exception as ex:
            print(f"\n  [ERREUR] {ex}")
        finally:
            sys.stdout = old

    btn(af, "  Chiffrer / Dechiffrer", run_rsa).pack(fill="x", padx=10, pady=6)
    btn(af, "  Euclide Etendu", run_euclide, ACCENT2).pack(fill="x", padx=10, pady=6)
    btn(af, "  Effacer", lambda: clear_term(term), BG3).pack(fill="x", padx=10, pady=6)

# ══════════════════════════════════════════════════════════════════════════════
#  TAB 2 — ECC
# ══════════════════════════════════════════════════════════════════════════════
def build_ecc_tab(nb):
    tab = tk.Frame(nb, bg=BG2); nb.add(tab, text="  📐 ECC  ")
    top = tk.Frame(tab, bg=BG2); top.pack(fill="x", padx=16, pady=10)

    cf = section_frame(top, "Courbe  y^2 = x^3 + ax + b  (mod p)"); cf.pack(side="left", padx=(0,12), pady=4)
    curve_fields = {}
    for i,(k,v) in enumerate([("a","2"),("b","2"),("p (premier)","17"),("Gx","5"),("Gy","1")]):
        label(cf, k+":").grid(row=i, column=0, sticky="w", padx=8, pady=3)
        e = entry(cf, width=8); e.insert(0,v); e.grid(row=i, column=1, padx=8, pady=3)
        curve_fields[k] = e

    kf = section_frame(top, "Clés privées (ECDH)"); kf.pack(side="left", padx=(0,12), pady=4)
    label(kf, "dA (Alice):").grid(row=0, column=0, sticky="w", padx=8, pady=4)
    dA_e = entry(kf, width=10); dA_e.insert(0, "5"); dA_e.grid(row=0, column=1, padx=8, pady=4)
    label(kf, "dB (Bob):").grid(row=1, column=0, sticky="w", padx=8, pady=4)
    dB_e = entry(kf, width=10); dB_e.insert(0, "7"); dB_e.grid(row=1, column=1, padx=8, pady=4)

    mf = section_frame(top, "Message (signature)"); mf.pack(side="left", padx=(0,12), pady=4)
    label(mf, "Message:").grid(row=0, column=0, padx=8, pady=4)
    msg_e = entry(mf, width=20); msg_e.insert(0,"Hello Crypto!"); msg_e.grid(row=0,column=1,padx=8,pady=4)

    af = section_frame(top, "Actions"); af.pack(side="left", pady=4)
    term = make_term(tab, 20); term.pack(fill="both", expand=True, padx=16, pady=(0,12))

    def get_curve():
        from modules.ecc_module import Curve, Point
        a = int(curve_fields["a"].get()); b = int(curve_fields["b"].get())
        p = int(curve_fields["p (premier)"].get())
        gx= int(curve_fields["Gx"].get());  gy= int(curve_fields["Gy"].get())
        c = Curve(a,b,p,"Custom"); G = Point(gx,gy,c)
        return c, G

    def run_points():
        clear_term(term)
        cap = TermCapture(term); old=sys.stdout; sys.stdout=cap
        try:
            c, G = get_curve()
            pts = c.list_points()
            print(f"\n  Courbe : y^2 = x^3 + {c.a}*x + {c.b}  (mod {c.p})")
            print(f"  Nombre de points affines : {len(pts)}  (+1 point a l'infini)")
            print(f"\n  Liste des points :")
            for i,pt in enumerate(pts):
                print(f"    {i+1:>2}. {pt}", end="  ")
                if (i+1)%3==0: print()
            print(f"\n\n  G = {G}  |  G sur courbe : {c.is_on_curve(G)}")
        except Exception as ex:
            print(f"\n  [ERREUR] {ex}")
        finally:
            sys.stdout=old

    def run_ecdh():
        clear_term(term)
        cap = TermCapture(term); old=sys.stdout; sys.stdout=cap
        try:
            from modules.ecc_module import Curve, Point, scalar_mult
            c, G = get_curve()
            # compute real order (naif)
            ord_G=1
            while scalar_mult(ord_G+1, G, c) is not None and ord_G < 5000:
                ord_G += 1
            print(f"\n  Courbe : {c}")
            print(f"  G = {G}, ordre = {ord_G}")
            dA = int(dA_e.get()); dB = int(dB_e.get())
            if not (1 <= dA < ord_G) or not (1 <= dB < ord_G):
                raise ValueError(f"dA et dB doivent être dans [1, ordre(G)-1] = [1, {ord_G-1}]")

            # même point G pour Alice & Bob
            Pa = scalar_mult(dA, G, c)
            Pb = scalar_mult(dB, G, c)
            print(f"\n  Alice : dA={dA}, Qa=dA*G={Pa}")
            print(f"  Bob   : dB={dB}, Qb=dB*G={Pb}")

            Sa = scalar_mult(dA, Pb, c)
            Sb = scalar_mult(dB, Pa, c)
            print(f"\n  Secret Alice = {Sa}")
            print(f"  Secret Bob   = {Sb}")
            print(f"\n  Accord ECDH : {'[OK]' if Sa==Sb else '[ERREUR]'}")
        except Exception as ex:
            print(f"\n  [ERREUR] {ex}")
        finally:
            sys.stdout=old

    def run_sign():
        clear_term(term)
        cap = TermCapture(term); old=sys.stdout; sys.stdout=cap
        try:
            from modules.ecc_module import Curve, Point, ECDH, ECSign, scalar_mult
            c, G = get_curve()
            tmp=G; ord_G=1
            while scalar_mult(ord_G+1,G,c) is not None and ord_G<500:
                ord_G+=1
            ecdh=ECDH(c,G,ord_G); ec=ECSign(c,G,ord_G)
            priv,pub = ecdh.generate_keypair()
            msg = msg_e.get()
            print(f"\n  Message : '{msg}'")
            print(f"  Cle privee : {priv}  |  Cle publique : {pub}")
            sig = ec.sign(msg, priv)
            print(f"\n  Signature : r={sig[0]}, s={sig[1]}")
            v = ec.verify(msg, sig, pub)
            print(f"  Verification (bonne cle) : {'[Valide]' if v else '[Invalide]'}")
            _,bad=ecdh.generate_keypair()
            v2=ec.verify(msg,sig,bad)
            print(f"  Verification (mauvaise cle) : {'[Valide !?]' if v2 else '[Invalide - correct]'}")
        except Exception as ex:
            print(f"\n  [ERREUR] {ex}")
        finally:
            sys.stdout=old

    btn(af,"  Lister les Points",  run_points).pack(fill="x",padx=10,pady=5)
    btn(af,"  Protocole ECDH",     run_ecdh, ACCENT2).pack(fill="x",padx=10,pady=5)
    btn(af,"  Signer & Verifier",  run_sign,"#a855f7").pack(fill="x",padx=10,pady=5)
    btn(af,"  Effacer", lambda:clear_term(term), BG3).pack(fill="x",padx=10,pady=5)

# ══════════════════════════════════════════════════════════════════════════════
#  TAB 3 — ATTAQUES
# ══════════════════════════════════════════════════════════════════════════════
def build_attack_tab(nb):
    tab = tk.Frame(nb, bg=BG2); nb.add(tab, text="  🚨 Attaques  ")
    top = tk.Frame(tab, bg=BG2); top.pack(fill="x", padx=16, pady=10)

    # Pollard
    pf = section_frame(top, "Pollard's Rho — Factorisation RSA"); pf.pack(side="left", padx=(0,12), pady=4)
    label(pf,"n (a factoriser):").grid(row=0,column=0,padx=8,pady=6,sticky="w")
    n_e = entry(pf, width=14); n_e.insert(0,"323"); n_e.grid(row=0,column=1,padx=8,pady=6)

    # BSGS
    bf = section_frame(top, "BSGS — Log Discret ECC"); bf.pack(side="left", padx=(0,12), pady=4)
    bsgs_f = {}
    for i,(k,v) in enumerate([("a","2"),("b","2"),("p","17"),("Gx","5"),("Gy","1"),("ordre","18")]):
        label(bf,k+":").grid(row=i,column=0,padx=6,pady=2,sticky="w")
        e=entry(bf,width=6); e.insert(0,v); e.grid(row=i,column=1,padx=6,pady=2)
        bsgs_f[k]=e
    label(bf,"cle privee (a deviner):").grid(row=6,column=0,padx=6,pady=2,sticky="w")
    priv_e=entry(bf,width=6); priv_e.insert(0,"9"); priv_e.grid(row=6,column=1,padx=6,pady=2)

    af = section_frame(top,"Actions"); af.pack(side="left",pady=4)
    term = make_term(tab,20); term.pack(fill="both",expand=True,padx=16,pady=(0,12))

    # Step-by-step options (trace)
    vf = section_frame(top, "Step-by-step"); vf.pack(side="left", padx=(12, 0), pady=4)
    verbose_var = tk.BooleanVar(value=False)
    tk.Checkbutton(
        vf,
        text="Afficher étapes (verbose)",
        variable=verbose_var,
        bg=BG2,
        fg=TEXT,
        selectcolor=BG3,
        activebackground=BG2,
        activeforeground=TEXT,
        font=FONT,
    ).pack(anchor="w", padx=10, pady=(8, 2))
    label(vf, "Log chaque N itérations:").pack(anchor="w", padx=10, pady=(6, 2))
    every_e = entry(vf, width=8); every_e.insert(0, "25"); every_e.pack(anchor="w", padx=10, pady=(0, 8))

    def run_rho():
        clear_term(term)
        cap=TermCapture(term); old=sys.stdout; sys.stdout=cap
        def job():
            try:
                from modules.attacks_module import factor_rsa, pollard_rho
                n=int(n_e.get())
                verbose = bool(verbose_var.get())
                every = int(every_e.get() or "25")
                trace = [] if verbose else None
                p,q=factor_rsa(n, verbose=verbose, log_every=every, trace=trace)
                t=pollard_rho._last_elapsed
                if p:
                    print(f"\n  [OK] {n} = {p} x {q}")
                    print(f"  Temps : {t:.6f} s")
                    phi=(p-1)*(q-1)
                    print(f"  phi(n) = {phi}")
                    print(f"  => La cle privee RSA est recalculable !")
                    if verbose and trace:
                        print("\n  --- TRACE (Pollard's Rho) ---")
                        for line in trace[-500:]:
                            print(f"  {line}")
                else:
                    print(f"\n  [ECHEC] Factorisation de {n} echouee.")
            except Exception as ex:
                print(f"\n  [ERREUR] {ex}")
            finally:
                sys.stdout=old
        threading.Thread(target=job,daemon=True).start()

    def run_bsgs():
        clear_term(term)
        cap=TermCapture(term); old=sys.stdout; sys.stdout=cap
        def job():
            try:
                from modules.ecc_module import Curve, Point, scalar_mult
                from modules.attacks_module import bsgs_ecc
                a=int(bsgs_f["a"].get()); b=int(bsgs_f["b"].get())
                p=int(bsgs_f["p"].get()); gx=int(bsgs_f["Gx"].get())
                gy=int(bsgs_f["Gy"].get()); order=int(bsgs_f["ordre"].get())
                priv=int(priv_e.get())
                c=Curve(a,b,p); G=Point(gx,gy,c)
                Q=scalar_mult(priv,G,c)
                print(f"\n  G = {G}, ordre = {order}")
                print(f"  Cle privee reelle : k = {priv}")
                print(f"  Cle publique Q = k*G = {Q}")
                print(f"\n  Lancement BSGS...")
                verbose = bool(verbose_var.get())
                every = int(every_e.get() or "1")
                trace = [] if verbose else None
                k=bsgs_ecc(G,Q,c,order, verbose=verbose, log_every=every, trace=trace)
                if k is not None:
                    print(f"\n  [OK] Cle retrouvee : k = {k}")
                    verify=scalar_mult(k,G,c)
                    print(f"  Verification : {k}*G = {verify} == {Q} : {verify==Q}")
                    if verbose and trace:
                        print("\n  --- TRACE (BSGS) ---")
                        for line in trace[-800:]:
                            print(f"  {line}")
                else:
                    print(f"\n  [ECHEC] Cle non retrouvee.")
            except Exception as ex:
                print(f"\n  [ERREUR] {ex}")
            finally:
                sys.stdout=old
        threading.Thread(target=job,daemon=True).start()

    btn(af,"  Lancer Pollard's Rho", run_rho, WARN).pack(fill="x",padx=10,pady=5)
    btn(af,"  Lancer BSGS ECC",      run_bsgs,"#f97316").pack(fill="x",padx=10,pady=5)
    btn(af,"  Effacer", lambda:clear_term(term), BG3).pack(fill="x",padx=10,pady=5)

# ══════════════════════════════════════════════════════════════════════════════
#  TAB 4 — RAPPORT
# ══════════════════════════════════════════════════════════════════════════════
def build_report_tab(nb):
    tab = tk.Frame(nb, bg=BG2); nb.add(tab, text="  📊 Rapport  ")
    top = tk.Frame(tab, bg=BG2); top.pack(fill="x", padx=16, pady=10)
    af = section_frame(top,"Actions"); af.pack(side="left",pady=4)
    term = make_term(tab,22); term.pack(fill="both",expand=True,padx=16,pady=(0,12))

    def run_full():
        clear_term(term)
        cap=TermCapture(term); old=sys.stdout; sys.stdout=cap
        def job():
            try:
                from modules.rsa_module import RSAEngine
                from modules.ecc_module import Curve, Point, ECDH, ECSign, scalar_mult
                from modules.attacks_module import factor_rsa, bsgs_ecc, pollard_rho
                from modules.report_module import ReportEngine
                report=ReportEngine()
                print("  [1/4] RSA p=17 q=19 e=7 ...")
                rsa=RSAEngine(); rsa.set_params(17,19,7)
                c=rsa.encrypt(42); d=rsa.decrypt(c)
                t=rsa.get_timings()
                report.add_metric("RSA","set_params",t["set_params"],f"n={rsa.n},d={rsa.d}")
                report.add_metric("RSA","encrypt",t["encrypt"],f"c={c}")
                report.add_metric("RSA","decrypt",t["decrypt"],f"m={d}")
                print("  [2/4] ECC y^2=x^3+2x+2 mod 17 ...")
                curve=Curve(2,2,17,"Demo17"); G=Point(5,1,curve)
                ord_G=1
                while scalar_mult(ord_G+1,G,curve) is not None and ord_G<500: ord_G+=1
                ecdh=ECDH(curve,G,ord_G)
                ka,Pa=ecdh.generate_keypair(); kb,Pb=ecdh.generate_keypair()
                ecdh.shared_secret(ka,Pb)
                report.add_metric("ECC","generate_keypair",ecdh.generate_keypair._last_elapsed,"Paire Alice")
                report.add_metric("ECC","shared_secret",ecdh.shared_secret._last_elapsed,"ECDH")
                ec=ECSign(curve,G,ord_G)
                sig=ec.sign("test",ka)
                ec.verify("test",sig,Pa)
                report.add_metric("ECC","sign",ec.sign._last_elapsed,"Signature")
                report.add_metric("ECC","verify",ec.verify._last_elapsed,"Verification")
                print("  [3/4] Attaques ...")
                factor_rsa(rsa.n)
                report.set_attack_result("Pollard's Rho",f"n=323=19x17",pollard_rho._last_elapsed)
                k=bsgs_ecc(G,Pa,curve,ord_G)
                from modules.attacks_module import bsgs_ecc as bf
                report.set_attack_result("BSGS ECC",f"k={k} retrouve" if k else "echec",bf._last_elapsed)
                report.add_info("RSA: p=17,q=19,n=323,e=7,d=247")
                report.add_info("ECC: y^2=x^3+2x+2 mod 17, G=(5,1), ordre=19")
                print("  [4/4] Generation rapport ...")
                out=os.path.dirname(os.path.abspath(__file__))
                content=report.generate(filename="rapport_crypto.md",output_dir=out)
                report.print_summary()
                print("\n  === APERCU RAPPORT ===\n")
                for line in content.split("\n")[:30]:
                    print(f"  {line}")
                print("  ...")
            except Exception as ex:
                print(f"\n  [ERREUR] {ex}")
                import traceback; traceback.print_exc()
            finally:
                sys.stdout=old
        threading.Thread(target=job,daemon=True).start()

    def open_report():
        path=os.path.join(os.path.dirname(os.path.abspath(__file__)),"rapport_crypto.md")
        if os.path.exists(path):
            term.configure(state="normal"); term.delete("1.0",tk.END)
            with open(path,encoding="utf-8") as f:
                term.insert(tk.END, f.read())
            term.configure(state="disabled")
        else:
            messagebox.showwarning("Rapport","Generez d'abord le rapport complet.")

    btn(af,"  Generer Rapport Complet", run_full, ACCENT).pack(fill="x",padx=10,pady=5)
    btn(af,"  Afficher rapport.md",     open_report, ACCENT2).pack(fill="x",padx=10,pady=5)
    btn(af,"  Effacer", lambda:clear_term(term), BG3).pack(fill="x",padx=10,pady=5)

# ══════════════════════════════════════════════════════════════════════════════
#  FENETRE PRINCIPALE
# ══════════════════════════════════════════════════════════════════════════════
def main():
    root = tk.Tk()
    root.title("CryptoValidator — Pure Python")
    root.geometry("980x720"); root.minsize(820,600)
    root.configure(bg=BG)

    # Header
    hdr = tk.Frame(root, bg=BG, pady=10); hdr.pack(fill="x", padx=20)
    tk.Label(hdr, text="[ CRYPTO VALIDATOR ]", bg=BG, fg=ACCENT,
             font=("Consolas",20,"bold")).pack(side="left")
    tk.Label(hdr, text="Pure Python | No External Libs", bg=BG, fg=GRAY,
             font=("Consolas",11)).pack(side="left", padx=16)
    tk.Label(hdr, text="RSA | ECC | Attaques | Rapport", bg=BG, fg=ACCENT2,
             font=("Consolas",11)).pack(side="right")

    tk.Frame(root, bg=ACCENT, height=2).pack(fill="x", padx=20)

    # Notebook
    style = ttk.Style()
    style.theme_use("default")
    style.configure("TNotebook",        background=BG,  borderwidth=0)
    style.configure("TNotebook.Tab",    background=BG3, foreground=GRAY,
                    font=("Consolas",11,"bold"), padding=[14,8])
    style.map("TNotebook.Tab",
              background=[("selected", BG2)],
              foreground=[("selected", ACCENT)])
    style.configure("TFrame", background=BG2)

    nb = ttk.Notebook(root); nb.pack(fill="both", expand=True, padx=20, pady=12)

    build_rsa_tab(nb)
    build_ecc_tab(nb)
    build_attack_tab(nb)
    build_report_tab(nb)

    # Footer
    ft = tk.Frame(root, bg=BG); ft.pack(fill="x", padx=20, pady=(0,8))
    tk.Label(ft, text="Architecte Cryptographie | Calculs natifs Python | Zero dependance externe",
             bg=BG, fg=GRAY, font=("Consolas",9)).pack(side="left")

    root.mainloop()

if __name__ == "__main__":
    main()
