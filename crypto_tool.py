"""
=============================================================================
CryptoValidator -- Orchestrateur Principal
=============================================================================
Auteur  : Architecte Cryptographie
Usage   : python crypto_tool.py

Demontre :
  MODULE 1 -> RSA avec p=17, q=19, e=7
  MODULE 2 -> ECC sur y^2 = x^3 + 2x + 2 (mod 17), ECDH + Signature
  MODULE 3 -> Pollard's Rho (factoriser n=323) + BSGS (retrouver cle ECC)
  MODULE 4 -> Rapport Markdown comparatif

AUCUNE bibliotheque externe (cryptography, OpenSSL, pycryptodome).
=============================================================================
"""
import sys
import os

# Force UTF-8 sur Windows pour les caracteres speciaux dans le terminal
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Assure que le repertoire courant est dans le path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.rsa_module     import RSAEngine
from modules.ecc_module     import Curve, Point, ECDH, ECSign, scalar_mult
from modules.attacks_module import factor_rsa, bsgs_ecc
from modules.report_module  import ReportEngine


# ---------------------------------------------------------------------------
#  HELPERS D'AFFICHAGE
# ---------------------------------------------------------------------------

def banner(title: str, width: int = 65):
    print("\n+" + "=" * (width - 2) + "+")
    pad = (width - 2 - len(title)) // 2
    print("|" + " " * pad + title + " " * (width - 2 - pad - len(title)) + "|")
    print("+" + "=" * (width - 2) + "+")

def section(title: str):
    line = "-" * max(0, 55 - len(title))
    print(f"\n  +-- {title} {line}")


# ---------------------------------------------------------------------------
#  MAIN
# ---------------------------------------------------------------------------

def main():
    banner("CryptoValidator | Pure Python | Architecte Cryptographie")
    report = ReportEngine()

    # =======================================================================
    # MODULE 1 : RSA DYNAMIQUE
    # =======================================================================
    banner("MODULE 1 : RSA DYNAMIQUE")

    section("Initialisation RSA (p=17, q=19, e=7)")
    rsa = RSAEngine()
    rsa.set_params(p=17, q=19, e=7)

    section("Chiffrement RSA")
    message    = 42
    ciphertext = rsa.encrypt(message)
    print(f"  Message original   : {message}")
    print(f"  Message chiffre    : {ciphertext}")

    section("Dechiffrement RSA")
    recovered = rsa.decrypt(ciphertext)
    print(f"  Message dechiffre  : {recovered}")
    integrity = "OK" if recovered == message else "ERREUR"
    print(f"  Integrite          : [{integrity}]")

    # Enregistrement des timings RSA
    rsa_timings = rsa.get_timings()
    report.add_metric("RSA", "set_params", rsa_timings["set_params"],
                      f"Config n={rsa.n}, phi={rsa.phi_n}, d={rsa.d}")
    report.add_metric("RSA", "encrypt",   rsa_timings["encrypt"],
                      f"c = {message}^{rsa.e} mod {rsa.n} = {ciphertext}")
    report.add_metric("RSA", "decrypt",   rsa_timings["decrypt"],
                      f"m = {ciphertext}^{rsa.d} mod {rsa.n} = {recovered}")

    report.add_info(f"RSA : p={rsa.p}, q={rsa.q}, n={rsa.n}, e={rsa.e}, d={rsa.d}, phi(n)={rsa.phi_n}")
    report.add_info(f"RSA : message={message}, chiffre={ciphertext}, dechiffre={recovered}")

    # =======================================================================
    # MODULE 2 : ECC UNIVERSEL
    # =======================================================================
    banner("MODULE 2 : ECC UNIVERSEL  y^2 = x^3 + 2x + 2  (mod 17)")

    section("Definition de la courbe")
    curve = Curve(a=2, b=2, p=17, name="Demo17")
    print(f"  Courbe : {curve}")

    section("Enumeration des points affines")
    points = curve.list_points()
    print(f"  Points sur la courbe ({len(points)} points affines + point a l'infini) :")
    for i, pt in enumerate(points):
        print(f"    {i+1:>2}. {pt}", end="  ")
        if (i + 1) % 4 == 0:
            print()
    print()

    # Point generateur G = (5, 1) sur y^2 = x^3+2x+2 mod 17
    # Verification : 1^2 = 1 ; 5^3+2*5+2 = 137 = 8*17+1 -> 1 mod 17 [OK]
    G = Point(5, 1, curve)
    print(f"  Point generateur G = {G}")
    print(f"  G sur courbe : {curve.is_on_curve(G)}")

    section("Calcul de l'ordre du groupe (ordre de G par iteration)")
    order_G = 1
    tmp = scalar_mult(order_G + 1, G, curve)
    while tmp is not None and order_G < 1000:
        order_G += 1
        tmp = scalar_mult(order_G + 1, G, curve)

    print(f"  Ordre de G : {order_G}")

    # -- ECDH -----------------------------------------------------------------
    section("Protocole ECDH (Echange de Cles Diffie-Hellman)")
    ecdh = ECDH(curve, G, order_G)

    priv_alice, pub_alice = ecdh.generate_keypair()
    print(f"  Alice : cle privee = {priv_alice}, cle publique = {pub_alice}")
    t_alice_gen = ecdh.generate_keypair._last_elapsed

    priv_bob, pub_bob = ecdh.generate_keypair()
    print(f"  Bob   : cle privee = {priv_bob},   cle publique = {pub_bob}")

    secret_alice = ecdh.shared_secret(priv_alice, pub_bob)
    secret_bob   = ecdh.shared_secret(priv_bob,   pub_alice)
    t_secret     = ecdh.shared_secret._last_elapsed

    print(f"\n  Secret Alice = {secret_alice}")
    print(f"  Secret Bob   = {secret_bob}")
    accord = "OK - secrets identiques" if secret_alice == secret_bob else "ERREUR"
    print(f"  Accord ECDH  : [{accord}]")

    report.add_metric("ECC", "generate_keypair", t_alice_gen, "Generation paire Alice")
    report.add_metric("ECC", "shared_secret",    t_secret,    "Calcul secret partage ECDH")
    report.add_info(f"ECC : Courbe y^2=x^3+2x+2 mod 17, G={G}, ordre(G)={order_G}")
    report.add_info(f"ECDH : Alice priv={priv_alice}, Bob priv={priv_bob}, secret commun={secret_alice}")

    # -- Signature numerique --------------------------------------------------
    section("Signature Numerique (ECDSA-like)")
    ec_sign  = ECSign(curve, G, order_G)
    test_msg = "Hello, Cryptographie!"

    sig = ec_sign.sign(test_msg, priv_alice)
    print(f"  Message   : '{test_msg}'")
    print(f"  Signature : (r={sig[0]}, s={sig[1]})")
    t_sign = ec_sign.sign._last_elapsed

    valid = ec_sign.verify(test_msg, sig, pub_alice)
    print(f"  Verification cle Alice   : [{'Valide' if valid else 'Invalide'}]")
    t_verify = ec_sign.verify._last_elapsed

    # Test avec mauvaise cle
    _, pub_impostor = ecdh.generate_keypair()
    invalid = ec_sign.verify(test_msg, sig, pub_impostor)
    print(f"  Verification cle imposteur: [{'Valide (probleme!)' if invalid else 'Invalide - correct!'}]")

    report.add_metric("ECC", "sign",   t_sign,   f"Signature ECDSA-like de '{test_msg[:20]}'")
    report.add_metric("ECC", "verify", t_verify, "Verification signature")

    # =======================================================================
    # MODULE 3 : ANALYSE D'ATTAQUES
    # =======================================================================
    banner("MODULE 3 : ANALYSE D'ATTAQUES")

    # -- Pollard's Rho --------------------------------------------------------
    section("Attaque Pollard's Rho (factoriser n=323)")
    p_found, q_found = factor_rsa(rsa.n)

    from modules.attacks_module import pollard_rho
    t_rho_elapsed = pollard_rho._last_elapsed

    if p_found:
        rho_result = f"n={rsa.n} = {p_found} x {q_found} => d retrouvable"
        print(f"  Consequence : la cle privee d={rsa.d} peut etre recalculee!")
    else:
        rho_result = "Factorisation echouee"

    report.set_attack_result("Pollard's Rho (RSA)", rho_result, t_rho_elapsed)

    # -- BSGS ECC -------------------------------------------------------------
    section("Attaque BSGS ECC (retrouver la cle privee d'Alice)")
    print(f"  Objectif : retrouver k tel que k*G = {pub_alice}")
    print(f"  Cle privee reelle : {priv_alice}")

    k_found = bsgs_ecc(G, pub_alice, curve, order_G)

    from modules.attacks_module import bsgs_ecc as bsgs_fn
    t_bsgs_elapsed = bsgs_fn._last_elapsed

    if k_found is not None:
        bsgs_result = f"[OK] k={k_found} retrouve (reel={priv_alice})"
        verify_pt = scalar_mult(k_found, G, curve)
        match = (verify_pt == pub_alice)
        print(f"  Verification : {k_found}*G = {verify_pt} == {pub_alice} -> [{'OK' if match else 'ERREUR'}]")
    else:
        bsgs_result = "Logarithme discret non trouve"

    report.set_attack_result("BSGS (ECC)", bsgs_result, t_bsgs_elapsed)

    # =======================================================================
    # MODULE 4 : RAPPORT MARKDOWN
    # =======================================================================
    banner("MODULE 4 : GENERATION DU RAPPORT")

    report.print_summary()

    output_path = os.path.dirname(os.path.abspath(__file__))
    content = report.generate(filename="rapport_crypto.md", output_dir=output_path)

    print("\n  Apercu des 12 premieres lignes du rapport :")
    for line in content.split("\n")[:12]:
        print(f"    {line}")
    print("    ...")

    banner("EXECUTION TERMINEE | Rapport : rapport_crypto.md")


if __name__ == "__main__":
    main()
