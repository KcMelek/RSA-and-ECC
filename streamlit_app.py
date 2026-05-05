import time
from dataclasses import dataclass
from typing import Any, Optional

import pandas as pd
import streamlit as st

from modules.rsa_module import RSAEngine
from modules.ecc_module import Curve, Point, ECDH, ECSign, scalar_mult, point_add
from modules.attacks_module import factor_rsa, bsgs_ecc, pollard_rho


@dataclass
class TimingRow:
    system: str
    operation: str
    elapsed_s: float
    elapsed_ns: int
    details: str = ""


def _perf_call(fn, *args, **kwargs):
    t0 = time.perf_counter_ns()
    out = fn(*args, **kwargs)
    t1 = time.perf_counter_ns()
    return out, (t1 - t0)


def _init_state():
    if "timings" not in st.session_state:
        st.session_state.timings: list[TimingRow] = []


def _add_timing(system: str, operation: str, elapsed_ns: int, details: str = ""):
    st.session_state.timings.append(
        TimingRow(system=system, operation=operation, elapsed_s=elapsed_ns / 1e9, elapsed_ns=int(elapsed_ns), details=details)
    )


def _df_timings() -> pd.DataFrame:
    rows = [
        {
            "system": t.system,
            "operation": t.operation,
            "elapsed_s": t.elapsed_s,
            "elapsed_ms": t.elapsed_s * 1e3,
            "elapsed_us": t.elapsed_s * 1e6,
            "elapsed_ns": t.elapsed_ns,
            "details": t.details,
        }
        for t in st.session_state.timings
    ]
    return pd.DataFrame(rows)


def rsa_tab():
    st.subheader("RSA")

    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown("**Calcul des clés (seul)**")
        p = st.number_input("p (premier)", min_value=2, value=17, step=1)
        q = st.number_input("q (premier)", min_value=2, value=19, step=1)
        e = st.number_input("e (exposant)", min_value=2, value=7, step=1)
        do_keys = st.button("Calculer les clés", use_container_width=True)

    with c2:
        st.markdown("**Message (texte)**")
        msg = st.text_area("Message à chiffrer / signer", value="Hello RSA!", height=120)

    rsa: Optional[RSAEngine] = st.session_state.get("rsa_engine")

    if do_keys:
        try:
            rsa = RSAEngine()
            _, ns = _perf_call(rsa.set_params, int(p), int(q), int(e))
            st.session_state.rsa_engine = rsa
            _add_timing("RSA", "set_params", ns, details=f"n={rsa.n}")
            st.success(f"Clés calculées. n={rsa.n}, phi={rsa.phi_n}, d={rsa.d}")
            st.code(f"Clé publique (e,n) = ({rsa.e}, {rsa.n})\nClé privée  (d,n) = ({rsa.d}, {rsa.n})")
            st.caption(f"Temps exact: {ns} ns ({ns/1e6:.3f} ms)")
        except Exception as ex:
            st.error(str(ex))

    st.divider()

    st.markdown("**Chiffrer (seul) — chiffrer le message écrit**")
    colA, colB = st.columns([1, 1])
    with colA:
        enc_btn = st.button("Chiffrer le message", type="primary", use_container_width=True)
    with colB:
        st.markdown("**Payload chiffré** (copiez/collez pour déchiffrer)")
        cipher_in = st.text_area("Ciphertext payload", value=st.session_state.get("rsa_cipher_payload", ""), height=110)

    if enc_btn:
        if rsa is None:
            st.error("Calculez d'abord les clés RSA.")
        else:
            try:
                payload, ns = _perf_call(rsa.encrypt_text, msg)
                st.session_state.rsa_cipher_payload = payload
                _add_timing("RSA", "encrypt_text", ns, details=f"len={len(msg)}")
                st.success("Message chiffré.")
                st.caption(f"Temps exact: {ns} ns ({ns/1e6:.3f} ms)")
                st.text_area("Ciphertext payload (base64 JSON)", value=payload, height=110)
            except Exception as ex:
                st.error(str(ex))

    st.divider()

    st.markdown("**Déchiffrer (seul) — déchiffrer le message écrit**")
    dec_btn = st.button("Déchiffrer le payload", use_container_width=True)
    if dec_btn:
        if rsa is None:
            st.error("Calculez d'abord les clés RSA.")
        else:
            try:
                clear, ns = _perf_call(rsa.decrypt_text, cipher_in.strip())
                _add_timing("RSA", "decrypt_text", ns, details=f"out_len={len(clear)}")
                st.success("Payload déchiffré.")
                st.caption(f"Temps exact: {ns} ns ({ns/1e6:.3f} ms)")
                st.text_area("Message déchiffré", value=clear, height=100)
            except Exception as ex:
                st.error(str(ex))

    st.divider()

    st.markdown("**Signature (seul)**")
    s1, s2, s3 = st.columns([1, 1, 1])
    with s1:
        sign_btn = st.button("Signer le message", use_container_width=True)
    with s2:
        sig_val = st.text_input("Signature (entier)", value=st.session_state.get("rsa_signature", ""))
    with s3:
        verify_btn = st.button("Vérifier la signature", use_container_width=True)

    if sign_btn:
        if rsa is None:
            st.error("Calculez d'abord les clés RSA.")
        else:
            try:
                sig, ns = _perf_call(rsa.sign, msg)
                st.session_state.rsa_signature = str(sig)
                _add_timing("RSA", "sign", ns)
                st.success("Signature générée.")
                st.caption(f"Temps exact: {ns} ns ({ns/1e6:.3f} ms)")
                st.text_input("Signature (entier)", value=str(sig))
            except Exception as ex:
                st.error(str(ex))

    if verify_btn:
        if rsa is None:
            st.error("Calculez d'abord les clés RSA.")
        else:
            try:
                sig_int = int(sig_val.strip())
                ok, ns = _perf_call(rsa.verify, msg, sig_int)
                _add_timing("RSA", "verify", ns, details=f"ok={ok}")
                if ok:
                    st.success("Signature valide.")
                else:
                    st.error("Signature invalide.")
                st.caption(f"Temps exact: {ns} ns ({ns/1e6:.3f} ms)")
            except Exception as ex:
                st.error(str(ex))


def _compute_order_of_G(curve: Curve, G: Point, max_iter: int = 20000) -> int:
    # ordre naïf par itération: cherche k tel que (k+1)G = O
    ord_g = 1
    while ord_g < max_iter:
        if scalar_mult(ord_g + 1, G, curve) is None:
            return ord_g
        ord_g += 1
    raise ValueError(f"Ordre de G non trouvé (max_iter={max_iter}). Fournissez l'ordre manuellement.")


def ecc_tab():
    st.subheader("ECC (courbes non-standards)")
    st.caption("Équation: y² = x³ + a·x + b (mod p).")

    c1, c2 = st.columns([1, 1])
    with c1:
        a = st.number_input("a", value=2, step=1)
        b = st.number_input("b", value=2, step=1)
        p = st.number_input("p (premier)", min_value=3, value=17, step=1)
    with c2:
        gx = st.number_input("Gx", value=5, step=1)
        gy = st.number_input("Gy", value=1, step=1)
        order_mode = st.selectbox("Ordre du générateur", ["Auto (petits p)", "Manuel"])
        order_manual = st.number_input("Ordre (si manuel)", min_value=2, value=19, step=1, disabled=(order_mode != "Manuel"))

    msg = st.text_area("Message (pour signature)", value="Hello ECC!", height=90)

    build_btn = st.button("Initialiser courbe et générateur", use_container_width=True)
    if build_btn:
        try:
            curve, ns_curve = _perf_call(Curve, int(a), int(b), int(p), "Custom")
            G, ns_G = _perf_call(Point, int(gx), int(gy), curve)
            if order_mode == "Manuel":
                order = int(order_manual)
                ns_order = 0
            else:
                order, ns_order = _perf_call(_compute_order_of_G, curve, G, 20000)

            st.session_state.ecc_curve = curve
            st.session_state.ecc_G = G
            st.session_state.ecc_order = order

            _add_timing("ECC", "curve_init", ns_curve, details=f"p={p}")
            _add_timing("ECC", "G_init", ns_G, details=f"G=({gx},{gy})")
            if ns_order:
                _add_timing("ECC", "order(G)", ns_order, details=f"order={order}")

            st.success(f"Courbe OK. G={G}. ordre(G)={order}")
            st.caption(f"Temps exact: curve={ns_curve} ns, G={ns_G} ns, ordre={ns_order} ns")
        except Exception as ex:
            st.error(str(ex))

    curve: Optional[Curve] = st.session_state.get("ecc_curve")
    G: Optional[Point] = st.session_state.get("ecc_G")
    order: Optional[int] = st.session_state.get("ecc_order")

    st.divider()
    st.markdown("**Échange de clés (ECDH)**")
    ecdh_btn = st.button("Exécuter ECDH", type="primary", use_container_width=True)
    if ecdh_btn:
        if curve is None or G is None or order is None:
            st.error("Initialisez d'abord la courbe et G.")
        else:
            try:
                ecdh = ECDH(curve, G, int(order))
                (ka, Qa), ns_ka = _perf_call(ecdh.generate_keypair)
                (kb, Qb), ns_kb = _perf_call(ecdh.generate_keypair)
                Sa, ns_sa = _perf_call(ecdh.shared_secret, ka, Qb)
                Sb, ns_sb = _perf_call(ecdh.shared_secret, kb, Qa)

                _add_timing("ECC", "generate_keypair", ns_ka, details="Alice")
                _add_timing("ECC", "generate_keypair", ns_kb, details="Bob")
                _add_timing("ECC", "shared_secret", ns_sa, details="Alice")
                _add_timing("ECC", "shared_secret", ns_sb, details="Bob")

                st.code(
                    "\n".join(
                        [
                            f"Alice: priv={ka}, pub={Qa}",
                            f"Bob  : priv={kb}, pub={Qb}",
                            f"Secret Alice: {Sa}",
                            f"Secret Bob  : {Sb}",
                            f"Accord: {Sa == Sb}",
                        ]
                    )
                )
                st.caption(f"Temps exact (ns): keypair(A)={ns_ka}, keypair(B)={ns_kb}, secret(A)={ns_sa}, secret(B)={ns_sb}")
            except Exception as ex:
                st.error(str(ex))

    st.divider()
    st.markdown("**Signature (ECDSA-like)**")
    sig_btn = st.button("Signer & vérifier", use_container_width=True)
    if sig_btn:
        if curve is None or G is None or order is None:
            st.error("Initialisez d'abord la courbe et G.")
        else:
            try:
                ecdh = ECDH(curve, G, int(order))
                priv, pub = ecdh.generate_keypair()
                signer = ECSign(curve, G, int(order))
                sig, ns_sign = _perf_call(signer.sign, msg, priv)
                ok, ns_verify = _perf_call(signer.verify, msg, sig, pub)

                _add_timing("ECC", "sign", ns_sign)
                _add_timing("ECC", "verify", ns_verify, details=f"ok={ok}")

                st.code(f"priv={priv}\npub={pub}\nsignature=(r={sig[0]}, s={sig[1]})\nvalid={ok}")
                st.caption(f"Temps exact: sign={ns_sign} ns, verify={ns_verify} ns")
            except Exception as ex:
                st.error(str(ex))

    st.divider()
    st.markdown("**(Optionnel) Chiffrement d’un point (ElGamal ECC)**")
    colM1, colM2 = st.columns([1, 1])
    with colM1:
        mx = st.number_input("Mx", value=5, step=1)
    with colM2:
        my = st.number_input("My", value=1, step=1)
    encp_btn = st.button("Chiffrer un point M avec une clé publique", use_container_width=True)
    if encp_btn:
        if curve is None or G is None or order is None:
            st.error("Initialisez d'abord la courbe et G.")
        else:
            try:
                ecdh = ECDH(curve, G, int(order))
                priv, pub = ecdh.generate_keypair()
                M = Point(int(mx), int(my), curve)

                # ElGamal ECC: C1=kG, C2=M + kQ
                import random

                k = random.randint(1, int(order) - 1)
                (C1, ns_c1) = _perf_call(scalar_mult, k, G, curve)
                kQ, ns_kq = _perf_call(scalar_mult, k, pub, curve)
                C2, ns_c2 = _perf_call(point_add, M, kQ, curve)

                # Déchiffrement: M = C2 - d*C1
                dC1, ns_dc1 = _perf_call(scalar_mult, priv, C1, curve)
                neg_dC1 = -dC1 if dC1 else None
                M_rec, ns_mrec = _perf_call(point_add, C2, neg_dC1, curve)

                _add_timing("ECC", "point_encrypt", ns_c1 + ns_kq + ns_c2)
                _add_timing("ECC", "point_decrypt", ns_dc1 + ns_mrec, details=f"ok={M_rec == M}")

                st.code(
                    "\n".join(
                        [
                            f"Clé publique Q={pub}",
                            f"M={M}",
                            f"k={k}",
                            f"C1={C1}",
                            f"C2={C2}",
                            f"M_rec={M_rec}",
                            f"OK={M_rec == M}",
                        ]
                    )
                )
                st.caption(
                    f"Temps exact (ns): C1={ns_c1}, kQ={ns_kq}, C2={ns_c2}, dC1={ns_dc1}, Mrec={ns_mrec}"
                )
            except Exception as ex:
                st.error(str(ex))


def attacks_tab():
    st.subheader("Attaques (démo)")

    st.markdown("**RSA — Pollard's Rho (factorisation)**")
    n = st.number_input("n (à factoriser)", min_value=3, value=323, step=1)
    rho_btn = st.button("Lancer Pollard's Rho", type="primary", use_container_width=True)
    if rho_btn:
        try:
            (pq, ns) = _perf_call(factor_rsa, int(n))
            # factor_rsa appelle pollard_rho décoré; on prend l'exact de perf_call ici
            _add_timing("ATK", "pollard_rho", ns, details=f"n={n}")
            p, q = pq
            if p is None:
                st.error("Échec de factorisation.")
            else:
                st.success(f"Factorisation: {n} = {p} × {q}")
            st.caption(f"Temps exact: {ns} ns ({ns/1e6:.3f} ms)")
        except Exception as ex:
            st.error(str(ex))

    st.divider()
    st.markdown("**ECC — BSGS (logarithme discret)**")
    c1, c2 = st.columns([1, 1])
    with c1:
        a = st.number_input("a (attaque)", value=2, step=1, key="atk_a")
        b = st.number_input("b (attaque)", value=2, step=1, key="atk_b")
        p = st.number_input("p (attaque)", min_value=3, value=17, step=1, key="atk_p")
    with c2:
        gx = st.number_input("Gx (attaque)", value=5, step=1, key="atk_gx")
        gy = st.number_input("Gy (attaque)", value=1, step=1, key="atk_gy")
        order = st.number_input("ordre", min_value=2, value=19, step=1, key="atk_order")
        k_real = st.number_input("clé privée k (pour générer Q)", min_value=0, value=9, step=1, key="atk_k")

    bsgs_btn = st.button("Lancer BSGS", use_container_width=True)
    if bsgs_btn:
        try:
            curve = Curve(int(a), int(b), int(p), "ATK")
            G = Point(int(gx), int(gy), curve)
            Q = scalar_mult(int(k_real), G, curve)
            k_found, ns = _perf_call(bsgs_ecc, G, Q, curve, int(order))
            _add_timing("ATK", "bsgs_ecc", ns, details=f"found={k_found}")
            st.code(f"Q = k*G = {Q}\nTrouvé k = {k_found}\nOK = {k_found == int(k_real)}")
            st.caption(f"Temps exact: {ns} ns ({ns/1e6:.3f} ms)")
        except Exception as ex:
            st.error(str(ex))


def validation_tab():
    st.subheader("Validation croisée (RSA vs ECC)")
    df = _df_timings()
    if df.empty:
        st.info("Aucun timing enregistré pour le moment. Lancez des opérations dans les onglets RSA/ECC/Attaques.")
        return

    st.markdown("**Table des temps**")
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.markdown("**Comparaison (ms)**")
    df2 = df[df["system"].isin(["RSA", "ECC"])].copy()
    if df2.empty:
        st.info("Aucun timing RSA/ECC trouvé (seulement attaques).")
    else:
        chart = (
            df2.groupby(["system", "operation"], as_index=False)["elapsed_ms"]
            .mean()
            .sort_values(["operation", "system"])
        )
        st.bar_chart(chart, x="operation", y="elapsed_ms", color="system")

    st.divider()
    st.markdown("**Nettoyage**")
    if st.button("Effacer tous les timings", use_container_width=True):
        st.session_state.timings = []
        st.rerun()


def main():
    st.set_page_config(page_title="CryptoValidator — Streamlit", layout="wide")
    _init_state()

    st.title("CryptoValidator — Interface Streamlit")
    st.caption("RSA | ECC (courbes non standards) | Attaques | Validation croisée — avec temps d'exécution exact par opération.")

    tabs = st.tabs(["RSA", "ECC", "Attaques", "Validation croisée"])
    with tabs[0]:
        rsa_tab()
    with tabs[1]:
        ecc_tab()
    with tabs[2]:
        attacks_tab()
    with tabs[3]:
        validation_tab()


if __name__ == "__main__":
    main()

