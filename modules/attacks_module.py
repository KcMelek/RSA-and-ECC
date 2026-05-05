"""
=============================================================================
MODULE 3 : ANALYSE D'ATTAQUES CRYPTOGRAPHIQUES — Pure Python
=============================================================================
Auteur  : Architecte Cryptographie
Desc    : Implémentation de deux attaques classiques :
            - Pollard's Rho   : factorisation de n (attaque RSA)
            - Baby-Step Giant-Step (BSGS) : logarithme discret ECC (attaque ECC)
=============================================================================
"""

import math
import time
import functools
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
#  DÉCORATEUR TIMER (copie locale)
# ─────────────────────────────────────────────────────────────────────────────

def timer(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        t_start = time.perf_counter()
        result  = func(*args, **kwargs)
        elapsed = time.perf_counter() - t_start
        wrapper._last_elapsed = elapsed
        # ASCII-only to avoid Windows cp1252 encoding issues
        print(f"  [TIMER] {func.__qualname__:<40} -> {elapsed:.6f} s")
        return result
    wrapper._last_elapsed = 0.0
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
#  ATTAQUE 1 : POLLARD'S RHO — Factorisation RSA
# ─────────────────────────────────────────────────────────────────────────────

def _gcd(a: int, b: int) -> int:
    """PGCD via l'algorithme d'Euclide."""
    while b:
        a, b = b, a % b
    return a


def _trace(trace: Optional[list[str]], msg: str) -> None:
    if trace is not None:
        trace.append(msg)


@timer
def pollard_rho(
    n: int,
    max_iter: int = 100_000,
    *,
    verbose: bool = False,
    log_every: int = 1,
    trace: Optional[list[str]] = None,
) -> Optional[int]:
    """
    Algorithme de Pollard's Rho pour factoriser n.

    Principe :
        On cherche x, y tels que gcd(|x - y|, n) ∈ (1, n).
        La fonction pseudo-aléatoire f(x) = (x² + c) mod n génère une séquence
        avec structure cyclique (tortue et lièvre de Floyd).

    Paramètres :
        n        : entier à factoriser (produit de deux premiers pour RSA)
        max_iter : nombre maximal d'itérations

    Retourne :
        Un facteur non-trivial de n, ou None si échec (réessayer avec c différent).

    Complexité : O(n^{1/4}) en moyenne.

    Exemple :
        pollard_rho(323)  # 323 = 17 x 19  ->  retourne 17 ou 19
    """
    if n % 2 == 0:
        _trace(trace, "n est pair -> facteur 2")
        return 2
    if n == 1:
        _trace(trace, "n=1 -> pas de facteur")
        return None

    for c in range(1, 20):          # Essai avec plusieurs constantes c
        x = 2
        y = 2
        d = 1

        f = lambda v: (v * v + c) % n    # Fonction pseudo-aléatoire

        _trace(trace, f"Essai avec c={c}, init x=y=2, d=1")
        iterations = 0
        while d == 1 and iterations < max_iter:
            x = f(x)            # Tortue : avance d'un pas
            y = f(f(y))         # Lièvre : avance de deux pas
            d = _gcd(abs(x - y), n)
            iterations += 1
            if verbose and log_every > 0 and (iterations % log_every == 0):
                _trace(trace, f"it={iterations}: x={x}, y={y}, |x-y|={abs(x-y)}, gcd={d}")

        if 1 < d < n:
            msg = f"Facteur trouvé: d={d} (apres {iterations} iterations, c={c})"
            _trace(trace, msg)
            print(f"  [Pollard rho] {msg}")
            return d
        # Si d == n : relancer avec un autre c
        msg = f"c={c} -> cycle degenere (d=n), changement de constante..."
        _trace(trace, msg)
        print(f"  [Pollard rho] {msg}")

    print(f"  [Pollard rho] Echec : n={n} resiste (peut-etre premier ou trop grand).")
    _trace(trace, f"Echec: aucun facteur trouve (max_iter={max_iter}, c=1..19)")
    return None


def factor_rsa(
    n: int,
    *,
    verbose: bool = False,
    log_every: int = 1,
    trace: Optional[list[str]] = None,
) -> tuple[Optional[int], Optional[int]]:
    """
    Factorise n = p·q en utilisant Pollard's Rho.
    Retourne (p, q) ou (None, None) si échec.
    """
    print(f"\n  == Factorisation RSA : n = {n} ==")
    _trace(trace, f"Debut factorisation: n={n}")
    p = pollard_rho(n, verbose=verbose, log_every=log_every, trace=trace)
    if p is None:
        return None, None
    q = n // p
    # Vérification
    if p * q == n:
        print(f"  [OK] Factorisation reussie : {n} = {p} x {q}")
        _trace(trace, f"OK: {n} = {p} x {q}")
        return p, q
    _trace(trace, "Echec verification: p*q != n")
    return None, None


# ─────────────────────────────────────────────────────────────────────────────
#  ATTAQUE 2 : BABY-STEP GIANT-STEP (BSGS) — Logarithme Discret ECC
# ─────────────────────────────────────────────────────────────────────────────

@timer
def bsgs_ecc(
    G,
    Q,
    curve,
    order: int,
    *,
    verbose: bool = False,
    log_every: int = 1,
    trace: Optional[list[str]] = None,
) -> Optional[int]:
    """
    Baby-Step Giant-Step pour résoudre le logarithme discret ECC :
        Trouver k tel que k·G = Q  sur la courbe.

    Algorithme :
        m = ceil(sqrt(order))
        Baby steps : précalcule {j·G : 0 <= j < m}
        Giant steps : cherche  Q - i·m·G  dans la table baby-steps
            -> si Q - i·m·G = j·G alors k = i·m + j

    Paramètres :
        G     : point générateur
        Q     : point public (clé connue de l'attaquant)
        curve : la courbe ECC
        order : ordre du groupe (ou borne supérieure)

    Retourne :
        k (entier) tel que k·G = Q, ou None si introuvable.

    Complexite : O(sqrt(order)) en temps et memoire.

    ⚠ Sécurité : efficace uniquement pour order < ~10^10 (groupes faibles).
    """
    from .ecc_module import scalar_mult, point_add, point_double

    if Q is None:                  # Q = O -> k = 0
        _trace(trace, "Q = O (point a l'infini) -> k = 0")
        return 0

    m = math.isqrt(order) + 1     # m = ceil(sqrt(order))

    # ── Baby Steps : table {j·G -> j} ─────────────────────────────────────
    print(f"  [BSGS] Calcul des baby-steps (m = {m})...")
    _trace(trace, f"Parametres: order={order}, m=ceil(sqrt(order))={m}")
    baby_table: dict = {}
    current = None                 # 0·G = O

    for j in range(m):
        key = (current.x, current.y) if current else "inf"
        baby_table[key] = j
        if verbose and log_every > 0 and (j % log_every == 0):
            _trace(trace, f"baby j={j}: P={current} (key={key})")
        current = point_add(current, G, curve)

    # ── Giant Steps : cherche Q - i·(m·G) ─────────────────────────────────
    mG     = scalar_mult(m, G, curve)         # m·G
    neg_mG = -mG if mG else None              # -(m·G) = (x, p-y)
    if neg_mG is None:
        neg_mG_obj = None
    else:
        neg_mG_obj = neg_mG

    print(f"  [BSGS] Recherche giant-steps (<= {m} iterations)...")
    _trace(trace, f"mG = {mG}, -mG = {neg_mG_obj}")
    gamma = Q                                 # Q - 0·(m·G)

    for i in range(m):
        key = (gamma.x, gamma.y) if gamma else "inf"
        if verbose and log_every > 0 and (i % log_every == 0):
            _trace(trace, f"giant i={i}: gamma={gamma} (key={key})")
        if key in baby_table:
            j = baby_table[key]
            k = i * m + j
            msg = f"Match: gamma == baby[j] avec (i={i}, j={j}) -> k={k}"
            _trace(trace, msg)
            print(f"  [BSGS OK] {msg}")
            return k
        gamma = point_add(gamma, neg_mG_obj, curve)

    print(f"  [BSGS ✗] Logarithme discret introuvable dans [0, {order}].")
    _trace(trace, f"Echec: aucun match dans i=0..{m-1}")
    return None
