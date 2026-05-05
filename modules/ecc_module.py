"""
=============================================================================
MODULE 2 : ECC UNIVERSEL (COURBES NON-STANDARDS) — Pure Python
=============================================================================
Auteur  : Architecte Cryptographie
Desc    : Arithmétique sur courbe elliptique de Weierstrass y² ≡ x³+ax+b (mod p).
          Supporte n'importe quel triplet (a, b, p).
          Protocoles : ECDH + Signature simplifiée (ECDSA-like).
=============================================================================
"""

import random
import hashlib
import time
import functools


# ─────────────────────────────────────────────────────────────────────────────
#  DÉCORATEUR TIMER (copie locale pour l'indépendance du module)
# ─────────────────────────────────────────────────────────────────────────────

def timer(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        t_start = time.perf_counter()
        result  = func(*args, **kwargs)
        elapsed = time.perf_counter() - t_start
        wrapper._last_elapsed = elapsed
        # ASCII-only to avoid Windows cp1252 encoding issues
        print(f"  [TIMER] {func.__qualname__:<35} -> {elapsed:.6f} s")
        return result
    wrapper._last_elapsed = 0.0
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
#  INVERSE MODULAIRE (nécessaire pour l'arithmétique ECC)
# ─────────────────────────────────────────────────────────────────────────────

def _mod_inv(a: int, p: int) -> int:
    """
    Inverse modulaire via l'algorithme d'Euclide étendu.
    Retourne a^{-1} mod p. Lève ZeroDivisionError si a ≡ 0 (mod p).
    """
    if a % p == 0:
        raise ZeroDivisionError(f"Impossible d'inverser 0 mod {p}.")
    old_r, r = a % p, p
    old_s, s = 1, 0
    while r != 0:
        q     = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % p


# ─────────────────────────────────────────────────────────────────────────────
#  CLASSE Curve
# ─────────────────────────────────────────────────────────────────────────────

class Curve:
    """
    Courbe elliptique de Weierstrass courte :  y² ≡ x³ + a·x + b  (mod p)

    Paramètres :
        a, b : coefficients de la courbe  (entiers)
        p    : nombre premier (corps fini F_p)
        name : nom optionnel pour l'affichage

    La courbe est non-singulière si  4a³ + 27b² ≢ 0 (mod p).
    """

    def __init__(self, a: int, b: int, p: int, name: str = "Custom"):
        self.a    = a % p
        self.b    = b % p
        self.p    = p
        self.name = name
        self._validate()

    def _validate(self):
        discriminant = (4 * pow(self.a, 3, self.p) + 27 * pow(self.b, 2, self.p)) % self.p
        if discriminant == 0:
            raise ValueError(
                f"Courbe singulière détectée : 4a³+27b² ≡ 0 (mod {self.p}). "
                f"Choisissez d'autres paramètres."
            )

    def is_on_curve(self, P: "Point | None") -> bool:
        """Vérifie si P appartient à la courbe (y² ≡ x³+ax+b mod p)."""
        if P is None:                              # Point à l'infini
            return True
        lhs = pow(P.y, 2, self.p)
        rhs = (pow(P.x, 3, self.p) + self.a * P.x + self.b) % self.p
        return lhs == rhs

    def __repr__(self) -> str:
        return (
            f"Curve[{self.name}] : y^2 = x^3 + {self.a}*x + {self.b}  (mod {self.p})"
        )

    def list_points(self) -> list["Point"]:
        """
        Énumère tous les points affines de la courbe (brute-force, usage debug/petits p).
        Complexité O(p) — uniquement pour p petit.
        """
        points = []
        for x in range(self.p):
            rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
            for y in range(self.p):
                if pow(y, 2, self.p) == rhs:
                    points.append(Point(x, y, self))
        return points


# ─────────────────────────────────────────────────────────────────────────────
#  CLASSE Point
# ─────────────────────────────────────────────────────────────────────────────

class Point:
    """
    Point affine (x, y) sur une Curve.

    Le point à l'infini (neutre additif) est représenté par None au niveau
    des fonctions d'addition — ou par Point.infinity(curve).

    Attributs :
        x, y  : coordonnées (entiers mod p)
        curve : référence à la Curve parente
    """

    def __init__(self, x: int, y: int, curve: Curve):
        self.x     = x % curve.p
        self.y     = y % curve.p
        self.curve = curve
        if not curve.is_on_curve(self):
            raise ValueError(
                f"Le point ({x}, {y}) n'est pas sur la courbe {curve}."
            )

    @classmethod
    def infinity(cls, curve: Curve) -> None:
        """Retourne None (convention pour le point à l'infini O)."""
        return None

    def __eq__(self, other) -> bool:
        if other is None:
            return False
        return self.x == other.x and self.y == other.y and self.curve.p == other.curve.p

    def __neg__(self) -> "Point | None":
        """Inverse additif : -(x, y) = (x, p-y)."""
        if self.y == 0:
            return None   # Point d'ordre 2 : son inverse est lui-même
        return Point(self.x, self.curve.p - self.y, self.curve)

    def __repr__(self) -> str:
        return f"Point({self.x}, {self.y})"


# ─────────────────────────────────────────────────────────────────────────────
#  ARITHMÉTIQUE SUR COURBE ELLIPTIQUE
# ─────────────────────────────────────────────────────────────────────────────

def point_add(P: "Point | None", Q: "Point | None", curve: Curve) -> "Point | None":
    """
    Addition de deux points sur la courbe elliptique.

    Cas traités :
      1. P = O  ->  Q
      2. Q = O  ->  P
      3. P = -Q ->  O  (points symétriques)
      4. P = Q  ->  doublement (tangente)
      5. Cas général (corde)

    Formules (sur F_p, P≠Q) :
        λ = (y_Q - y_P) · (x_Q - x_P)^{-1}  mod p
        x_R = λ² - x_P - x_Q                  mod p
        y_R = λ(x_P - x_R) - y_P              mod p
    """
    # ── Cas neutres ──────────────────────────────────────────────────────────
    if P is None:
        return Q
    if Q is None:
        return P

    # ── Même abscisse ────────────────────────────────────────────────────────
    if P.x == Q.x:
        if P.y != Q.y or P.y == 0:
            return None          # P + (-P) = O  ou  point d'ordre 2
        else:
            return point_double(P, curve)   # P == Q

    # ── Cas général ──────────────────────────────────────────────────────────
    p   = curve.p
    lam = ((Q.y - P.y) * _mod_inv(Q.x - P.x, p)) % p
    x_r = (lam * lam - P.x - Q.x) % p
    y_r = (lam * (P.x - x_r) - P.y) % p
    return Point(x_r, y_r, curve)


def point_double(P: "Point | None", curve: Curve) -> "Point | None":
    """
    Doublement d'un point P : Q = 2P (tangente à la courbe).

    Formules :
        λ = (3·x_P² + a) · (2·y_P)^{-1}  mod p
        x_R = λ² - 2·x_P                   mod p
        y_R = λ(x_P - x_R) - y_P           mod p
    """
    if P is None:
        return None
    if P.y == 0:
        return None       # Tangente verticale -> point à l'infini

    p   = curve.p
    lam = ((3 * P.x * P.x + curve.a) * _mod_inv(2 * P.y, p)) % p
    x_r = (lam * lam - 2 * P.x) % p
    y_r = (lam * (P.x - x_r) - P.y) % p
    return Point(x_r, y_r, curve)


def scalar_mult(k: int, P: "Point | None", curve: Curve) -> "Point | None":
    """
    Multiplication scalaire k·P par l'algorithme Double-and-Add.

    Algorithme (left-to-right, bit par bit) :
        R = O
        pour chaque bit de k (du MSB au LSB) :
            R = 2R
            si bit = 1 : R = R + P

    Complexité : O(log k) additions/doublements.

    Paramètres :
        k : scalaire entier (clé privée ou facteur)
        P : point générateur
    Retourne  : Q = k·P (ou None si résultat = O)
    """
    if k == 0 or P is None:
        return None
    if k < 0:
        return scalar_mult(-k, -P, curve)

    R = None    # Point à l'infini (neutre)
    for bit in bin(k)[2:]:          # itère du MSB au LSB
        R = point_double(R, curve)
        if bit == '1':
            R = point_add(R, P, curve)
    return R


# ─────────────────────────────────────────────────────────────────────────────
#  PROTOCOLE ECDH
# ─────────────────────────────────────────────────────────────────────────────

class ECDH:
    """
    Échange de clés Diffie-Hellman sur courbe elliptique.

    Protocole :
        1. Alice choisit k_A aléatoire  ->  Q_A = k_A · G
        2. Bob   choisit k_B aléatoire  ->  Q_B = k_B · G
        3. Alice calcule S = k_A · Q_B = k_A · k_B · G
        4. Bob   calcule S = k_B · Q_A = k_B · k_A · G
        -> même secret partagé S

    Paramètres nécessaires : point générateur G et son ordre (approximatif).
    """

    def __init__(self, curve: Curve, G: Point, order: int):
        self.curve = curve
        self.G     = G
        self.order = order

    @timer
    def generate_keypair(self) -> tuple[int, "Point"]:
        """
        Génère une paire (clé_privée k, clé_publique Q = k·G).
        k ∈ [1, order-1] (aléatoire sécurisé).
        """
        k = random.randint(1, self.order - 1)
        Q = scalar_mult(k, self.G, self.curve)
        return k, Q

    @timer
    def shared_secret(self, priv: int, pub: "Point") -> "Point | None":
        """
        Calcule le secret partagé : S = priv · pub.
        La coordonnée x de S sert généralement de clé de session.
        """
        return scalar_mult(priv, pub, self.curve)


# ─────────────────────────────────────────────────────────────────────────────
#  PROTOCOLE SIGNATURE SIMPLIFIÉE (ECDSA-like)
# ─────────────────────────────────────────────────────────────────────────────

def _hash_message(message: str) -> int:
    """Hash SHA-256 du message -> entier."""
    h = hashlib.sha256(message.encode()).hexdigest()
    return int(h, 16)


class ECSign:
    """
    Signature numérique simplifiée sur courbe elliptique (ECDSA-like).

    Génération de signature (r, s) pour le message m :
        1. Choisir k aléatoire ∈ [1, order-1]
        2. R = k·G  ;  r = R.x mod order
        3. s = k^{-1}·(hash(m) + d·r) mod order    (d = clé privée)
        4. Signature = (r, s)

    Vérification :
        1. w  = s^{-1} mod order
        2. u1 = hash(m)·w mod order
        3. u2 = r·w mod order
        4. X  = u1·G + u2·Q   (Q = clé publique)
        5. Valide si  X.x mod order == r
    """

    def __init__(self, curve: Curve, G: Point, order: int):
        self.curve = curve
        self.G     = G
        self.order = order

    def _ext_gcd(self, a, b):
        old_r, r = a, b
        old_s, s = 1, 0
        while r:
            q = old_r // r
            old_r, r = r, old_r - q * r
            old_s, s = s, old_s - q * s
        return old_r, old_s

    def _inv(self, a, n):
        _, x = self._ext_gcd(a % n, n)
        return x % n

    @timer
    def sign(self, message: str, private_key: int) -> tuple[int, int]:
        """
        Signe le message avec la clé privée.
        Retourne (r, s).
        """
        n   = self.order
        z   = _hash_message(message) % n
        r, s = 0, 0

        while r == 0 or s == 0:
            k = random.randint(1, n - 1)
            R = scalar_mult(k, self.G, self.curve)
            if R is None:
                continue
            r = R.x % n
            if r == 0:
                continue
            k_inv = self._inv(k, n)
            s = (k_inv * (z + private_key * r)) % n

        return r, s

    @timer
    def verify(self, message: str, signature: tuple[int, int], public_key: "Point") -> bool:
        """
        Vérifie la signature (r, s) du message avec la clé publique.
        Retourne True si valide, False sinon.
        """
        n    = self.order
        r, s = signature
        if not (1 <= r < n and 1 <= s < n):
            return False

        z  = _hash_message(message) % n
        w  = self._inv(s, n)
        u1 = (z * w) % n
        u2 = (r * w) % n

        X = point_add(
            scalar_mult(u1, self.G, self.curve),
            scalar_mult(u2, public_key, self.curve),
            self.curve
        )
        if X is None:
            return False
        return (X.x % n) == r
