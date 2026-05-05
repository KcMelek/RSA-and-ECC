"""
=============================================================================
MODULE 1 : RSA DYNAMIQUE — Pure Python
=============================================================================
Auteur  : Architecte Cryptographie
Desc    : Chiffrement RSA avec calcul d'inverse modulaire via Euclide étendu.
          Chaque méthode publique est décorée @timer (précision 10^-6 s).
=============================================================================
"""

import time
import functools
import math
import hashlib
import json
import base64


# ─────────────────────────────────────────────────────────────────────────────
#  DÉCORATEUR TIMER
# ─────────────────────────────────────────────────────────────────────────────

def timer(func):
    """
    Décorateur mesurant le temps d'exécution de la fonction décorée.
    Affiche : [TIMER] <nom> terminé en X.XXXXXX s
    Injecte l'attribut func._last_elapsed (float) après chaque appel.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        t_start = time.perf_counter()
        result = func(*args, **kwargs)
        t_end = time.perf_counter()
        elapsed = t_end - t_start
        # Stockage de la dernière durée sur l'objet wrapper pour le rapport
        wrapper._last_elapsed = elapsed
        # ASCII-only to avoid Windows cp1252 encoding issues
        print(f"  [TIMER] {func.__qualname__:<30} -> {elapsed:.6f} s")
        return result
    wrapper._last_elapsed = 0.0
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
#  ALGORITHME D'EUCLIDE ÉTENDU (itératif, sans récursion)
# ─────────────────────────────────────────────────────────────────────────────

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Retourne (gcd, x, y) tel que  a*x + b*y = gcd(a, b).
    Implémentation itérative de l'algorithme d'Euclide étendu.

    Exemple :
        extended_gcd(35, 15) -> (5, 1, -2)  car 35·1 + 15·(-2) = 5
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t  # gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
    """
    Calcule e^{-1} mod phi via l'algorithme d'Euclide étendu.
    Lève ValueError si e et phi ne sont pas premiers entre eux.
    """
    gcd, x, _ = extended_gcd(e % phi, phi)
    if gcd != 1:
        raise ValueError(
            f"Impossible de calculer l'inverse : gcd({e}, {phi}) = {gcd} ≠ 1. "
            f"Vérifiez que e et φ(n) sont premiers entre eux."
        )
    return x % phi


def is_prime(n: int) -> bool:
    """Test de primalité naïf (suffisant pour p, q de démonstration)."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.isqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  CLASSE RSAEngine
# ─────────────────────────────────────────────────────────────────────────────

class RSAEngine:
    """
    Moteur RSA dynamique.

    Usage :
        rsa = RSAEngine()
        rsa.set_params(p=17, q=19, e=7)
        c = rsa.encrypt(42)
        m = rsa.decrypt(c)
    """

    def __init__(self):
        self.p = None
        self.q = None
        self.e = None
        self.n = None
        self.phi_n = None
        self.d = None
        self._timings: dict[str, float] = {}

    # ── set_params ────────────────────────────────────────────────────────────

    @timer
    def set_params(self, p: int, q: int, e: int) -> None:
        """
        Configure le moteur RSA avec les premiers p, q et l'exposant e.

        Paramètres :
            p : premier nombre premier
            q : second nombre premier (p ≠ q)
            e : exposant public, 1 < e < φ(n), gcd(e, φ(n)) = 1

        Calculs effectués :
            n    = p · q
            φ(n) = (p-1)(q-1)
            d    = e^{-1} mod φ(n)
        """
        # ── Validation des entrées ──────────────────────────────────────────
        if not is_prime(p):
            raise ValueError(f"p={p} n'est pas premier.")
        if not is_prime(q):
            raise ValueError(f"q={q} n'est pas premier.")
        if p == q:
            raise ValueError("p et q doivent être distincts.")

        self.p = p
        self.q = q
        self.e = e

        # ── Calculs RSA ────────────────────────────────────────────────────
        self.n     = p * q
        self.phi_n = (p - 1) * (q - 1)

        if not (1 < e < self.phi_n):
            raise ValueError(
                f"L'exposant e={e} doit satisfaire 1 < e < φ(n)={self.phi_n}."
            )

        self.d = mod_inverse(e, self.phi_n)

        # ── Rapport ───────────────────────────────────────────────────────
        print(f"\n  +-- RSA Parametres -------------------------------------")
        print(f"  |  p      = {p}")
        print(f"  |  q      = {q}")
        print(f"  |  n      = p*q = {self.n}")
        print(f"  |  phi(n) = (p-1)(q-1) = {self.phi_n}")
        print(f"  |  e      = {e}")
        print(f"  |  d      = e^-1 mod phi(n) = {self.d}")
        print(f"  |  Verif  : (e*d) mod phi(n) = {(e * self.d) % self.phi_n}  (doit etre 1)")
        print(f"  +------------------------------------------------------")

    # ── encrypt ───────────────────────────────────────────────────────────────

    @timer
    def encrypt(self, message: int) -> int:
        """
        Chiffre un entier m par RSA : c = m^e mod n.

        Contrainte : 0 <= m < n
        Retourne   : c (chiffré)
        """
        self._check_params_set()
        if not (0 <= message < self.n):
            raise ValueError(
                f"Message {message} hors plage [0, {self.n - 1}]. "
                    f"Assurez-vous que 0 <= message < n."
            )
        # pow(base, exp, mod) utilise l'exponentiation rapide de Python
        return pow(message, self.e, self.n)

    # ── decrypt ───────────────────────────────────────────────────────────────

    @timer
    def decrypt(self, ciphertext: int) -> int:
        """
        Déchiffre un entier c par RSA : m = c^d mod n.

        Retourne : m (message original)
        """
        self._check_params_set()
        return pow(ciphertext, self.d, self.n)

    # ── Utilitaires ───────────────────────────────────────────────────────────

    def _check_params_set(self):
        if self.n is None:
            raise RuntimeError(
                "Paramètres non initialisés. Appelez d'abord set_params(p, q, e)."
            )

    def get_public_key(self) -> tuple[int, int]:
        """Retourne (e, n)."""
        self._check_params_set()
        return (self.e, self.n)

    def get_private_key(self) -> tuple[int, int]:
        """Retourne (d, n)."""
        self._check_params_set()
        return (self.d, self.n)

    def get_timings(self) -> dict[str, float]:
        """Récupère les derniers timings enregistrés par @timer."""
        return {
            "set_params": self.set_params._last_elapsed,
            "encrypt"   : self.encrypt._last_elapsed,
            "decrypt"   : self.decrypt._last_elapsed,
            "sign"      : getattr(self.sign, "_last_elapsed", 0.0),
            "verify"    : getattr(self.verify, "_last_elapsed", 0.0),
            "encrypt_text": getattr(self.encrypt_text, "_last_elapsed", 0.0),
            "decrypt_text": getattr(self.decrypt_text, "_last_elapsed", 0.0),
        }

    # ── Signature RSA (sans padding, démonstration) ───────────────────────────

    def _hash_to_int_mod_n(self, message: str) -> int:
        self._check_params_set()
        h = hashlib.sha256(message.encode("utf-8")).digest()
        return int.from_bytes(h, "big") % self.n

    @timer
    def sign(self, message: str) -> int:
        """
        Signature RSA (démonstration) :
            s = H(m)^d mod n
        où H = SHA-256, sans padding (NON sécurisé en production).
        """
        h = self._hash_to_int_mod_n(message)
        return pow(h, self.d, self.n)

    @timer
    def verify(self, message: str, signature: int) -> bool:
        """
        Vérification RSA (démonstration) :
            H(m) ?= s^e mod n
        """
        h = self._hash_to_int_mod_n(message)
        return pow(signature, self.e, self.n) == h

    # ── Chiffrement / déchiffrement texte (chunking bytes -> int) ─────────────

    def _max_chunk_bytes(self) -> int:
        self._check_params_set()
        # On impose chunk_int < n. On prend nb_octets strictement inférieur à n.
        # Pour de petits n (démo), ça tombe souvent à 1 octet.
        return max(1, (self.n.bit_length() - 1) // 8)

    @timer
    def encrypt_text(self, plaintext: str) -> str:
        """
        Chiffre un texte UTF-8 en une payload ASCII (base64 JSON) portable.
        Retourne une chaîne qui encode:
          - chunks ciphertext (liste d'entiers)
          - longueur originale en octets
          - taille de chunk
        """
        self._check_params_set()
        data = plaintext.encode("utf-8")
        chunk_bytes = self._max_chunk_bytes()
        if chunk_bytes <= 0:
            raise ValueError("n trop petit pour chiffrer un texte.")

        chunks: list[int] = []
        for i in range(0, len(data), chunk_bytes):
            block = data[i:i + chunk_bytes]
            m_int = int.from_bytes(block, "big")
            if m_int >= self.n:
                raise ValueError(
                    f"Bloc >= n (m={m_int}, n={self.n}). "
                    f"Utilisez des paramètres RSA plus grands."
                )
            chunks.append(pow(m_int, self.e, self.n))

        payload = {
            "v": 1,
            "n": self.n,
            "chunk_bytes": chunk_bytes,
            "length": len(data),
            "chunks": chunks,
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    @timer
    def decrypt_text(self, ciphertext_payload: str) -> str:
        """
        Déchiffre la payload produite par encrypt_text().
        """
        self._check_params_set()
        try:
            raw = base64.b64decode(ciphertext_payload.encode("ascii"), validate=True)
            payload = json.loads(raw.decode("utf-8"))
        except Exception as ex:
            raise ValueError("Payload invalide (attendu: base64(JSON)).") from ex

        if payload.get("v") != 1:
            raise ValueError("Version payload non supportée.")
        if int(payload.get("n")) != int(self.n):
            raise ValueError(
                f"Payload RSA incompatible: n(payload)={payload.get('n')} != n(courant)={self.n}."
            )

        chunk_bytes = int(payload["chunk_bytes"])
        total_len = int(payload["length"])
        chunks = payload["chunks"]

        out = bytearray()
        for c in chunks:
            m_int = pow(int(c), self.d, self.n)
            out.extend(int(m_int).to_bytes(chunk_bytes, "big"))

        return bytes(out[:total_len]).decode("utf-8", errors="strict")
