# 🔐 Rapport Comparatif Cryptographique

> **Généré le :** 2026-05-04 18:45:07  
> **Outil :** CryptoValidator — Pure Python  
> **Aucune dépendance externe (OpenSSL / hazmat / pycryptodome)**

---

## ⚙️ Contexte de l'Expérience

- RSA: p=17,q=19,n=323,e=7,d=247
- ECC: y^2=x^3+2x+2 mod 17, G=(5,1), ordre=19

---

## 📊 Tableau Comparatif des Performances

| Système | Opération | Temps (s) | Temps (µs) | Description |
|---------|-----------|-----------|------------|-------------|
| **RSA** | `set_params` | 0.097317 | 97317.20 µs | n=323,d=247 |
| **RSA** | `encrypt` | 0.000009 | 9.40 µs | c=253 |
| **RSA** | `decrypt` | 0.000011 | 10.70 µs | m=42 |
| **ECC** | `generate_keypair` | 0.000028 | 28.20 µs | Paire Alice |
| **ECC** | `shared_secret` | 0.000041 | 41.40 µs | ECDH |
| **ECC** | `sign` | 0.000093 | 92.80 µs | Signature |
| **ECC** | `verify` | 0.000107 | 107.00 µs | Verification |

---

## ⚡ Analyse du Ratio d'Efficacité

$$
R = \frac{T_{\text{RSA}}}{T_{\text{ECC}}}
$$

| Métrique | Valeur |
|----------|--------|
| Temps total RSA | 0.097337 s (97337.30 µs) |
| Temps total ECC | 0.000269 s (269.40 µs) |
| **Ratio R = T_RSA / T_ECC** | **361.3114×** |

> ⚠️ **Interprétation :** RSA est **361.31× plus lent** que ECC pour ces paramètres. ECC offre une meilleure efficacité à sécurité équivalente.

---

## 🚨 Résultats des Attaques

| Attaque | Résultat | Temps (s) | Statut |
|---------|----------|-----------|--------|
| **Pollard's Rho** | n=323=19x17 | 0.023830 s | ❌ Échec |
| **BSGS ECC** | k=9 retrouve | 0.120846 s | ❌ Échec |

---

## 🛡️ Recommandations de Sécurité

| Critère | RSA | ECC |
|---------|-----|-----|
| Taille de clé recommandée | 2048-4096 bits | 256-521 bits |
| Problème difficile | Factorisation entière | Logarithme discret ECC |
| Attaque classique | Pollard's Rho / NFS | Baby-Step Giant-Step |
| Efficacité relative | Référence | ~6× plus rapide (même sécurité) |
| Compatibilité | Universelle | Dépend de la courbe |

> 📌 **Note :** Les paramètres utilisés dans cette démonstration (p=17, q=19) sont **délibérément faibles** pour illustrer les attaques. En production, utilisez RSA-3072+ ou NIST P-256 / Curve25519.

---

## 📚 Références Mathématiques

- **RSA** : Rivest, Shamir, Adleman — *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems*, CACM 1978
- **ECC** : Koblitz, Miller — *Elliptic Curve Cryptography*, 1985
- **Pollard ρ** : Pollard — *A Monte Carlo method for factorization*, 1975
- **BSGS** : Shanks — *Class number, a theory of factorization*, 1971

---
*Rapport généré par CryptoValidator — 100% Pure Python*