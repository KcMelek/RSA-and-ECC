"""
=============================================================================
MODULE 4 : GÉNÉRATEUR DE RAPPORT MARKDOWN — Pure Python
=============================================================================
Auteur  : Architecte Cryptographie
Desc    : Collecte les métriques de performance et génère un rapport comparatif
          RSA vs ECC au format Markdown.
          Calcule le ratio d'efficacité R = T_RSA / T_ECC.
=============================================================================
"""

import datetime
import os


class ReportEngine:
    """
    Collecte des timings et génère un tableau comparatif Markdown.

    Usage :
        report = ReportEngine()
        report.add_metric("RSA", "set_params", 0.000123, "Configuration clés")
        report.add_metric("ECC", "generate_keypair", 0.000045, "Génération clés")
        report.set_attack_result("Pollard's Rho", n=323, factor=17, time=0.001)
        report.set_attack_result("BSGS", n=19, key=7, time=0.003)
        report.generate(filename="rapport_crypto.md")
    """

    def __init__(self):
        self._metrics: list[dict] = []
        self._attacks: list[dict] = []
        self._rsa_total  = 0.0
        self._ecc_total  = 0.0
        self._extra_info: list[str] = []

    # ─────────────────────────────────────────────────────────────────────────
    #  API publique
    # ─────────────────────────────────────────────────────────────────────────

    def add_metric(self, system: str, operation: str, elapsed: float, description: str = ""):
        """
        Ajoute une métrique de performance.

        Paramètres :
            system      : "RSA" ou "ECC"
            operation   : nom de l'opération
            elapsed     : temps en secondes (float)
            description : description courte
        """
        self._metrics.append({
            "system"     : system,
            "operation"  : operation,
            "elapsed"    : elapsed,
            "description": description,
        })
        if system.upper() == "RSA":
            self._rsa_total += elapsed
        elif system.upper() == "ECC":
            self._ecc_total += elapsed

    def set_attack_result(self, attack: str, result_info: str, elapsed: float):
        """
        Enregistre le résultat d'une attaque.

        Paramètres :
            attack      : nom de l'attaque
            result_info : résumé du résultat
            elapsed     : temps d'exécution
        """
        self._attacks.append({
            "attack"     : attack,
            "result"     : result_info,
            "elapsed"    : elapsed,
        })

    def add_info(self, line: str):
        """Ajoute une ligne d'information libre dans la section Contexte."""
        self._extra_info.append(line)

    def generate(self, filename: str = "rapport_crypto.md", output_dir: str = ".") -> str:
        """
        Génère le rapport Markdown complet et le sauvegarde sur disque.

        Retourne : le contenu du rapport (str).
        """
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Calcul du ratio d'efficacité ─────────────────────────────────
        if self._ecc_total > 0:
            ratio = self._rsa_total / self._ecc_total
        else:
            ratio = float("inf")

        lines = []

        # ── En-tête ───────────────────────────────────────────────────────
        lines += [
            "# 🔐 Rapport Comparatif Cryptographique",
            "",
            f"> **Généré le :** {now}  ",
            f"> **Outil :** CryptoValidator — Pure Python  ",
            f"> **Aucune dépendance externe (OpenSSL / hazmat / pycryptodome)**",
            "",
            "---",
            "",
        ]

        # ── Section Contexte ──────────────────────────────────────────────
        if self._extra_info:
            lines += ["## ⚙️ Contexte de l'Expérience", ""]
            for info in self._extra_info:
                lines.append(f"- {info}")
            lines += ["", "---", ""]

        # ── Tableau principal ─────────────────────────────────────────────
        lines += [
            "## 📊 Tableau Comparatif des Performances",
            "",
            "| Système | Opération | Temps (s) | Temps (µs) | Description |",
            "|---------|-----------|-----------|------------|-------------|",
        ]

        for m in self._metrics:
            us = m["elapsed"] * 1_000_000
            lines.append(
                f"| **{m['system']}** | `{m['operation']}` "
                f"| {m['elapsed']:.6f} | {us:.2f} µs | {m['description']} |"
            )

        lines += ["", "---", ""]

        # ── Section Ratio ─────────────────────────────────────────────────
        lines += [
            "## ⚡ Analyse du Ratio d'Efficacité",
            "",
            "$$",
            r"R = \frac{T_{\text{RSA}}}{T_{\text{ECC}}}",
            "$$",
            "",
            "| Métrique | Valeur |",
            "|----------|--------|",
            f"| Temps total RSA | {self._rsa_total:.6f} s ({self._rsa_total * 1e6:.2f} µs) |",
            f"| Temps total ECC | {self._ecc_total:.6f} s ({self._ecc_total * 1e6:.2f} µs) |",
            f"| **Ratio R = T_RSA / T_ECC** | **{ratio:.4f}×** |",
            "",
        ]

        if ratio > 1:
            lines.append(
                f"> ⚠️ **Interprétation :** RSA est **{ratio:.2f}× plus lent** que ECC "
                f"pour ces paramètres. ECC offre une meilleure efficacité à sécurité équivalente."
            )
        else:
            lines.append(
                f"> ✅ **Interprétation :** RSA est **{1/ratio:.2f}× plus rapide** que ECC "
                f"sur ces paramètres (atypique pour de grands paramètres)."
            )

        lines += ["", "---", ""]

        # ── Section Attaques ──────────────────────────────────────────────
        if self._attacks:
            lines += [
                "## 🚨 Résultats des Attaques",
                "",
                "| Attaque | Résultat | Temps (s) | Statut |",
                "|---------|----------|-----------|--------|",
            ]
            for a in self._attacks:
                success = "✅ Succès" if "✓" in a["result"] or "retrouvé" in a["result"].lower() \
                          or "trouvé" in a["result"].lower() else "❌ Échec"
                lines.append(
                    f"| **{a['attack']}** | {a['result']} | {a['elapsed']:.6f} s | {success} |"
                )
            lines += ["", "---", ""]

        # ── Résumé de sécurité ────────────────────────────────────────────
        lines += [
            "## 🛡️ Recommandations de Sécurité",
            "",
            "| Critère | RSA | ECC |",
            "|---------|-----|-----|",
            "| Taille de clé recommandée | 2048-4096 bits | 256-521 bits |",
            "| Problème difficile | Factorisation entière | Logarithme discret ECC |",
            "| Attaque classique | Pollard's Rho / NFS | Baby-Step Giant-Step |",
            "| Efficacité relative | Référence | ~6× plus rapide (même sécurité) |",
            "| Compatibilité | Universelle | Dépend de la courbe |",
            "",
            "> 📌 **Note :** Les paramètres utilisés dans cette démonstration (p=17, q=19) "
            "sont **délibérément faibles** pour illustrer les attaques. "
            "En production, utilisez RSA-3072+ ou NIST P-256 / Curve25519.",
            "",
            "---",
            "",
            "## 📚 Références Mathématiques",
            "",
            "- **RSA** : Rivest, Shamir, Adleman — *A Method for Obtaining Digital Signatures "
            "and Public-Key Cryptosystems*, CACM 1978",
            "- **ECC** : Koblitz, Miller — *Elliptic Curve Cryptography*, 1985",
            "- **Pollard ρ** : Pollard — *A Monte Carlo method for factorization*, 1975",
            "- **BSGS** : Shanks — *Class number, a theory of factorization*, 1971",
            "",
            "---",
            "*Rapport généré par CryptoValidator — 100% Pure Python*",
        ]

        # ── Écriture sur disque ───────────────────────────────────────────
        content = "\n".join(lines)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"\n  [RAPPORT] Fichier généré : {filepath}")
        return content

    def print_summary(self):
        """Affiche un résumé dans le terminal."""
        print("\n" + "═" * 60)
        print("  RÉSUMÉ PERFORMANCES")
        print("═" * 60)
        for m in self._metrics:
            print(f"  {m['system']:<5} │ {m['operation']:<25} │ {m['elapsed']:.6f} s")

        if self._ecc_total > 0:
            ratio = self._rsa_total / self._ecc_total
            print("─" * 60)
            print(f"  T_RSA = {self._rsa_total:.6f} s")
            print(f"  T_ECC = {self._ecc_total:.6f} s")
            print(f"  R = T_RSA / T_ECC = {ratio:.4f}×")
        print("═" * 60)
