# CryptoValidator

A pure Python cryptography educational tool that demonstrates RSA and Elliptic Curve Cryptography (ECC) from scratch — **zero external crypto dependencies**.

## Features

- **RSA Module** — Key generation, encryption, decryption, digital signatures, and extended Euclidean algorithm
- **ECC Module** — Custom curve definitions, point operations, ECDH key exchange, ECDSA-like signatures, and ElGamal point encryption
- **Cryptographic Attacks** — Pollard's Rho factorization (RSA) and Baby-Step Giant-Step discrete log (ECC)
- **Performance Timing** — Nanosecond-precision timing on every operation
- **Cross-Validation** — Compare RSA vs ECC performance side-by-side
- **Automated Reporting** — Generates Markdown reports with metrics and attack results

## Interfaces

| Interface | Command | Description |
|-----------|---------|-------------|
| CLI | `python crypto_tool.py` | Terminal-based demo of all modules |
| GUI | `python gui.py` | Dark-themed Tkinter app with 4 tabs |
| Web | `streamlit run streamlit_app.py` | Browser-based Streamlit dashboard |

## Project Structure

```
RSA-and-ECC/
├── crypto_tool.py        # CLI entry point
├── gui.py                # Tkinter GUI (dark cybersecurity theme)
├── streamlit_app.py      # Streamlit web interface
├── requirements.txt      # Streamlit dependencies (pandas, altair)
├── modules/
│   ├── rsa_module.py    # RSA: keys, encrypt, decrypt, sign, verify
│   ├── ecc_module.py    # ECC: curves, points, ECDH, ECSign, scalar mult
│   ├── attacks_module.py # Pollard's Rho, BSGS discrete log
│   └── report_module.py # Markdown report generation
└── rapport_crypto.md    # Generated report output
```

## Installation

```bash
git clone https://github.com/KcMelek/RSA-and-ECC.git
cd RSA-and-ECC
pip install -r requirements.txt
```

> **Note:** The core crypto modules (`modules/`) require **no external dependencies**. Only the Streamlit web interface needs `streamlit`, `pandas`, and `altair`.

## Usage

### CLI Demo

```bash
python crypto_tool.py
```

Runs all 4 modules sequentially: RSA, ECC, Attacks, and Report generation.

### GUI Application

```bash
python gui.py
```

A dark-themed Tkinter interface with four tabs:
- **RSA** — Set parameters (p, q, e), encrypt/decrypt messages, compute extended GCD
- **ECC** — Define custom curves, list points, run ECDH, sign & verify messages
- **Attaques** — Run Pollard's Rho and BSGS attacks
- **Rapport** — Generate and view the full Markdown report

### Streamlit Web App

```bash
streamlit run streamlit_app.py
```

Browser-based dashboard with:
- RSA operations with text encryption and digital signatures
- ECC with custom curve parameters and ElGamal point encryption
- Attack demos with real-time results
- Cross-validation charts comparing RSA vs ECC performance

## Educational Value

This project is designed for learning cryptography fundamentals:

- **No black boxes** — Every algorithm is implemented from scratch in pure Python
- **Visual feedback** — GUI and web interfaces show each step
- **Attack demonstrations** — See how Pollard's Rho breaks small RSA keys and BSGS recovers ECC private keys
- **Performance comparison** — Understand the speed differences between RSA and ECC operations

## Example Parameters

The default demo uses:
- **RSA:** p=17, q=19, e=7, n=323
- **ECC:** Curve y² = x³ + 2x + 2 (mod 17), Generator G=(5,1)

## Technologies

- **Language:** Python 3
- **GUI:** Tkinter (built-in)
- **Web:** Streamlit, Pandas, Altair
- **Crypto:** 100% Pure Python (no OpenSSL, no cryptography, no PyCryptodome)

## Author

**KcMelek** — Architecte Cryptographie

## License

This project is open-source and available for educational use.
