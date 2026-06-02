"""
Motor de criptomoneda GodoyCoin para GODOYCRUZ Marketplace.
Implementa wallets ECDSA, monedas individuales, transacciones firmadas y cadena de bloques.
"""

import hashlib
import json
import os
import time
import uuid
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature

# ── Configuración ─────────────────────────────────────────────────────────────
CHAIN_FILE      = "chain.json"
GENESIS_FILE    = "genesis.json"
COMMISSION_RATE = 0.02          # 2% de comisión por transacción
WALLET_ESTADO   = "estado"      # nombre de la wallet que recibe comisiones
MAX_COINS       = 100           # límite de monedas por wallet

# Clave Fernet para cifrar claves privadas (debe estar en variable de entorno)
_raw = os.environ.get("GODOYCRUZ_ENCRYPTION_KEY", Fernet.generate_key().decode())
_FERNET = Fernet(_raw.encode() if isinstance(_raw, str) else _raw)


# ══════════════════════════════════════════════════════════════════════════════
# CAPA 1 — GESTIÓN DE CLAVES Y WALLETS
# ══════════════════════════════════════════════════════════════════════════════

def generate_keypair() -> dict:
    """
    Genera un par de claves ECDSA (P-256).
    Devuelve {"public_key": str_hex, "private_key_encrypted": str_fernet}
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key  = private_key.public_key()

    # Serializar clave pública en formato sin comprimir (hex)
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pub_hex = pub_bytes.hex()

    # Serializar clave privada en PEM y cifrarla con Fernet
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    priv_encrypted = _FERNET.encrypt(priv_bytes).decode()

    return {
        "public_key": pub_hex,
        "private_key_encrypted": priv_encrypted
    }


def _load_private_key(private_key_encrypted: str):
    """Descifra y carga una clave privada ECDSA desde su forma cifrada con Fernet."""
    pem = _FERNET.decrypt(private_key_encrypted.encode())
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())


def _load_public_key(pub_hex: str):
    """Carga una clave pública ECDSA desde su representación hexadecimal."""
    pub_bytes = bytes.fromhex(pub_hex)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)


# ══════════════════════════════════════════════════════════════════════════════
# CAPA 2 — MONEDAS
# ══════════════════════════════════════════════════════════════════════════════

def create_coin(owner_pubkey: str, value: float) -> dict:
    """
    Crea una moneda nueva con identificador único.
    owner_pubkey: clave pública hex del propietario.
    value: valor numérico de la moneda.
    """
    coin_id = hashlib.sha256(
        f"{owner_pubkey}{value}{uuid.uuid4()}".encode()
    ).hexdigest()

    return {
        "id":    coin_id,
        "value": round(value, 8),
        "owner": owner_pubkey
    }


def get_wallet_coins(pub_hex: str, chain: list) -> list:
    """
    Recorre la cadena y devuelve las monedas actuales en posesión de pub_hex.
    Una moneda es 'actual' si aparece como output en alguna transacción
    y NO aparece como input en ninguna posterior.
    """
    spent_ids = set()
    owned     = {}   # coin_id -> coin dict

    for block in chain:
        for tx in block.get("transactions", []):
            # Marcar inputs como gastados
            for inp in tx.get("inputs", []):
                spent_ids.add(inp["id"])
                owned.pop(inp["id"], None)

            # Registrar outputs propios
            for out in tx.get("outputs", []):
                if out["owner"] == pub_hex:
                    owned[out["id"]] = out

    # Filtrar los ya gastados (por si se procesaron en el mismo bloque)
    return [c for cid, c in owned.items() if cid not in spent_ids]


def get_balance(pub_hex: str, chain: list) -> float:
    """Suma el valor de todas las monedas actuales de una wallet."""
    return round(sum(c["value"] for c in get_wallet_coins(pub_hex, chain)), 8)


def coin_count(pub_hex: str, chain: list) -> int:
    """Cuenta cuántas monedas tiene actualmente una wallet."""
    return len(get_wallet_coins(pub_hex, chain))


# ══════════════════════════════════════════════════════════════════════════════
# CAPA 3 — TRANSACCIONES
# ══════════════════════════════════════════════════════════════════════════════

def _sign(data: dict, private_key_encrypted: str) -> str:
    """Firma el payload serializado con ECDSA-SHA256. Devuelve la firma en hex."""
    priv = _load_private_key(private_key_encrypted)
    payload = json.dumps(data, sort_keys=True).encode()
    sig_der = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
    return sig_der.hex()


def _verify_signature(data: dict, signature_hex: str, pub_hex: str) -> bool:
    """Verifica que la firma del dict corresponde a la clave pública dada."""
    try:
        pub = _load_public_key(pub_hex)
        payload = json.dumps(data, sort_keys=True).encode()
        sig_der = bytes.fromhex(signature_hex)
        pub.verify(sig_der, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


def _build_tx_payload(tx_type: str, inputs: list, outputs: list,
                      sender_pub: str, timestamp: float) -> dict:
    """Construye el payload firmable de una transacción (sin firma)."""
    return {
        "type":      tx_type,
        "sender":    sender_pub,
        "inputs":    inputs,
        "outputs":   outputs,
        "timestamp": timestamp
    }


def build_transfer(sender_pub: str, sender_priv_enc: str,
                   receiver_pub: str, amount: float,
                   chain: list) -> Optional[dict]:
    """
    Construye una transacción de TRANSFERENCIA de sender a receiver.
    Selecciona monedas automáticamente, genera cambio si es necesario,
    y aplica la comisión del 2% hacia la wallet Estado.
    Devuelve el dict de transacción firmado, o None si no hay fondos.
    """
    estado_pub = _get_estado_pubkey()
    if not estado_pub:
        return None

    commission = round(amount * COMMISSION_RATE, 8)
    total_needed = round(amount + commission, 8)

    # Seleccionar monedas del sender (greedy)
    my_coins = get_wallet_coins(sender_pub, chain)
    selected, selected_value = _select_coins(my_coins, total_needed)
    if selected_value < total_needed:
        return None   # fondos insuficientes

    ts = time.time()
    outputs = [
        create_coin(receiver_pub, amount),
        create_coin(estado_pub,   commission),
    ]
    change = round(selected_value - total_needed, 8)
    if change > 0:
        outputs.append(create_coin(sender_pub, change))

    payload = _build_tx_payload("TRANSFER", selected, outputs, sender_pub, ts)
    signature = _sign(payload, sender_priv_enc)

    return {**payload, "signature": signature,
            "tx_id": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}


def build_merge(owner_pub: str, owner_priv_enc: str,
                coin_ids: list, chain: list) -> Optional[dict]:
    """
    Construye una transacción MERGE: varias monedas → una sola.
    coin_ids: lista de IDs de monedas a fusionar.
    """
    my_coins = get_wallet_coins(owner_pub, chain)
    to_merge = [c for c in my_coins if c["id"] in coin_ids]

    if len(to_merge) < 2:
        return None

    estado_pub = _get_estado_pubkey()
    if not estado_pub:
        return None

    total_value = sum(c["value"] for c in to_merge)
    commission  = round(total_value * COMMISSION_RATE, 8)
    merged_val  = round(total_value - commission, 8)

    ts = time.time()
    outputs = [
        create_coin(owner_pub,  merged_val),
        create_coin(estado_pub, commission),
    ]

    payload = _build_tx_payload("MERGE", to_merge, outputs, owner_pub, ts)
    signature = _sign(payload, owner_priv_enc)

    return {**payload, "signature": signature,
            "tx_id": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}


def build_split(owner_pub: str, owner_priv_enc: str,
                coin_id: str, parts: int, chain: list) -> Optional[dict]:
    """
    Construye una transacción SPLIT: una moneda → N monedas de igual valor.
    Se aplica comisión sobre el valor total antes de dividir.
    """
    my_coins = get_wallet_coins(owner_pub, chain)
    coin = next((c for c in my_coins if c["id"] == coin_id), None)
    if not coin or parts < 2:
        return None

    estado_pub = _get_estado_pubkey()
    if not estado_pub:
        return None

    commission = round(coin["value"] * COMMISSION_RATE, 8)
    net_value  = round(coin["value"] - commission, 8)
    part_val   = round(net_value / parts, 8)

    # Verificar límite de 100 monedas tras el split
    current_count = coin_count(owner_pub, chain)
    coins_after   = current_count - 1 + parts   # -1 la que se consume, +parts las nuevas
    if coins_after > MAX_COINS:
        return None

    ts = time.time()
    outputs = [create_coin(owner_pub, part_val) for _ in range(parts)]
    outputs.append(create_coin(estado_pub, commission))

    payload = _build_tx_payload("SPLIT", [coin], outputs, owner_pub, ts)
    signature = _sign(payload, owner_priv_enc)

    return {**payload, "signature": signature,
            "tx_id": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}


# ══════════════════════════════════════════════════════════════════════════════
# CAPA 4 — VALIDACIÓN DE TRANSACCIONES
# ══════════════════════════════════════════════════════════════════════════════

def validate_transaction(tx: dict, chain: list) -> tuple[bool, str]:
    """
    Valida una transacción contra todas las reglas del protocolo.
    Devuelve (True, "OK") o (False, motivo_del_error).
    """
    tx_type = tx.get("type")
    sender  = tx.get("sender")

    # 1. Firma correcta
    payload = _build_tx_payload(
        tx_type, tx["inputs"], tx["outputs"], sender, tx["timestamp"]
    )
    if not _verify_signature(payload, tx["signature"], sender):
        return False, "Firma digital inválida"

    # 2. No doble gasto — los inputs no deben estar ya gastados en la cadena
    spent = _get_spent_coin_ids(chain)
    for inp in tx["inputs"]:
        if inp["id"] in spent:
            return False, f"Doble gasto detectado: moneda {inp['id'][:16]}..."

    # 3. Los inputs pertenecen al sender
    sender_coins = {c["id"] for c in get_wallet_coins(sender, chain)}
    for inp in tx["inputs"]:
        if inp["id"] not in sender_coins:
            return False, f"Input {inp['id'][:16]}... no pertenece al sender"

    # 4. Conservación de valor (con tolerancia de punto flotante)
    input_total  = round(sum(c["value"] for c in tx["inputs"]),  8)
    output_total = round(sum(c["value"] for c in tx["outputs"]), 8)
    if abs(input_total - output_total) > 1e-6:
        return False, f"Valor no conservado: entrada={input_total} salida={output_total}"

    # 5. Comisión obligatoria presente en outputs hacia wallet Estado
    estado_pub = _get_estado_pubkey()
    if estado_pub:
        commission_outputs = [o for o in tx["outputs"] if o["owner"] == estado_pub]
        if not commission_outputs:
            return False, "Falta comisión obligatoria hacia wallet Estado"

    # 6. Ninguna wallet supera el límite de 100 monedas tras la transacción
    result_ok, reason = _check_wallet_limits(tx, chain)
    if not result_ok:
        return False, reason

    return True, "OK"


def _get_spent_coin_ids(chain: list) -> set:
    """Devuelve el conjunto de IDs de monedas ya gastadas en la cadena."""
    spent = set()
    for block in chain:
        for tx in block.get("transactions", []):
            for inp in tx.get("inputs", []):
                spent.add(inp["id"])
    return spent


def _check_wallet_limits(tx: dict, chain: list) -> tuple[bool, str]:
    """Verifica que ninguna wallet supere MAX_COINS tras aplicar la transacción."""
    # Calcular delta de monedas por wallet
    delta: dict = {}
    for inp in tx["inputs"]:
        delta[inp["owner"]] = delta.get(inp["owner"], 0) - 1
    for out in tx["outputs"]:
        delta[out["owner"]] = delta.get(out["owner"], 0) + 1

    for pub, change in delta.items():
        current = coin_count(pub, chain)
        if current + change > MAX_COINS:
            return False, f"Wallet {pub[:16]}... superaría límite de {MAX_COINS} monedas"
    return True, "OK"


# ══════════════════════════════════════════════════════════════════════════════
# CAPA 5 — BLOQUES Y CADENA
# ══════════════════════════════════════════════════════════════════════════════

def _hash_block(block: dict) -> str:
    """Calcula el hash SHA-256 de un bloque."""
    block_copy = {k: v for k, v in block.items() if k != "hash"}
    payload = json.dumps(block_copy, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def load_chain() -> list:
    """Carga la cadena desde chain.json. Si no existe, la inicializa desde genesis.json."""
    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    # Primera vez: cargar bloque génesis
    if os.path.exists(GENESIS_FILE):
        with open(GENESIS_FILE, "r", encoding="utf-8") as f:
            genesis = json.load(f)
        chain = [genesis]
        _save_chain(chain)
        return chain
    return []


def _save_chain(chain: list):
    """Persiste la cadena en disco."""
    with open(CHAIN_FILE, "w", encoding="utf-8") as f:
        json.dump(chain, f, indent=2)


def add_transaction_to_chain(tx: dict) -> tuple[bool, str]:
    """
    Valida una transacción y, si es válida, la añade en un nuevo bloque.
    Devuelve (True, tx_id) o (False, motivo_del_error).
    """
    chain = load_chain()
    valid, reason = validate_transaction(tx, chain)
    if not valid:
        return False, reason

    prev_hash = chain[-1]["hash"] if chain else "0" * 64
    new_block = {
        "index":        len(chain),
        "timestamp":    time.time(),
        "transactions": [tx],
        "previous_hash": prev_hash,
    }
    new_block["hash"] = _hash_block(new_block)
    chain.append(new_block)
    _save_chain(chain)
    return True, tx["tx_id"]


def verify_chain_integrity(chain: list) -> tuple[bool, str]:
    """
    Recorre la cadena verificando que cada bloque enlaza correctamente con el anterior.
    Devuelve (True, "OK") o (False, descripción del bloque corrupto).
    """
    for i in range(1, len(chain)):
        block = chain[i]
        prev  = chain[i - 1]
        if block["previous_hash"] != prev["hash"]:
            return False, f"Bloque {i} desvinculado del anterior"
        if block["hash"] != _hash_block(block):
            return False, f"Bloque {i} con hash inválido (posible manipulación)"
    return True, "OK"


# ══════════════════════════════════════════════════════════════════════════════
# CAPA 6 — GENESIS Y UTILIDADES
# ══════════════════════════════════════════════════════════════════════════════

def create_genesis(user_pubkeys: dict, initial_coins_per_user: int = 10,
                   coin_value: float = 100.0) -> dict:
    """
    Genera el bloque génesis con una distribución inicial de monedas.
    user_pubkeys: {username: pub_hex}
    Usado solo si el profesor no proporciona un génesis oficial.
    """
    outputs = []
    for username, pub_hex in user_pubkeys.items():
        for _ in range(initial_coins_per_user):
            outputs.append(create_coin(pub_hex, coin_value))

    genesis_tx = {
        "type":      "GENESIS",
        "sender":    "GENESIS",
        "inputs":    [],
        "outputs":   outputs,
        "timestamp": 0.0,
        "signature": "GENESIS_SIGNATURE",
        "tx_id":     "genesis_tx"
    }

    genesis_block = {
        "index":         0,
        "timestamp":     0.0,
        "transactions":  [genesis_tx],
        "previous_hash": "0" * 64,
    }
    genesis_block["hash"] = _hash_block(genesis_block)
    return genesis_block


def get_transaction_history(pub_hex: str, chain: list) -> list:
    """Devuelve todas las transacciones donde pub_hex aparece como sender o receptor."""
    history = []
    for block in chain:
        for tx in block.get("transactions", []):
            involved = (
                tx.get("sender") == pub_hex or
                any(o["owner"] == pub_hex for o in tx.get("outputs", [])) or
                any(i["owner"] == pub_hex for i in tx.get("inputs", []))
            )
            if involved:
                history.append({**tx, "block_index": block["index"]})
    return list(reversed(history))


# ══════════════════════════════════════════════════════════════════════════════
# UTILIDADES INTERNAS
# ══════════════════════════════════════════════════════════════════════════════

def _select_coins(coins: list, amount_needed: float) -> tuple[list, float]:
    """Selecciona monedas suficientes para cubrir amount_needed (greedy por valor desc)."""
    sorted_coins = sorted(coins, key=lambda c: c["value"], reverse=True)
    selected, total = [], 0.0
    for coin in sorted_coins:
        if total >= amount_needed:
            break
        selected.append(coin)
        total = round(total + coin["value"], 8)
    return selected, total


def _get_estado_pubkey() -> Optional[str]:
    """Lee la clave pública de la wallet Estado desde data.json."""
    try:
        with open("data.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["users"].get(WALLET_ESTADO, {}).get("public_key")
    except Exception:
        return None
