"""
setup_blockchain.py
-------------------
Ejecutar UNA SOLA VEZ para inicializar el sistema blockchain en vuestro entorno.

Hace todo automáticamente:
1. Genera una clave Fernet nueva para VUESTRO entorno
2. Genera pares de claves ECDSA para cada usuario
3. Actualiza data.json con las claves nuevas
4. Crea genesis.json y chain.json
5. Crea el fichero .env con la clave

Uso:
    python setup_blockchain.py
"""

import json
import os
import sys

# Verificar que blockchain.py está en la misma carpeta
if not os.path.exists("blockchain.py"):
    print("ERROR: blockchain.py no encontrado. Ponlo en la misma carpeta que este script.")
    sys.exit(1)

if not os.path.exists("data.json"):
    print("ERROR: data.json no encontrado.")
    sys.exit(1)

# ── Paso 1: Generar clave Fernet nueva ───────────────────────────────────────
from cryptography.fernet import Fernet

NEW_KEY = Fernet.generate_key().decode()
print(f"[1/5] Clave Fernet generada: {NEW_KEY[:20]}...")

# Establecer en el entorno del proceso actual para que blockchain.py la use
os.environ["GODOYCRUZ_ENCRYPTION_KEY"] = NEW_KEY

# ── Paso 2: Importar blockchain DESPUÉS de fijar la variable de entorno ───────
import blockchain as bc

print("[2/5] Motor blockchain cargado correctamente.")

# ── Paso 3: Leer data.json y regenerar claves para todos los usuarios ─────────
with open("data.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Asegurar que existe la wallet Estado
if bc.WALLET_ESTADO not in data["users"]:
    data["users"][bc.WALLET_ESTADO] = {
        "rol": "admin",
        "cart": [],
        "purchased": []
    }
    print(f"   → Wallet '{bc.WALLET_ESTADO}' creada.")

# Generar claves para cada usuario
for username, info in data["users"].items():
    kp = bc.generate_keypair()
    info["public_key"]           = kp["public_key"]
    info["private_key_encrypted"] = kp["private_key_encrypted"]
    # Eliminar campo wallet numérico antiguo si existe
    info.pop("wallet", None)
    print(f"   → Claves generadas para: {username}")

with open("data.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4, ensure_ascii=False)

print("[3/5] data.json actualizado con claves ECDSA.")

# ── Paso 4: Crear genesis.json y chain.json ───────────────────────────────────
# Limpiar chain anterior si existe
if os.path.exists("chain.json"):
    os.remove("chain.json")
    print("   → chain.json anterior eliminado.")

# Crear génesis con 10 monedas de 100 GC por usuario (excepto estado)
pubkeys = {
    u: info["public_key"]
    for u, info in data["users"].items()
    if u != bc.WALLET_ESTADO
}

genesis = bc.create_genesis(pubkeys, initial_coins_per_user=10, coin_value=100.0)

with open("genesis.json", "w", encoding="utf-8") as f:
    json.dump(genesis, f, indent=2)

# Forzar carga de la cadena (crea chain.json desde genesis.json)
chain = bc.load_chain()

print(f"[4/5] genesis.json y chain.json creados.")
print(f"   → Monedas en génesis: {len(genesis['transactions'][0]['outputs'])}")
print(f"   → Bloques en cadena:  {len(chain)}")

# ── Paso 5: Crear fichero .env ────────────────────────────────────────────────
env_content = f"""# Variables de entorno para GODOYCRUZ Marketplace
# NO subir este fichero a Git (.gitignore debe incluir .env)

GODOYCRUZ_ENCRYPTION_KEY={NEW_KEY}
GODOYCRUZ_SECRET_KEY={Fernet.generate_key().decode()}
"""

with open(".env", "w", encoding="utf-8") as f:
    f.write(env_content)

print("[5/5] Fichero .env creado con las claves.")

# ── Verificación final ────────────────────────────────────────────────────────
print()
print("=" * 60)
print("VERIFICACIÓN FINAL")
print("=" * 60)

# Test: transferencia de cliente1 a empresa1
c1_pub  = data["users"]["cliente1"]["public_key"]
c1_priv = data["users"]["cliente1"]["private_key_encrypted"]
emp_pub = data["users"]["empresa1"]["public_key"]

saldo_antes = bc.get_balance(c1_pub, chain)
print(f"Saldo cliente1 antes:  {saldo_antes} GC")

tx = bc.build_transfer(c1_pub, c1_priv, emp_pub, 150.0, chain)
if tx:
    ok, msg = bc.add_transaction_to_chain(tx)
    chain2 = bc.load_chain()
    saldo_despues = bc.get_balance(c1_pub, chain2)
    estado_pub = data["users"][bc.WALLET_ESTADO]["public_key"]
    comision   = bc.get_balance(estado_pub, chain2)
    ok_int, _ = bc.verify_chain_integrity(chain2)
    print(f"Saldo cliente1 después: {saldo_despues} GC")
    print(f"Comisión en Estado:     {comision} GC")
    print(f"Integridad cadena:      {'✅ OK' if ok_int else '❌ ERROR'}")
    print(f"Transacción añadida:    {'✅ OK' if ok else '❌ ' + msg}")
else:
    print("❌ ERROR construyendo transacción de prueba")
    sys.exit(1)

print()
print("=" * 60)
print("✅ SETUP COMPLETADO CON ÉXITO")
print("=" * 60)
print()
print("Para arrancar Flask en Windows (PowerShell):")
print(f'  $env:GODOYCRUZ_ENCRYPTION_KEY="{NEW_KEY}"')
print(f'  $env:GODOYCRUZ_SECRET_KEY="<valor del .env>"')
print("  python app.py")
print()
print("O más fácil, usar el script arrancar.ps1 que se ha creado.")

# ── Crear script de arranque para PowerShell ──────────────────────────────────
flask_key_line = ""
with open(".env") as f:
    for line in f:
        if "GODOYCRUZ_SECRET_KEY" in line:
            flask_key_line = line.strip().split("=", 1)[1]

ps1_content = f"""# arrancar.ps1 — ejecutar en PowerShell para arrancar el marketplace
$env:GODOYCRUZ_ENCRYPTION_KEY="{NEW_KEY}"
$env:GODOYCRUZ_SECRET_KEY="{flask_key_line}"
python app.py
"""

with open("arrancar.ps1", "w", encoding="utf-8") as f:
    f.write(ps1_content)

print("Script PowerShell creado: arrancar.ps1")
print("Ejecútalo así:  .\\arrancar.ps1")
