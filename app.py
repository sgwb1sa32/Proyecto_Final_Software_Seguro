"""Módulo principal de la aplicación GODOYCRUZ Marketplace."""

import json
import os
import secrets

from flask import Flask, flash, redirect, render_template, request, session, url_for

from security import (
    SECURITY_ALERTS, access_control, monitor1,
    verify_and_read_logs, verify_csrf, add_security_alert
)

# ── NUEVO: importar el motor de criptomoneda ──────────────────────────────────
import blockchain as bc

app = Flask(__name__)
app.secret_key = os.environ.get('GODOYCRUZ_SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# --- MANEJO DE DATOS ---------------------------------------------------------
def load_data():
    with open('data.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def save_data(data):
    with open('data.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

# --- CABECERAS DE SEGURIDAD --------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' https://images.unsplash.com;"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ── CAMBIO: init_system ahora inicializa también la blockchain ────────────────
def init_system():
    """
    Inicializa el sistema:
    - Genera claves ECDSA para usuarios que no las tengan.
    - Crea el bloque génesis si no existe cadena.
    - Elimina el campo 'wallet' numérico antiguo si quedara.
    """
    data = load_data()
    changed = False

    for username, info in data['users'].items():
        # Quitar wallet numérica antigua si existe
        if 'wallet' in info:
            del info['wallet']
            changed = True
        # Generar claves si el usuario no las tiene
        if 'public_key' not in info or 'private_key_encrypted' not in info:
            kp = bc.generate_keypair()
            info['public_key'] = kp['public_key']
            info['private_key_encrypted'] = kp['private_key_encrypted']
            changed = True
        if 'cart' not in info:
            info['cart'] = []
            changed = True

    # Asegurar que existe la wallet Estado
    if bc.WALLET_ESTADO not in data['users']:
        kp = bc.generate_keypair()
        data['users'][bc.WALLET_ESTADO] = {
            'rol': 'admin',
            'public_key': kp['public_key'],
            'private_key_encrypted': kp['private_key_encrypted'],
            'cart': [],
            'purchased': []
        }
        changed = True

    if changed:
        save_data(data)

    # Inicializar la cadena desde génesis si no existe
    if not os.path.exists('chain.json'):
        pubkeys = {
            u: info['public_key']
            for u, info in data['users'].items()
            if u != bc.WALLET_ESTADO
        }
        genesis = bc.create_genesis(pubkeys, initial_coins_per_user=10, coin_value=100.0)
        with open('genesis.json', 'w', encoding='utf-8') as f:
            json.dump(genesis, f, indent=2)
        bc.load_chain()   # crea chain.json desde genesis.json


# ── CAMBIO: inject_user ahora lee saldo desde la blockchain ──────────────────
@app.context_processor
def inject_user():
    data = load_data()
    username = session.get('username', 'cliente1')

    if username not in data['users']:
        username = 'cliente1'

    session['username'] = username
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

    user_info = data['users'][username]

    # Leer saldo real desde la blockchain
    chain = bc.load_chain()
    pub_hex = user_info.get('public_key', '')
    wallet_balance = bc.get_balance(pub_hex, chain) if pub_hex else 0

    return {
        "current_user":   username,
        "user_data":      user_info,
        "wallet_balance": wallet_balance,
        "all_users":      list(data['users'].keys()),
        "csrf_token":     session['csrf_token'],
        "security_alerts": SECURITY_ALERTS
    }

# --- RUTAS SIN CAMBIOS -------------------------------------------------------

@app.route('/switch_user/<username>')
def switch_user(username):
    session['username'] = username
    return redirect(url_for('index'))

@app.route('/')
@monitor1(nivel_log="INFO")
def index():
    data = load_data()
    return render_template('index.html', products=data['products'])

@app.route('/cart/add/<int:product_id>', methods=['POST'])
@verify_csrf
@access_control("normal_user")
@monitor1(nivel_log="INFO")
def add_to_cart(product_id):
    data = load_data()
    product = next((p for p in data['products'] if p['id'] == product_id), None)
    if product:
        username = session.get('username', 'cliente1')
        data['users'][username]['cart'].append(product)
        save_data(data)
        flash(f"Añadido {product['name']} al carrito.", "success")
    return redirect(url_for('index'))

@app.route('/cart')
@access_control("normal_user")
@monitor1(nivel_log="INFO")
def view_cart():
    data = load_data()
    username = session.get('username', 'cliente1')
    cart = data['users'][username]['cart']
    total = sum(p['price'] for p in cart)
    return render_template('cart.html', cart=cart, total=total)

@app.route('/cart/remove/<int:index>', methods=['POST'])
@verify_csrf
@access_control("normal_user")
def remove_from_cart(index):
    data = load_data()
    username = session.get('username', 'cliente1')
    cart = data['users'][username]['cart']
    if 0 <= index < len(cart):
        removed = cart.pop(index)
        save_data(data)
        flash(f"'{removed['name']}' eliminado del carrito.", "success")
    return redirect(url_for('view_cart'))

# ── CAMBIO PRINCIPAL: checkout usa transacciones de blockchain ────────────────
@app.route('/cart/checkout', methods=['POST'])
@verify_csrf
@access_control("normal_user")
@monitor1(nivel_log="WARNING")
def checkout():
    """
    Procesa la compra generando una transacción firmada por cada producto.
    El pago se realiza mediante el motor de blockchain:
    - Se seleccionan monedas del comprador
    - Se genera una transacción firmada con su clave privada
    - La comisión del 2% va automáticamente a la wallet Estado
    - Si la validación falla, la compra se rechaza
    """
    data = load_data()
    username = session.get('username', 'cliente1')
    comprador = data['users'][username]
    cart = comprador['cart']

    if not cart:
        flash("Tu carrito está vacío.", "error")
        return redirect(url_for('view_cart'))

    total_price = sum(p['price'] for p in cart)
    buyer_pub  = comprador['public_key']
    buyer_priv = comprador['private_key_encrypted']

    # Agrupar pagos por vendedor
    sellers_payments = {}
    for item in cart:
        seller = item['seller']
        sellers_payments[seller] = sellers_payments.get(seller, 0) + item['price']

    chain = bc.load_chain()

    # Verificar saldo antes de intentar
    if bc.get_balance(buyer_pub, chain) < total_price:
        flash("GodoyCoins insuficientes. Recarga tu Wallet.", "error")
        return redirect(url_for('view_cart'))

    # Procesar un pago por vendedor
    all_ok = True
    for seller_name, amount in sellers_payments.items():
        seller_pub = data['users'][seller_name]['public_key']
        chain = bc.load_chain()   # recargar tras cada bloque añadido
        tx = bc.build_transfer(buyer_pub, buyer_priv, seller_pub, float(amount), chain)
        if tx is None:
            all_ok = False
            add_security_alert("CRITICAL",
                f"Fondos insuficientes para pagar a {seller_name} durante checkout.")
            break

        ok, msg = bc.add_transaction_to_chain(tx)
        if not ok:
            all_ok = False
            add_security_alert("CRITICAL",
                f"Transacción rechazada en checkout hacia {seller_name}: {msg}")
            break

    if all_ok:
        # Registrar compras y limpiar carrito
        for item in cart:
            comprador.setdefault('purchased', []).append(item)
        comprador['cart'] = []
        save_data(data)
        flash(f"Compra realizada con éxito. Total: {total_price} GC "
              f"(+{round(total_price * bc.COMMISSION_RATE, 2)} GC comisión).", "success")
    else:
        flash("Error procesando el pago. Comprueba tu saldo.", "error")

    return redirect(url_for('index'))


# ── CAMBIO: wallet lee y opera contra la blockchain ──────────────────────────
@app.route('/wallet', methods=['GET', 'POST'])
@verify_csrf
@monitor1(nivel_log="INFO")
def wallet():
    """
    Gestiona la wallet del usuario leyendo la blockchain real.
    - GET:  muestra saldo, monedas individuales y formularios
    - POST: procesa compra de GC (mint), venta (burn) o transferencia
    """
    data    = load_data()
    username = session.get('username', 'cliente1')
    user    = data['users'][username]
    pub_hex = user['public_key']
    priv_enc = user['private_key_encrypted']

    chain   = bc.load_chain()
    coins   = bc.get_wallet_coins(pub_hex, chain)
    balance = bc.get_balance(pub_hex, chain)

    if request.method == 'POST':
        action = request.form.get('action')

        try:
            amount = int(request.form.get('amount', 0))
            if amount <= 0 or amount > 10000:
                raise ValueError()
        except (ValueError, TypeError):
            flash("Cantidad inválida. Introduce un número entero entre 1 y 10,000 GC.", "error")
            return redirect(url_for('wallet'))

        if action == 'buy':
            import time as _time, hashlib as _hashlib
            chain_current = bc.load_chain()
            current_count = bc.coin_count(pub_hex, chain_current)
            if current_count >= bc.MAX_COINS:
                flash(f"No puedes comprar más GC: ya tienes {current_count}/100 monedas. "
                      "Usa MERGE para liberar slots.", "error")
                return redirect(url_for('wallet'))

            new_coin = bc.create_coin(pub_hex, float(amount))
            ts = _time.time()
            mint_tx = {
                "type":      "MINT",
                "sender":    "SISTEMA",
                "inputs":    [],
                "outputs":   [new_coin],
                "timestamp": ts,
                "signature": "MINT_AUTHORIZED",
                "tx_id":     _hashlib.sha256(f"mint{pub_hex}{amount}{ts}".encode()).hexdigest()
            }
            prev_hash = chain_current[-1]["hash"] if chain_current else "0" * 64
            new_block = {
                "index":         len(chain_current),
                "timestamp":     ts,
                "transactions":  [mint_tx],
                "previous_hash": prev_hash,
            }
            new_block["hash"] = bc._hash_block(new_block)
            chain_current.append(new_block)
            bc._save_chain(chain_current)
            flash(f"Has comprado {amount} GC con tu tarjeta.", "success")

        elif action == 'sell':
            # BURN: enviar monedas a wallet Estado (simula retiro a banco)
            estado_pub = data['users'][bc.WALLET_ESTADO]['public_key']
            chain = bc.load_chain()
            tx = bc.build_transfer(pub_hex, priv_enc, estado_pub, amount, chain)
            if tx:
                ok, msg = bc.add_transaction_to_chain(tx)
                if ok:
                    flash(f"Has retirado {amount} GC a tu cuenta bancaria.", "success")
                else:
                    flash(f"Error en la retirada: {msg}", "error")
            else:
                flash("No tienes suficientes GC o cantidad inválida.", "error")

        elif action == 'transfer':
            target = request.form.get('target')
            if target not in data['users'] or target == username:
                flash("Destinatario inválido.", "error")
                return redirect(url_for('wallet'))

            target_pub = data['users'][target]['public_key']
            chain = bc.load_chain()
            tx = bc.build_transfer(pub_hex, priv_enc, target_pub, amount, chain)
            if tx:
                ok, msg = bc.add_transaction_to_chain(tx)
                if ok:
                    flash(f"Transferiste {amount} GC a {target} "
                          f"(comisión: {round(amount * bc.COMMISSION_RATE, 2)} GC).", "success")
                else:
                    flash(f"Transferencia rechazada: {msg}", "error")
            else:
                flash("Error en la transferencia. Revisa datos.", "error")

        return redirect(url_for('wallet'))

    # GET: pasar monedas individuales al template
    return render_template('wallet.html',
                           users_list=list(data['users'].keys()),
                           coins=coins,
                           balance=balance)


# ── NUEVA RUTA: operaciones MERGE y SPLIT ────────────────────────────────────
@app.route('/coins', methods=['GET', 'POST'])
@verify_csrf
@access_control("normal_user")
@monitor1(nivel_log="INFO")
def coins_view():
    """
    Panel de gestión de monedas individuales.
    Permite realizar MERGE (fusionar) y SPLIT (dividir) de monedas.
    """
    data     = load_data()
    username = session.get('username', 'cliente1')
    user     = data['users'][username]
    pub_hex  = user['public_key']
    priv_enc = user['private_key_encrypted']

    chain = bc.load_chain()
    coins = bc.get_wallet_coins(pub_hex, chain)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'merge':
            coin_ids = request.form.getlist('coin_ids')
            if len(coin_ids) < 2:
                flash("Selecciona al menos 2 monedas para fusionar.", "error")
                return redirect(url_for('coins_view'))

            tx = bc.build_merge(pub_hex, priv_enc, coin_ids, chain)
            if tx:
                ok, msg = bc.add_transaction_to_chain(tx)
                flash(f"MERGE realizado: {len(coin_ids)} monedas fusionadas." if ok
                      else f"MERGE rechazado: {msg}",
                      "success" if ok else "error")
            else:
                flash("No se pudo construir el MERGE. Verifica las monedas seleccionadas.", "error")

        elif action == 'split':
            coin_id = request.form.get('coin_id')
            try:
                parts = int(request.form.get('parts', 2))
                if parts < 2 or parts > 10:
                    raise ValueError()
            except (ValueError, TypeError):
                flash("Número de partes inválido (entre 2 y 10).", "error")
                return redirect(url_for('coins_view'))

            tx = bc.build_split(pub_hex, priv_enc, coin_id, parts, chain)
            if tx:
                ok, msg = bc.add_transaction_to_chain(tx)
                flash(f"SPLIT realizado: moneda dividida en {parts} partes." if ok
                      else f"SPLIT rechazado: {msg}",
                      "success" if ok else "error")
            else:
                flash("No se pudo construir el SPLIT. "
                      "Verifica que no superarás el límite de 100 monedas.", "error")

        return redirect(url_for('coins_view'))

    return render_template('coins.html', coins=coins)


# --- RUTAS SIN CAMBIOS (empresa y admin) ------------------------------------

@app.route('/company', methods=['GET', 'POST'])
@verify_csrf
@access_control("company")
@monitor1(nivel_log="INFO")
def company_dashboard():
    data = load_data()
    username = session.get('username', 'empresa1')

    if request.method == 'POST':
        try:
            p_id = int(request.form.get('product_id', -1))
            new_price = int(request.form.get('price', -1))
            if p_id < 0 or new_price <= 0:
                raise ValueError()
        except (ValueError, TypeError):
            flash("Datos de producto inválidos.", "error")
            return redirect(url_for('company_dashboard'))

        product = next((p for p in data['products'] if p['id'] == p_id), None)
        if product and product['seller'] == username:
            product['price'] = new_price
            product['description'] = request.form.get('description', '')
            save_data(data)
            flash("Producto actualizado correctamente.", "success")
            return redirect(url_for('company_dashboard'))

    my_products = [p for p in data['products'] if p['seller'] == username]
    return render_template('company.html', products=my_products)


@app.route('/admin/security')
@access_control("admin")
@monitor1(nivel_log="INFO")
def admin_security():
    """Centro de control con logs, alertas e integridad de la blockchain."""
    decrypted_logs, tamper_detected = verify_and_read_logs()

    # NUEVO: verificar integridad de la cadena de bloques
    chain = bc.load_chain()
    chain_ok, chain_msg = bc.verify_chain_integrity(chain)
    if not chain_ok:
        add_security_alert("CRITICAL", f"Integridad blockchain comprometida: {chain_msg}")

    return render_template(
        'security_panel.html',
        logs=list(reversed(decrypted_logs)),
        alerts=list(reversed(SECURITY_ALERTS)),
        tamper_detected=tamper_detected,
        chain_ok=chain_ok,
        chain_msg=chain_msg,
        chain_length=len(chain)
    )


if __name__ == '__main__':
    init_system()
    app.run(debug=False)