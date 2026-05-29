"""Módulo principal de la aplicación GODOYCRUZ Marketplace."""

import json
import os
import secrets

from flask import Flask, flash, redirect, render_template, request, session, url_for

from security import (
    SECURITY_ALERTS, access_control, decrypt_val, encrypt_val,
    monitor1, verify_and_read_logs, verify_csrf
)
app = Flask(__name__)
# Configuración segura de cookies
app.secret_key = os.environ.get('GODOYCRUZ_SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# --- MANEJO DE DATOS ---
def load_data():
    """Carga los datos de usuarios y productos desde el archivo JSON de forma segura."""
    with open('data.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def save_data(data):
    """Guarda el estado actual del diccionario de datos en el archivo JSON."""
    with open('data.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

# --- CABECERAS DE SEGURIDAD ---
@app.after_request
def add_security_headers(response):
    """Inyecta cabeceras HTTP de seguridad para mitigar XSS y Clickjacking."""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' https://images.unsplash.com;"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def init_system():
    """Inicializa la base de datos aplicando cifrado a las carteras vulnerables."""
    data = load_data()
    changed = False
    for _, info in data['users'].items():
        if "cart" not in info:
            info["cart"] = []
            changed = True
        if str(info['wallet']).isdigit() or "gAAAAABl" in str(info['wallet']):
            info['wallet'] = encrypt_val(0)
            changed = True
    if changed:
        save_data(data)

@app.context_processor
def inject_user():
    """Inyecta variables de sesión globales en el contexto de las plantillas Jinja2."""
    data = load_data()
    username = session.get('username', 'cliente1')

    if username not in data['users']:
        username = 'cliente1'

    session['username'] = username

    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

    user_data = data['users'][username]
    decrypted_wallet = decrypt_val(user_data['wallet'])

    return {
        "current_user": username,
        "user_data": user_data,
        "wallet_balance": decrypted_wallet,
        "all_users": data['users'].keys(),
        "csrf_token": session['csrf_token'],
        "security_alerts": SECURITY_ALERTS
    }

# --- RUTAS DE LA APLICACIÓN ---

@app.route('/switch_user/<username>')
def switch_user(username):
    """Cambia el usuario actual en la sesión para demostraciones."""
    session['username'] = username
    return redirect(url_for('index'))

@app.route('/')
@monitor1(nivel_log="INFO")
def index():
    """Renderiza el catálogo principal de productos."""
    data = load_data()
    return render_template('index.html', products=data['products'])

@app.route('/cart/add/<int:product_id>', methods=['POST'])
@verify_csrf
@access_control("normal_user")
@monitor1(nivel_log="INFO")
def add_to_cart(product_id):
    """Añade un producto específico al carrito del usuario activo."""
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
    """Muestra los productos actualmente en el carrito de compras."""
    data = load_data()
    username = session.get('username', 'cliente1')
    cart = data['users'][username]['cart']
    total = sum(p['price'] for p in cart)
    return render_template('cart.html', cart=cart, total=total)

@app.route('/cart/checkout', methods=['POST'])
@verify_csrf
@access_control("normal_user")
@monitor1(nivel_log="WARNING")
def checkout():
    """Procesa el pago de los artículos del carrito verificando fondos."""
    data = load_data()
    username = session.get('username', 'cliente1')
    comprador = data['users'][username]
    cart = comprador['cart']

    if not cart:
        flash("Tu carrito está vacío.", "error")
        return redirect(url_for('view_cart'))

    total_price = sum(p['price'] for p in cart)
    saldo_actual = decrypt_val(comprador['wallet'])

    if saldo_actual >= total_price:
        comprador['wallet'] = encrypt_val(saldo_actual - total_price)
        for item in cart:
            vendedor = data['users'][item['seller']]
            saldo_empresa = decrypt_val(vendedor['wallet'])
            vendedor['wallet'] = encrypt_val(saldo_empresa + item['price'])
            comprador['purchased'].append(item)

        comprador['cart'] = []
        save_data(data)
        flash(f"Compra realizada con éxito. Total: {total_price} GC.", "success")
    else:
        flash("GodoyCoins insuficientes. Recarga tu Wallet.", "error")

    return redirect(url_for('index'))

@app.route('/wallet', methods=['GET', 'POST'])
@verify_csrf
@monitor1(nivel_log="INFO")
def wallet():
    """Gestiona la billetera del usuario: comprar, retirar o transferir fondos."""
    data = load_data()
    username = session.get('username', 'cliente1')
    user = data['users'][username]
    current_balance = decrypt_val(user['wallet'])

    if request.method == 'POST':
        action = request.form.get('action')
        amount = int(request.form.get('amount', 0))

        if action == 'buy':
            user['wallet'] = encrypt_val(current_balance + amount)
            flash(f"Has comprado {amount} GC con tu tarjeta.", "success")
        elif action == 'sell':
            if current_balance >= amount > 0:
                user['wallet'] = encrypt_val(current_balance - amount)
                flash(f"Has retirado {amount} GC a tu cuenta bancaria.", "success")
            else:
                flash("No tienes suficientes GC o cantidad inválida.", "error")
        elif action == 'transfer':
            target = request.form.get('target')
            if target in data['users'] and current_balance >= amount > 0:
                user['wallet'] = encrypt_val(current_balance - amount)
                saldo_target = decrypt_val(data['users'][target]['wallet'])
                data['users'][target]['wallet'] = encrypt_val(saldo_target + amount)
                flash(f"Transferiste {amount} GC a {target}.", "success")
            else:
                flash("Error en la transferencia. Revisa datos.", "error")

        save_data(data)
        return redirect(url_for('wallet'))

    return render_template('wallet.html', users_list=data['users'].keys())

@app.route('/company', methods=['GET', 'POST'])
@verify_csrf
@access_control("company")
@monitor1(nivel_log="INFO")
def company_dashboard():
    """Panel de empresa para gestionar precios y descripciones de inventario."""
    data = load_data()
    username = session.get('username', 'empresa1')

    if request.method == 'POST':
        p_id = int(request.form.get('product_id'))
        product = next((p for p in data['products'] if p['id'] == p_id), None)

        if product and product['seller'] == username:
            product['price'] = int(request.form.get('price'))
            product['description'] = request.form.get('description')
            save_data(data)
            flash("Producto actualizado correctamente.", "success")
            return redirect(url_for('company_dashboard'))

    my_products = [p for p in data['products'] if p['seller'] == username]
    return render_template('company.html', products=my_products)

@app.route('/admin/security')
@access_control("admin")
@monitor1(nivel_log="INFO")
def admin_security():
    """Centro de control de ciberseguridad para auditar logs y amenazas."""
    decrypted_logs, tamper_detected = verify_and_read_logs()

    return render_template(
        'security_panel.html',
        logs=reversed(decrypted_logs),
        alerts=reversed(SECURITY_ALERTS),
        tamper_detected=tamper_detected
    )

if __name__ == '__main__':
    init_system()
    app.run(debug=False)
