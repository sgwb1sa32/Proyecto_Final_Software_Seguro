"""Módulo de seguridad criptográfica y auditoría de eventos para GODOYCRUZ."""

import datetime
import hashlib
import hmac
import json

from functools import wraps

from cryptography.fernet import Fernet
from flask import abort, flash, redirect, request, session, url_for

# --- CONFIGURACIÓN CRIPTOGRÁFICA ---
import os
from cryptography.fernet import Fernet

# Obtenemos la clave del entorno y la convertimos a BYTES (.encode())
ENCRYPTION_KEY = os.environ.get("GODOYCRUZ_ENCRYPTION_KEY").encode('utf-8')

cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_val(value):
    """Cifra un valor en texto plano usando cifrado simétrico Fernet."""
    return cipher_suite.encrypt(str(value).encode()).decode('utf-8')

def decrypt_val(encrypted_value):
    """Descifra un valor. Retorna 0 como fail-safe si hay manipulación externa."""
    try:
        return int(cipher_suite.decrypt(encrypted_value.encode('utf-8')).decode())
    except Exception: # pylint: disable=broad-except
        return 0

# --- LOGGING SEGURO Y ALERTAS ---
LOG_FILE = "secure_log.txt"
SECURITY_ALERTS = []

def add_security_alert(level, message):
    """Añade una alerta al buzón global de notificaciones del administrador."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    SECURITY_ALERTS.append({
        "timestamp": timestamp,
        "level": level,
        "message": message
    })

def load_data_for_security():
    """Carga los datos de usuarios exclusivamente para validaciones de seguridad."""
    with open('data.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def log_event(nivel_log, user_id, event_msg, function_name):
    """Registra un evento en texto plano adjuntando una firma criptográfica HMAC."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_entry = f"{timestamp} | {nivel_log} | {user_id} | {event_msg} | Ruta: {function_name}"

    signature = hmac.new(ENCRYPTION_KEY, raw_entry.encode(), hashlib.sha256).hexdigest()
    secure_line = f"{raw_entry} ||| {signature}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(secure_line)

def verify_and_read_logs():
    """Lee el archivo de logs verificando la integridad (Firma HMAC) de cada línea."""
    verified_logs = []
    tamper_detected = False

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        tamper_detected = True
        add_security_alert("CRITICAL", "¡Archivo de logs ELIMINADO! Ha desaparecido.")
        return ["❌ [CRÍTICO] El archivo de auditoría no existe o ha sido borrado."], True

    lineas_reales = [line for line in lines if line.strip()]

    if not lineas_reales:
        tamper_detected = True
        add_security_alert("CRITICAL", "¡Historial VACIADO! Ha sido borrado por completo.")
        return ["❌ [CRÍTICO] El archivo ha sido vaciado manual o maliciosamente."], True

    for idx, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        if " ||| " not in line:
            tamper_detected = True
            add_security_alert(
                "CRITICAL",
                f"Falta Firma: La línea {idx+1} perdió su estructura criptográfica."
            )
            verified_logs.append(f"❌ [LOG CORRUPTO O INYECTADO EN LÍNEA {idx+1}]")
            continue

        raw_data, provided_sig = line.rsplit(" ||| ", 1)
        expected_sig = hmac.new(ENCRYPTION_KEY, raw_data.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, provided_sig):
            tamper_detected = True
            add_security_alert(
                "CRITICAL",
                f"Fallo Integridad: El texto de la línea {idx+1} fue alterado."
            )
            verified_logs.append(f"❌ [ALERTA] Línea {idx+1} alterada. Firma Inválida.")
            continue

        verified_logs.append(f"✅ {raw_data}")

    return verified_logs, tamper_detected

# --- CONTROL DE ACCESO (IDOR) ---
role_hierarchy = {
    "admin": {"implied_roles": {"normal_user", "company"}},
    "company": {"implied_roles": set()},
    "normal_user": {"implied_roles": set()}
}

def monitor1(nivel_log="INFO"):
    """Decorador que registra automáticamente la ejecución de funciones y accesos."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = session.get('username', 'anonimo')
            result = func(*args, **kwargs)
            log_event(nivel_log, user, f"Ejecución de {func.__name__}", func.__name__)
            return result
        return wrapper
    return decorator

def access_control(required_role):
    """Decorador que implementa el control de acceso basado en roles e intercepta IDOR."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            username = session.get('username', 'anonimo')
            data = load_data_for_security()
            user_role = data['users'].get(username, {}).get('rol')

            has_access = (
                user_role == required_role or
                required_role in role_hierarchy.get(user_role, {}).get("implied_roles", set())
            )

            if has_access:
                log_event("INFO", username, f"Acceso a {func.__name__}", func.__name__)
                return func(*args, **kwargs)

            log_event("WARNING", username, f"Intento violación en {func.__name__}", func.__name__)
            add_security_alert(
                "WARNING",
                f"El usuario '@{username}' intentó forzar acceso a '{func.__name__}'."
            )
            flash("Acceso denegado. No tienes permisos para esta acción.", "error")
            return redirect(url_for('index'))
        return wrapper
    return decorator

# --- PROTECCIÓN CSRF ---
def verify_csrf(func):
    """Decorador que intercepta ataques CSRF validando el token de sesión."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if request.method == "POST":
            token = session.get('csrf_token')
            form_token = request.form.get('csrf_token')
            if not token or token != form_token:
                username = session.get('username', 'anonimo')
                log_event("ERROR", username, "Ataque CSRF interceptado", func.__name__)
                add_security_alert(
                    "CRITICAL",
                    f"Ataque CSRF bloqueado hacia '{func.__name__}' del usuario '{username}'."
                )
                abort(403)
        return func(*args, **kwargs)
    return wrapper
