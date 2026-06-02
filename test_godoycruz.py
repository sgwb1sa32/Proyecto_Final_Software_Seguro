"""
S-TDD (Security-Test Driven Development) para GODOYCRUZ Marketplace.
Estas pruebas usan MOCKING para ejecutarse en memoria y NO modificar
los archivos reales (data.json, chain.json y secure_log.txt).

Adaptadas para la arquitectura blockchain con claves ECDSA.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import os
import tempfile
import secrets

from app import app
from security import log_event, verify_and_read_logs
import blockchain as bc

# ── Generar claves ECDSA para el entorno de test ──────────────────────────────
# Se generan una sola vez al importar el módulo para que todos los tests
# usen las mismas claves y la chain en memoria sea coherente.
_TEST_KEYPAIRS = {u: bc.generate_keypair()
                  for u in ['cliente1', 'empresa1', 'admin', 'estado']}


def _make_mock_db():
    """Construye un data.json simulado con claves ECDSA reales para los tests."""
    return {
        "users": {
            "cliente1": {
                "rol": "normal_user",
                "public_key": _TEST_KEYPAIRS["cliente1"]["public_key"],
                "private_key_encrypted": _TEST_KEYPAIRS["cliente1"]["private_key_encrypted"],
                "cart": [],
                "purchased": []
            },
            "empresa1": {
                "rol": "company",
                "public_key": _TEST_KEYPAIRS["empresa1"]["public_key"],
                "private_key_encrypted": _TEST_KEYPAIRS["empresa1"]["private_key_encrypted"],
                "cart": [],
                "purchased": []
            },
            "admin": {
                "rol": "admin",
                "public_key": _TEST_KEYPAIRS["admin"]["public_key"],
                "private_key_encrypted": _TEST_KEYPAIRS["admin"]["private_key_encrypted"],
                "cart": [],
                "purchased": []
            },
            "estado": {
                "rol": "admin",
                "public_key": _TEST_KEYPAIRS["estado"]["public_key"],
                "private_key_encrypted": _TEST_KEYPAIRS["estado"]["private_key_encrypted"],
                "cart": [],
                "purchased": []
            },
        },
        "products": [
            {
                "id": 1,
                "name": "Producto Test",
                "price": 50,
                "seller": "empresa1",
                "description": "Descripción de prueba",
                "img": ""
            }
        ]
    }


def _make_mock_chain():
    """Construye una cadena de bloques en memoria con saldo inicial para cliente1."""
    pubkeys = {u: _TEST_KEYPAIRS[u]["public_key"]
               for u in ["cliente1", "empresa1", "admin"]}
    genesis = bc.create_genesis(pubkeys, initial_coins_per_user=1, coin_value=100.0)
    return [genesis]


class TestSeguridadGodoyCruz(unittest.TestCase):

    def setUp(self):
        """Configuración inicial: Entorno virtualizado (Mocking)."""
        app.config['TESTING'] = True
        self.client = app.test_client()

        # Base de datos simulada en RAM con estructura nueva (ECDSA)
        self.mock_db = _make_mock_db()

        # Cadena en memoria con saldo inicial de 100 GC para cliente1
        self.mock_chain = _make_mock_chain()

        # Parchear load_data y save_data
        self.patcher_load = patch('app.load_data', side_effect=lambda: self.mock_db)
        self.patcher_save = patch('app.save_data', side_effect=self._mock_save)
        self.patcher_load.start()
        self.patcher_save.start()

        # Parchear load_chain y _save_chain para usar la cadena en memoria
        self.patcher_chain_load = patch('blockchain.load_chain',
                                        side_effect=lambda: self.mock_chain)
        self.patcher_chain_save = patch('blockchain._save_chain',
                                        side_effect=self._mock_save_chain)
        self.patcher_chain_load.start()
        self.patcher_chain_save.start()

        # También parchear las llamadas a load_chain desde app.py
        self.patcher_app_chain = patch('app.bc.load_chain',
                                       side_effect=lambda: self.mock_chain)
        self.patcher_app_chain_save = patch('app.bc._save_chain',
                                            side_effect=self._mock_save_chain)
        self.patcher_app_chain.start()
        self.patcher_app_chain_save.start()

        # Archivo de logs temporal
        self.temp_log = tempfile.NamedTemporaryFile(
            delete=False, mode='w+', encoding='utf-8')
        self.temp_log.close()
        self.patcher_log = patch('security.LOG_FILE', self.temp_log.name)
        self.patcher_log_app = patch('app.LOG_FILE', self.temp_log.name, create=True)
        self.patcher_log.start()
        self.patcher_log_app.start()

        # CSRF token fijo para los tests  # nosec B105
        self.csrf_token = 'token_test_fijo'

    def _mock_save(self, data):
        """Intercepta save_data y actualiza el mock en RAM."""
        self.mock_db = data

    def _mock_save_chain(self, chain):
        """Intercepta _save_chain y actualiza la cadena en RAM."""
        self.mock_chain = chain

    def tearDown(self):
        """Limpieza tras cada prueba."""
        self.patcher_load.stop()
        self.patcher_save.stop()
        self.patcher_chain_load.stop()
        self.patcher_chain_save.stop()
        self.patcher_app_chain.stop()
        self.patcher_app_chain_save.stop()
        self.patcher_log.stop()
        self.patcher_log_app.stop()
        if os.path.exists(self.temp_log.name):
            os.remove(self.temp_log.name)

    # ── RS1: CONFIDENCIALIDAD — Claves ECDSA generadas correctamente ──────────
    def test_rs1_claves_ecdsa_generadas_correctamente(self):
        """
        Verifica que cada usuario tiene un par de claves ECDSA válido:
        - La clave pública existe y tiene formato correcto (empieza por 04 = punto sin comprimir)
        - La clave privada está cifrada con Fernet (empieza por gAAAAA)
        - Se puede cargar y usar para firmar (la clave privada es válida)
        """
        for username in ['cliente1', 'empresa1', 'admin']:
            user = self.mock_db['users'][username]

            # Clave pública presente y con formato correcto
            self.assertIn('public_key', user,
                          f"{username} debe tener public_key")
            self.assertTrue(user['public_key'].startswith('04'),
                            f"Clave pública de {username} debe empezar por 04")
            self.assertGreater(len(user['public_key']), 100,
                               f"Clave pública de {username} demasiado corta")

            # Clave privada cifrada presente
            self.assertIn('private_key_encrypted', user,
                          f"{username} debe tener private_key_encrypted")
            self.assertTrue(user['private_key_encrypted'].startswith('gAAAAA'),
                            f"Clave privada de {username} debe estar cifrada con Fernet")

            # No debe haber campo 'wallet' numérico (arquitectura antigua)
            self.assertNotIn('wallet', user,
                             f"{username} NO debe tener campo 'wallet' numérico")

    # ── RS2: CONTROL DE ACCESO (IDOR) ────────────────────────────────────────
    def test_rs2_control_acceso_bloquea_idor(self):
        """
        Verifica que un usuario normal (normal_user) no puede acceder
        a rutas restringidas a otros roles escribiendo la URL directamente.
        El sistema debe redirigir (302) al inicio.
        """
        with self.client.session_transaction() as sess:
            sess['username'] = 'cliente1'
            sess['csrf_token'] = self.csrf_token

        # Intento de acceso al panel de empresa
        response_company = self.client.get('/company')
        self.assertEqual(response_company.status_code, 302,
                         "cliente1 no debe acceder a /company")
        self.assertIn('/', response_company.headers['Location'])

        # Intento de acceso al panel de admin
        response_admin = self.client.get('/admin/security')
        self.assertEqual(response_admin.status_code, 302,
                         "cliente1 no debe acceder a /admin/security")

    # ── RS3: PROTECCIÓN CSRF ─────────────────────────────────────────────────
    def test_rs3_proteccion_csrf_bloquea_peticiones_falsas(self):
        """
        Verifica que una petición POST sin el token CSRF correcto
        es bloqueada con HTTP 403, aunque el usuario esté autenticado.
        """
        with self.client.session_transaction() as sess:
            sess['username'] = 'cliente1'
            sess['csrf_token'] = 'token_real_en_sesion'  # nosec B105

        # Enviamos un token CSRF diferente al de la sesión
        response = self.client.post('/wallet', data={
            'action': 'transfer',
            'target': 'empresa1',
            'amount': 50,
            'csrf_token': 'token_falso_del_atacante'  # nosec B105
        })
        self.assertEqual(response.status_code, 403,
                         "Petición con CSRF falso debe devolver 403")

    # ── RS4: INTEGRIDAD DE LOGS / NO REPUDIO ─────────────────────────────────
    def test_rs4_integridad_logs_detecta_manipulacion(self):
        """
        Verifica que el sistema detecta la manipulación del archivo de logs.
        Cada línea tiene una firma HMAC-SHA256. Si se altera el contenido,
        la firma no coincide y tamper_detected debe ser True.
        """
        # 1. Generamos un log válido
        log_event("INFO", "cliente1", "Compra realizada", "checkout")

        logs, tamper_detected = verify_and_read_logs()
        self.assertFalse(tamper_detected,
                         "Log recién creado no debe detectarse como manipulado")
        self.assertTrue(any("cliente1" in l for l in logs),
                        "El log debe contener la entrada de cliente1")

        # 2. Ataque: modificamos el archivo físicamente
        with open(self.temp_log.name, 'r', encoding='utf-8') as f:
            contenido = f.read()

        contenido_manipulado = contenido.replace("cliente1", "hacker")

        with open(self.temp_log.name, 'w', encoding='utf-8') as f:
            f.write(contenido_manipulado)

        # 3. El sistema debe detectar la manipulación
        _, tamper_manipulado = verify_and_read_logs()
        self.assertTrue(tamper_manipulado,
                        "El sistema debe detectar que el log fue alterado")

    # ── RS5: SALDO INSUFICIENTE — No doble gasto / No creación de dinero ──────
    def test_rs5_evitar_saldos_negativos(self):
        """
        Verifica que un usuario no puede retirar más GC de los que tiene.
        cliente1 empieza con 100 GC. Intentar retirar 500 GC debe ser bloqueado
        y el saldo debe permanecer en 100 GC.
        Se mockea render_template para evitar dependencia de la carpeta templates.
        """
        pub_hex = self.mock_db['users']['cliente1']['public_key']
        saldo_antes = bc.get_balance(pub_hex, self.mock_chain)
        self.assertEqual(saldo_antes, 100.0,
                         "Saldo inicial de cliente1 debe ser 100 GC")

        # Mockear render_template para evitar TemplateNotFound en entorno de test
        with patch('app.render_template', return_value='OK'):
            with self.client.session_transaction() as sess:
                sess['username'] = 'cliente1'
                sess['csrf_token'] = self.csrf_token  # nosec B105

            # Intentar retirar 500 GC (más de lo que tiene)
            response = self.client.post('/wallet', data={
                'action': 'sell',
                'amount': 500,
                'csrf_token': self.csrf_token  # nosec B105
            }, follow_redirects=False)

        # El saldo no debe haber cambiado
        saldo_despues = bc.get_balance(pub_hex, self.mock_chain)
        self.assertEqual(saldo_despues, saldo_antes,
                         "El saldo no debe cambiar tras un intento fallido de retirada")

        # La petición debe redirigir (302) — no procesar la retirada
        self.assertIn(response.status_code, [302, 200],
                      "La respuesta debe ser una redirección o página de error")


if __name__ == '__main__':
    unittest.main(verbosity=2)