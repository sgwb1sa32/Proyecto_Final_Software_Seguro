"""
S-TDD (Security-Test Driven Development) para GODOYCRUZ Marketplace.
Estas pruebas usan MOCKING para ejecutarse en memoria y NO modificar 
los archivos reales (data.json y secure_log.txt).
"""

import unittest
from unittest.mock import patch
import json
import os
import tempfile

# Importamos la app y las funciones de seguridad
from app import app
from security import encrypt_val, decrypt_val, log_event, verify_and_read_logs

class TestSeguridadGodoyCruz(unittest.TestCase):

    def setUp(self):
        """Configuración inicial: Entorno virtualizado (Mocking)"""
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # 1. Base de datos simulada en memoria RAM
        self.mock_db = {
            "users": {
                "cliente1": {"rol": "normal_user", "wallet": encrypt_val(100), "cart": [], "purchased": []},
                "empresa1": {"rol": "company", "wallet": encrypt_val(500), "cart": [], "purchased": []},
                "admin": {"rol": "admin", "wallet": encrypt_val(0), "cart": [], "purchased": []}
            },
            "products": []
        }

        # 2. Parcheamos (Mock) las funciones load_data y save_data de app.py
        # Cuando app.py intente usar load_data, usará nuestra función lambda que devuelve la RAM
        self.patcher_load = patch('app.load_data', side_effect=lambda: self.mock_db)
        self.patcher_save = patch('app.save_data', side_effect=self.mock_save)
        self.patcher_load.start()
        self.patcher_save.start()

        # 3. Creamos un archivo de logs TEMPORAL que se borrará solo al terminar
        self.temp_log = tempfile.NamedTemporaryFile(delete=False, mode='w+', encoding='utf-8')
        self.temp_log.close() # Cerramos para que security.py pueda abrirlo
        
        # Parcheamos la variable LOG_FILE en security.py para que apunte al temporal
        self.patcher_log = patch('security.LOG_FILE', self.temp_log.name)
        self.patcher_log_app = patch('app.LOG_FILE', self.temp_log.name, create=True)
        self.patcher_log.start()
        self.patcher_log_app.start()

    def mock_save(self, data):
        """Esta función intercepta los guardados y los guarda en la RAM del test"""
        self.mock_db = data

    def tearDown(self):
        """Limpieza tras cada prueba: quitamos los parches y borramos el log temporal"""
        self.patcher_load.stop()
        self.patcher_save.stop()
        self.patcher_log.stop()
        self.patcher_log_app.stop()
        
        if os.path.exists(self.temp_log.name):
            os.remove(self.temp_log.name)

    # --- TEST RS1: CONFIDENCIALIDAD Y CRIPTOGRAFÍA ---
    def test_rs1_cifrado_wallet_reversible_y_seguro(self):
        saldo_original = 1500
        saldo_cifrado = encrypt_val(saldo_original)
        
        self.assertNotEqual(str(saldo_original), saldo_cifrado)
        self.assertTrue(saldo_cifrado.startswith("gAAAAA"))
        
        saldo_descifrado = decrypt_val(saldo_cifrado)
        self.assertEqual(saldo_original, saldo_descifrado)

    # --- TEST RS2: CONTROL DE ACCESO (IDOR Y PRIVILEGIOS) ---
    def test_rs2_control_acceso_bloquea_idor(self):
        with self.client.session_transaction() as sess:
            sess['username'] = 'cliente1'
            
        response = self.client.get('/company')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/', response.headers['Location'])

    # --- TEST RS3: FALSIFICACIÓN DE PETICIONES (CSRF) ---
    def test_rs3_proteccion_csrf_bloquea_peticiones_falsas(self):
        with self.client.session_transaction() as sess:
            sess['username'] = 'cliente1'
            sess['csrf_token'] = 'token_seguro_123'
            
        response = self.client.post('/wallet', data={
            'action': 'transfer', 
            'target': 'empresa1',
            'amount': 50
        })
        self.assertEqual(response.status_code, 403)

    # --- TEST RS4: INTEGRIDAD DE AUDITORÍA Y NO REPUDIO ---
    def test_rs4_integridad_logs_detecta_manipulacion(self):
        # 1. Generamos un log válido en el archivo temporal
        log_event("INFO", "cliente1", "Compra realizada", "checkout")
        
        logs, tamper_detected = verify_and_read_logs()
        self.assertFalse(tamper_detected)
        
        # 2. EL ATAQUE: Modificamos el archivo temporal físicamente
        with open(self.temp_log.name, 'r', encoding='utf-8') as f:
            contenido = f.read()
            
        contenido_manipulado = contenido.replace("cliente1", "hacker")
        
        with open(self.temp_log.name, 'w', encoding='utf-8') as f:
            f.write(contenido_manipulado)
            
        # 3. Comprobamos que detecta la corrupción
        _, tamper_manipulado = verify_and_read_logs()
        self.assertTrue(tamper_manipulado)

    # --- TEST RS5: DEFENSA LÓGICA DE NEGOCIO ---
    def test_rs5_evitar_saldos_negativos(self):
        with self.client.session_transaction() as sess:
            sess['username'] = 'cliente1'
            sess['csrf_token'] = 'token_valido'
            
        response = self.client.post('/wallet', data={
            'action': 'sell', 
            'amount': 500,
            'csrf_token': 'token_valido'
        }, follow_redirects=True)
        
        # Leemos nuestra DB simulada en memoria
        saldo_actual = decrypt_val(self.mock_db['users']['cliente1']['wallet'])
        
        self.assertEqual(saldo_actual, 100)
        self.assertIn(b"No tienes suficientes GC", response.data)

if __name__ == '__main__':
    unittest.main(verbosity=2)