
import unittest
import os
import json
from unittest.mock import patch
import keytool

class TestKeytool(unittest.TestCase):
    def setUp(self):
        self.test_keystore = "test_keystore.json"
        if os.path.exists(self.test_keystore):
            os.remove(self.test_keystore)
        if os.path.exists("test_alias.csr"):
            os.remove("test_alias.csr")

    def tearDown(self):
        if os.path.exists(self.test_keystore):
            os.remove(self.test_keystore)
        if os.path.exists("test_alias.csr"):
            os.remove("test_alias.csr")

    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_genkey_new_keystore(self, mock_getpass, mock_input):
        # inputs for alias, keystore, etc are handled effectively by args or stripped inputs
        # But genkey asks for keystore pass twice (for confirmation) if new
        
        # Mock CLI args
        class Args:
            alias = "test_alias"
            keystore = self.test_keystore
            keyalg = "RSA"
            keysize = 2048
            genkey = True
            certreq = False
            help = False

        # Sequence of passwords:
        # 1. "Contraseña del keystore: "
        # 2. "Vuelva a escribir..." (Confirmation)
        # 3. "Contraseña de la clave privada: "
        mock_getpass.side_effect = ["keystorepass", "keystorepass", "keypass"]
        
        keytool.genkey(Args())
        
        self.assertTrue(os.path.exists(self.test_keystore))
        with open(self.test_keystore, 'r') as f:
            data = json.load(f)
            self.assertIn("password_hash", data)
            self.assertIn("salt", data)
            self.assertIn("test_alias", data["keys"])

    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_certreq_auth_success(self, mock_getpass, mock_input):
        # First generate a keystore (reuse logic or manual setup)
        # Manual setup to ensure we test load_keystore logic independently
        salt, pwd_hash = keytool.hash_password("keystorepass")
        data = {
            "version": 2,
            "salt": salt,
            "password_hash": pwd_hash,
            "keys": {
                "test_alias": {
                    "private": "-----BEGIN PRIVATE KEY-----\n...", 
                    "public": "..." 
                } 
            }
        }
        # Need real valid PEM for certreq logic to not crash on serialization
        # actually, easier to just run genkey first
        
        class Args:
            alias = "test_alias"
            keystore = self.test_keystore
            keyalg = "RSA"
            keysize = 2048
            genkey = True
            certreq = False
            help = False
            
        mock_getpass.side_effect = ["keystorepass", "keystorepass", "keypass"]
        keytool.genkey(Args())
        
        # Now test certreq
        class ArgsCertReq:
            alias = "test_alias"
            keystore = self.test_keystore
            genkey = False
            certreq = True
            help = False
            keyalg = None
            keysize = None

        # Sequence:
        # 1. Keystore pass
        # 2. Key pass
        mock_getpass.side_effect = ["keystorepass", "keypass"]
        
        keytool.certreq(ArgsCertReq())
        
        self.assertTrue(os.path.exists("test_alias.csr"))

    @patch('getpass.getpass')
    def test_verify_password_fail(self, mock_getpass):
         # Create a fake file
         salt, pwd_hash = keytool.hash_password("correct")
         data = {
            "version": 2,
            "salt": salt,
            "password_hash": pwd_hash,
            "keys": {}
         }
         with open(self.test_keystore, 'w') as f:
             json.dump(data, f)
             
         with self.assertRaises(ValueError):
             keytool.load_keystore(self.test_keystore, "wrong")

if __name__ == '__main__':
    unittest.main()
