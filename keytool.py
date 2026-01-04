import argparse
import json
import os
import getpass
import hashlib
import binascii
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID
import cryptography.x509 as x509

KEYSTORE_VERSION = 2

def hash_password(password, salt=None):
    """Genera hash de contraseña usando PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    else:
        salt = binascii.unhexlify(salt)
    
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(pwd_hash).decode()

def verify_password(stored_salt, stored_hash, password):
    """Verifica si la contraseña coincide con el hash almacenado."""
    _, new_hash = hash_password(password, stored_salt)
    return new_hash == stored_hash

def load_keystore(filename, password=None):
    """Carga y verifica el keystore."""
    if not os.path.exists(filename):
        # Si no existe, devolvemos None para indicar que es nuevo
        return None
        
    try:
        with open(filename, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
         raise ValueError("El archivo keystore está corrupto o no es un JSON válido.")

    if "version" not in data:
        raise ValueError("Archivo de keystore inválido (sin versión)")
        
    # Si el keystore tiene protección de contraseña (versión 2+)
    if "password_hash" in data and "salt" in data:
        if password is None:
             raise ValueError("Se requiere contraseña para abrir este keystore.")
        
        if not verify_password(data["salt"], data["password_hash"], password):
            raise ValueError(" Contraseña del keystore incorrecta.")
    
    return data

def init_keystore(password):
    """Inicializa una estructura de keystore nueva con contraseña."""
    salt, pwd_hash = hash_password(password)
    return {
        "version": KEYSTORE_VERSION,
        "salt": salt,
        "password_hash": pwd_hash,
        "keys": {}
    }

def save_keystore(filename, data):
    """Guarda el keystore."""
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

def pedir_contraseña(msg):
    while True:
        pwd = getpass.getpass(msg)
        if len(pwd) < 6:
            print("La contraseña debe tener al menos 6 caracteres.")
        else:
            return pwd

def genkey(args):
    alias = args.alias or input("Introduce el alias de la clave: ").strip()
    if not alias:
        print("Debe especificar un alias.")
        return

    keystore_file = args.keystore or input("Introduce el nombre del keystore: ").strip()
    keyalg = args.keyalg or "RSA"
    keysize = int(args.keysize or 2048)

    print("\n=== Creación de par de claves ===")
    
    # 1. Manejo del Keystore
    ks_password = pedir_contraseña("Introduzca la contraseña del almacén de claves: ")
    
    try:
        ks = load_keystore(keystore_file, ks_password)
    except ValueError as e:
        print(str(e))
        return

    if ks is None:
        # Keystore nuevo
        print(f"⚠  El almacén de claves '{keystore_file}' no existe.")
        confirm = pedir_contraseña("Vuelva a escribir la contraseña del almacén de claves: ")
        if confirm != ks_password:
            print(" Las contraseñas no coinciden.")
            return
        ks = init_keystore(ks_password)
        print(" Nuevo almacén de claves creado.")
    
    if alias in ks["keys"]:
        print(f" Error: el alias '{alias}' ya existe en el keystore.")
        return

    # 2. Generación de claves
    key_password = pedir_contraseña(f"Introduzca la contraseña para <{alias}>: ")
    # (Opcional: permitir misma password que keystore si se deja en blanco, comportamiento keytool)
    
    if keyalg.upper() == "RSA":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=keysize)
    elif keyalg.upper() == "EC":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        print(" Algoritmo no soportado. Use RSA o EC.")
        return

    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key_password.encode())
    ).decode()

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    ks["keys"][alias] = {"private": pem_private, "public": pem_public}

    save_keystore(keystore_file, ks)
    print(f"Clave '{alias}' generada y almacenada en '{keystore_file}' correctamente.")


def certreq(args):
    alias = args.alias or input("Introduce el alias de la clave: ").strip()
    keystore_file = args.keystore or input("Introduce el nombre del keystore: ").strip()

    print("\n=== Generación de CSR ===")
    ks_password = pedir_contraseña("Introduzca la contraseña del almacén de claves: ")

    try:
        ks = load_keystore(keystore_file, ks_password)
    except ValueError as e:
        print(str(e))
        return # Salir si falla la auth del keystore

    if ks is None:
        print(f" Error: El archivo keystore '{keystore_file}' no existe.")
        return

    if alias not in ks["keys"]:
        print(f" No existe el alias '{alias}' en el keystore.")
        return

    key_password = pedir_contraseña(f"Introduzca la contraseña para <{alias}>: ")

    try:
        private_key = serialization.load_pem_private_key(
            ks["keys"][alias]["private"].encode(),
            password=key_password.encode()
        )
    except Exception:
        print("Contraseña incorrecta para la clave privada.")
        return

    # Datos básicos para la CSR (Simulados como si se pidieran o defaults)
    print("Simulando entrada de datos para CSR (CN, OU, O, etc)...")

    # Para simplicidad de este ejercicio usamos defaults o el alias como CN
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, alias)
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    csr_file = f"{alias}.csr"
    with open(csr_file, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"✅ CSR generada correctamente y guardada en '{csr_file}'.")


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--genkey", action="store_true", help="Generar par de claves")
    parser.add_argument("--certreq", action="store_true", help="Generar CSR")
    parser.add_argument("--help", action="store_true", help="Mostrar ayuda")
    parser.add_argument("--alias", help="Alias de la clave")
    parser.add_argument("--keystore", help="Archivo keystore")
    parser.add_argument("--keyalg", help="Algoritmo de clave (RSA o EC)")
    parser.add_argument("--keysize", help="Tamaño de clave (solo RSA)")

    args = parser.parse_args()

    if args.help or not any([args.genkey, args.certreq]):
        print("""
Uso: keeytool.py [comando] [opciones]
Comandos:
  --genkey     Generar un nuevo par de claves
  --certreq    Generar una CSR desde un alias existente
  --help       Mostrar esta ayuda

Opciones:
  --alias <nombre>       Alias de la clave
  --keystore <archivo>   Archivo del almacén de claves
  --keyalg <algoritmo>   Algoritmo (RSA o EC)
  --keysize <tamaño>     Tamaño (solo RSA)
        """)
        return

    if args.genkey:
        genkey(args)
    elif args.certreq:
        certreq(args)


if __name__ == "__main__":
    main()
