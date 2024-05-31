from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
import os




PATH = os.getcwd()
FolderPrivate = PATH + "/Extern"

class Master:
    """
    Clase de la entidad raiz
    """

    def __init__(self):
        self.private_key = self.cargar_o_generar_clave_privada()
        self.public_key = self.cargar_o_generar_clave_publica()
        self.certificate = None
        self.signature = None
        self.tbs_certificate_bytes = None
        self.auto_cert()
        print("Certificado de MASTER = ", self.certificate)



    def cargar_o_generar_clave_privada(self):
        """ Si tiene clave privada se lee del fichero,
        sino se genera y gusrda en el fichero """

        archivo_nombre= f"{FolderPrivate}/master_private.pem"
        try:
            with open(archivo_nombre, 'rb') as archivo:
                # Intenta cargar la clave privada desde el archivo PEM
                private_key = serialization.load_pem_private_key(archivo.read(), password=None)
        except (FileNotFoundError, ValueError):
            # Si el archivo no existe o no se puede cargar, genera una nueva clave privada
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            # Guarda la nueva clave privada en el archivo PEM
            self.guardar_clave_privada(archivo_nombre, private_key)
        return private_key


    def guardar_clave_privada(self, archivo_nombre, private_key):
        # Guarda la clave privada en un archivo PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(archivo_nombre, 'wb') as archivo:
            archivo.write(private_key_pem)


    def cargar_o_generar_clave_publica(self):
        """ Si tiene clave pública se lee del fichero,
         sino se genera y gusrda en el fichero """

        archivo_nombre = f"{FolderPrivate}/master_public.pem"
        try:
            with open(archivo_nombre, 'rb') as archivo:
                # Intenta cargar la clave pública desde el archivo PEM
                public_key = serialization.load_pem_public_key(archivo.read())
        except (FileNotFoundError, ValueError):
            # Si el archivo no existe o no se puede cargar, genera la clave pública a partir de la privada
            public_key = self.private_key.public_key()
            # Guarda la nueva clave pública en el archivo PEM
            self.guardar_clave_publica(archivo_nombre, public_key)
        return public_key

    def guardar_clave_publica(self, archivo_nombre, public_key):
        # Guarda la clave pública en un archivo PEM
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(archivo_nombre, 'wb') as archivo:
            archivo.write(public_key_pem)

    def auto_cert(self):
        """ Se encarga de crear un certificado certificado
        por la profia entidad al ser la raiz"""

        archivo_nombre = FolderPrivate + "/master_certificate.pem"

        try:
            with open(archivo_nombre, 'rb') as archivo:
                # Intenta cargar la clave pública desde el archivo PEM
                cert = serialization.load_pem_parameters(archivo.read())

        except (FileNotFoundError, ValueError):
            # Si no tiene certificado lo crea y lo certifica por ser la entidad raiz
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Maeztu"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "banco"),
                x509.NameAttribute(NameOID.COMMON_NAME, "banco.com")])
            cert = x509.CertificateBuilder(
                ).subject_name(subject
                ).issuer_name(issuer
                ).public_key(self.public_key
                ).serial_number(x509.random_serial_number()
                ).not_valid_before(datetime.datetime.now(datetime.timezone.utc)
                ).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60)
                ).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
                ).sign(self.private_key, hashes.SHA256())
            # Guarda la nueva clave pública en el archivo PEM
            self.guardar_certificado(archivo_nombre, cert)
        self.tbs_certificate_bytes = cert.tbs_certificate_bytes
        self.signature = cert.signature
        self.certificate = cert

    def guardar_certificado(self, archivo_nombre, cert):
        with open(archivo_nombre, 'wb') as archivo:
            archivo.write(cert.public_bytes(serialization.Encoding.PEM))


    def certificar(self, csr):
        """ Comprueba la validez del certificado y
        lo firma en caso de ser correcto """

        # Comprueba que la solicitud sea correcta
        csr.public_key().verify(csr.signature,
           csr.tbs_certrequest_bytes,
           padding.PKCS1v15(),
           csr.signature_hash_algorithm)

        # Si es correcta lo certifica
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(csr.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(seconds=60))
            .sign(self.private_key, hashes.SHA256())
        )
        return certificate

    def renovar_certificado(self):
        """ Renueva su certificado si su tiempo
        ha expirado y está inválido """

        # Si el certificado ha caducado se vuelve a generar
        archivo_nombre = FolderPrivate + "/master_certificate.pem"
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Maeztu"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "banco"),
            x509.NameAttribute(NameOID.COMMON_NAME, "banco.com")])
        cert = x509.CertificateBuilder(
                ).subject_name(subject
                ).issuer_name(issuer
                ).public_key(self.public_key
                ).serial_number(x509.random_serial_number()
                ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
                ).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60)
                ).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
                ).sign(self.private_key, hashes.SHA256())
        # Guarda la nueva clave pública en el archivo PEM
        self.guardar_certificado(archivo_nombre, cert)
        self.tbs_certificate_bytes = cert.tbs_certificate_bytes
        self.signature = cert.signature
        self.certificate = cert




