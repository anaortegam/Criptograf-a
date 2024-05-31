from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os
from BankMaster import Master
from cryptography.hazmat.primitives.asymmetric import padding



MASTER = Master()
PATH = os.getcwd()

FolderPrivate = PATH + "/BankCertificator"

class BankCertificator:
    """
    Clase de la entidad BankCertificator
    """

    def __init__(self):
        self.private_key = self.cargar_o_generar_clave_privada()
        self.public_key = self.cargar_o_generar_clave_publica()
        self.certificate = None
        self.signature = None
        self.tbs_certificate_bytes = None
        self.solicitar_certificado()


    def cargar_o_generar_clave_privada(self):
        """ Si tiene clave privada se lee del fichero,
        sino se genera y gusrda en el fichero """

        archivo_nombre= f"{FolderPrivate}/bank_private.pem"
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
        """ Si tiene clave publica se lee del fichero,
        sino se genera y gusrda en el fichero """

        archivo_nombre = f"{FolderPrivate}/bank_public.pem"
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

    def solicitar_certificado(self):
        """ Si tiene un certificado lo lee del fichero,
         sino se genera una solicitud y se guarda en el
         fichero el certificado firmado recibido"""

        archivo_nombre = PATH+"/BankCertificator/bank_certifado.pem"
        try:
            with open(archivo_nombre, 'rb') as archivo:
                # Intenta cargar el certificado desde el archivo PEM
                certificate = serialization.load_pem_parameters(archivo.read())
        except:
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "SZ"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Suiza"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CertBank"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "bankexclusive.com"),])
                ).sign(self.private_key, hashes.SHA256())
            certificate = MASTER.certificar(csr)
            self.guardar_certificado(archivo_nombre, certificate)
        self.certificate = certificate
        self.signature = self.certificate.signature
        self.tbs_certificate_bytes = self.certificate.tbs_certificate_bytes

    def guardar_certificado(self, archivo_nombre, certificate):
        with open(archivo_nombre, 'wb') as archivo:
            archivo.write(certificate.public_bytes(serialization.Encoding.PEM))

    def certificar(self, csr):
        """ Comprueba la solicitud y si es
        correcta genera el certificado """

        csr.public_key().verify(csr.signature,
           csr.tbs_certrequest_bytes,
           padding.PKCS1v15(),
           csr.signature_hash_algorithm)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(csr.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(seconds=30))
            .sign(self.private_key, hashes.SHA256())
            )
        return certificate


    def renovar_certificado(self):
        """ Si el certificado ha expirado, se genera una nueva
         solicitud y se guarda en el fichero el nuevo certificado """

        archivo_nombre = FolderPrivate + "/bank_certifado.pem"
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SZ"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Suiza"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CertBank"),
            x509.NameAttribute(NameOID.COMMON_NAME, "bankexclusive.com"), ])
        ).sign(self.private_key, hashes.SHA256())
        certificate = Master.certificar(csr)
        self.guardar_certificado(archivo_nombre, certificate)
        self.certificate = certificate
        self.signature = self.certificate.signature
        self.tbs_certificate_bytes = self.certificate.tbs_certificate_bytes