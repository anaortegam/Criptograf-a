from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import os
from BankCertificator import BankCertificator



PATH = os.getcwd()
BankCertificator = BankCertificator()
FolderPEM_private = PATH + "/DataBase/PEM_private/"
FolderPEM_public = PATH + "/DataBase/PEM_public/"
FolderCertificate = PATH + "/DataBase/Certificate"
if not os.path.exists(FolderCertificate):
    os.makedirs(FolderCertificate)

class Banco:
    """
    Clase de las entidades banco
    """

    def __init__(self, RegName):
        # Almacenar información del usuario
        self.RegName = RegName
        self.private_key = self.cargar_o_generar_clave_privada()
        self.public_key = self.cargar_o_generar_clave_publica()
        self.certificate = None
        self.signature = None
        self.tbs_certificate_bytes = None
        self.solicitar_certificado()


        print("Certificado de ", self.RegName, self.certificate)
        # Generar una clave privada y pública RSA
    def cargar_o_generar_clave_privada(self):
        """ Si tiene clave privada se lee del fichero,
        sino se genera y gusrda en el fichero """

        archivo_nombre= f"{FolderPEM_private}/{self.RegName}.pem"
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

        archivo_nombre = f"{FolderPEM_public}/{self.RegName}.pem"
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

    def sign_message(self, message):
        """ Utiliza la clave privada del banco para que cuando le
        llegue el mensaje al receptor sepa que es suya.
        Para firmar se crea un hash del mensaje y se firma el hash """

        hash = hashes.Hash(hashes.SHA256())
        hash.update(message)
        hashed_message = hash.finalize()
        signature = self.private_key.sign(hashed_message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
        print(signature.hex())
        return signature

    def solicitar_certificado(self):
        """ Si tiene un certificado lo lee del fichero,
         sino se genera una solicitud y, al recibir el
         certificado firmado se guarda en el fichero"""

        archivo_nombre = FolderCertificate + f"/{self.RegName}.pem"
        try:
            with open(archivo_nombre, 'rb') as archivo:
                # Intenta cargar el certificado desde el archivo PEM
                certificate = serialization.load_pem_parameters(archivo.read())

        except:
            # Si no tiene certificado creado se genera una solicitud y se envía para verificar y firmar
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.RegName),
                x509.NameAttribute(NameOID.COMMON_NAME, self.RegName+".com"),])
                ).sign(self.private_key, hashes.SHA256())
            certificate = BankCertificator.certificar(csr)
            self.guardar_certificado(archivo_nombre, certificate)
        self.certificate = certificate
        self.signature = self.certificate.signature
        self.tbs_certificate_bytes = self.certificate.tbs_certificate_bytes

    def guardar_certificado(self, archivo_nombre, certificate):
        with open(archivo_nombre, 'wb') as archivo:
            archivo.write(certificate.public_bytes(serialization.Encoding.PEM))


    def renovar_certificado(self):
        """ Si el certificado ha expirado se vuelve a crear
         una solicitud para que sea frimada"""

        # Si el certificado ha dejado de ser válido se vuelve a solicitar
        archivo_nombre = FolderCertificate + f"/{self.RegName}.pem"
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.RegName),
            x509.NameAttribute(NameOID.COMMON_NAME, self.RegName + ".com"), ])
        ).sign(self.private_key, hashes.SHA256())
        certificate = BankCertificator.certificar(csr)
        self.guardar_certificado(archivo_nombre, certificate)
        self.certificate = certificate
        self.signature = self.certificate.signature
        self.tbs_certificate_bytes = self.certificate.tbs_certificate_bytes






