from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import os
from UserCertificator import UserCertificator



UserCertificator = UserCertificator()
PATH = os.getcwd()
print(PATH)

FolderPrivate = PATH + "/Privates"
if not os.path.exists(FolderPrivate):
    os.makedirs(FolderPrivate)
FolderCertificate = PATH + "/Certificates"
if not os.path.exists(FolderCertificate):
    os.makedirs(FolderCertificate)

class Usuario:
    """
    Clase de las entidades usuario
    """
    def __init__(self, RegUser):
        # Almacenar información del usuario
        self.RegUser = RegUser
        self.private_key = self.cargar_o_generar_clave_privada()
        self.certificate = None
        self.public_key = self.obtener_clave_publica()
        self.signature = None
        self.tbs_certificate_bytes = None
        self.solicitar_certificado()

        print("Certificado de", self.RegUser, self.certificate)



    def cargar_o_generar_clave_privada(self):
        """ Si tiene clave privada se lee del fichero,
        sino se genera y gusrda en el fichero """

        archivo_nombre= f"{FolderPrivate}/{self.RegUser}.pem"
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


    def obtener_clave_publica(self):
        # Obtener la clave pública en formato PEM

        return self.private_key.public_key()

    def guardar_clave_publica(self, archivo_nombre):
        # Guardar la clave pública en un archivo PEM
        clave_publica_pem = self.obtener_clave_publica()
        with open(archivo_nombre, 'wb') as archivo:
            archivo.write(serialization.load_pem_public_key(clave_publica_pem))
        return clave_publica_pem


    def decrypt_symmetric_key(self, encrypted_symmetric_key):
        """ Desencripta la clave simétrica rercibida en el mensaje """

        decrypted_key = self.private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_key


    def verify_signature(self, public_key, signature, message):
        """ Comprobar que no ha habido ninguna alteración
        del mensaje y la comunicación ha sido correcta"""

        hash = hashes.Hash(hashes.SHA256())
        hash.update(message)
        hashed_message = hash.finalize()

        public_key.verify(
            signature,
            hashed_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Verificación de firma exitosa.")


    def sign_message(self, message):
        """ Utiliza la privada del usuario para que cuando le
         llegue el mensaje al receptor sepa que es suya.
         Para firmar se crea un hash del mensaje y se firma el hash"""

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
        sino se genera una solicitud y se guarda en el
        fichero el certificado firmado recibido"""

        archivo_nombre = FolderCertificate + f"/{self.RegUser}.pem"
        try:
            with open(archivo_nombre, 'rb') as archivo:

                certificate = serialization.load_pem_parameters(archivo.read())

        except:
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Colmenarejo"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.RegUser),
                x509.NameAttribute(NameOID.COMMON_NAME, self.RegUser+".com"),])
                ).sign(self.private_key, hashes.SHA256())
            certificate = UserCertificator.certificar(csr)
            self.guardar_certificado(archivo_nombre, certificate)
        self.certificate = certificate
        self.signature = self.certificate.signature
        self.tbs_certificate_bytes = self.certificate.tbs_certificate_bytes

    def guardar_certificado(self, archivo_nombre, certificate):
        with open(archivo_nombre, 'wb') as archivo:
            archivo.write(certificate.public_bytes(serialization.Encoding.PEM))


    def renovar_certificado(self):
        """ Si el certificado ha expirado, se genera una nueva
        solicitud y se guarda en el fichero el nuevo certificado """

        archivo_nombre = FolderCertificate + f"/{self.RegUser}.pem"
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Colmenarejo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.RegUser),
            x509.NameAttribute(NameOID.COMMON_NAME, self.RegUser + ".com"), ])
        ).sign(self.private_key, hashes.SHA256())
        certificate = UserCertificator.certificar(csr)
        self.guardar_certificado(archivo_nombre, certificate)
        self.certificate = certificate
        self.signature = self.certificate.signature
        self.tbs_certificate_bytes = self.certificate.tbs_certificate_bytes