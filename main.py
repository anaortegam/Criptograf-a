import datetime
import cv2
import face_recognition as fr
import numpy as np
import mediapipe as mp
import os
from tkinter import *
from datetime import datetime
from PIL import Image, ImageTk
import imutils
import math
import binascii
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as padding_symmetric
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from usuario import Usuario
from banco import Banco
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from BankMaster import Master
from UserCertificator import UserCertificator
import re
from BankCertificator import BankCertificator

PATH = os.getcwd()


"""
Apartado de funciones
"""
# Estilo de la pantalla del usuario
def Profile():
    global step, conteo, UserName, FolderPathUser, pantalla4

    step = 0
    conteo = 0

    pantalla4 = Toplevel(pantalla)
    pantalla4.title("PERFIL")
    pantalla4.geometry("640x640")
    LoadProfile()

# Estilo de la pantalla de transacciones
def Transation():
    pantalla5 = Toplevel(pantalla)
    pantalla5.title("PERFIL")
    pantalla5.geometry("640x640")
    LoadFile(pantalla5)

# Abrir el archivo de transferencias del usuario
def LoadFile(pantalla5):
    # El nombre del archivo JSON corresponderá al usuario actual, ajusta esto según tu lógica
    user_json_file = f"{FolderTransfers}/{usuario_trans}.json"

    try:
        with open(user_json_file, "r") as file:
            user_data = json.load(file)

            # Crear un widget de Text en pantalla5
            text_widget = Text(pantalla5)
            text_widget.pack(fill="both", expand=True)

            # Cargar clave privada del usuario actual
            usuario_actual = next((u for u in usuarios_class if u.RegUser == usuario_trans), None)
            if usuario_actual is not None:
                clave_privada = usuario_actual.private_key

            contador = 0
            messages = user_data.get("messages", [])
            for message in messages:
                contador += 1
                text_widget.insert("end", f"\nOperacion: {contador}\n")
                for key in message:
                    banco = Banco("Santander")
                    # Descifrar el valor cifrado con la clave privada del usuario actual
                    fichero = f"{FolderPEM_public}{banco.RegName}.pem"
                    print(fichero)
                    with (open(fichero, "rb") as file):
                        pem_data = file.read()
                        public_key_banco = serialization.load_pem_public_key(pem_data, backend=default_backend())
                    if VerifyCertificate_bank():
                        #usuario_actual.verify_signature(banco.public_key, bytes.fromhex(message[key][1]), bytes.fromhex(message[key][0]))
                        ciphertext = bytes.fromhex(message[key][0])
                        #ciphersign = bytes.fromhex(message[key][1])
                        decrypted_value = clave_privada.decrypt(
                            ciphertext,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        usuario_actual.verify_signature(banco.public_key, bytes.fromhex(message[key][1]),decrypted_value)

                        uds = "€" if key == "content" else ""
                        if key == "operation" and decrypted_value.decode() == "Recibir bizum":

                            content_value = "+" + decrypted_value.decode()
                        else:
                            content_value = decrypted_value.decode()

                        text_widget.insert("end", f"{key}: {content_value} {uds}\n")

    except FileNotFoundError:
        text_widget = Text(pantalla5)
        text_widget.pack(fill="both", expand=True)
        text_widget.insert("1.0", f"El archivo JSON del usuario {usuario_trans} no existe.")

# Funcion que permite ver el dinero del usuario
def VerImporte():
    global step, conteo, UserName, FolderPathUser, pantalla6


    pantalla6 = Toplevel(pantalla)
    pantalla6.title("PERFIL")
    pantalla6.geometry("640x640")
    LoadImport(pantalla6)

# Muestra el importe por pantalla.
def LoadImport(pantalla6):
    archivo_registro = f"{FolderPathUser}/{User}.txt"
    # Intenta abrir el archivo de registro
    with (open(archivo_registro, "r") as file):
        # Lee el contenido del archivo
        contenido = file.read()

        # Divide el contenido en una lista usando la coma como separador
        componentes = contenido.split(",")
        importe = componentes[4].strip()
        signature = componentes[5].strip()# Esto es la firma?
        usuario_objetivo = next((u for u in usuarios_class if u.RegUser == User), None)
        clave_privada =  usuario_objetivo.private_key
        ciphertext = bytes.fromhex(importe)
        ciphersignature = bytes.fromhex(signature)
        fichero = f"{FolderPEM_public}{banco.RegName}.pem"
        print(fichero)
        with (open(fichero, "rb") as file):
            pem_data = file.read()
            public_key_banco = serialization.load_pem_public_key(pem_data, backend=default_backend())
        if VerifyCertificate_bank():
            decrypted_value = clave_privada.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            usuario_objetivo.verify_signature(public_key_banco, bytes.fromhex(signature), decrypted_value)

            text_widget = Text(pantalla6)
            text_widget.pack(fill="both", expand=True)
            text_widget.insert("end", decrypted_value)

# Reconocimiento facial de log in
def Log_Rec():
    global LogUser, LogPass, FolderPathFace, cap, lblVideo, pantalla3, FaceCode, usuarios, images, pantalla2, step, parpadeo,conteo,UserName, img

    # Check Cap
    if cap is not None and cap.isOpened():
        ret, frame = cap.read()
        frameSave = frame.copy()

        if ret and frame is not None:
            frame = imutils.resize(frame, width=640)
            frameRGB = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            # Type frame
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

            if ret == True:
                resultado = FaceMesh.process(frameRGB)
                px = []
                py = []
                lista = []
                if resultado.multi_face_landmarks:
                    for item in resultado.multi_face_landmarks:


                        for id, puntos in enumerate(item.landmark):
                            alto, ancho, c = frame.shape
                            x, y = int(puntos.x * ancho), int(puntos.y * alto)
                            px.append(x)
                            py.append(y)
                            lista.append([id, x, y])

                            if len(lista) == 468:
                                # Detectar parpados
                                x1, y1 = lista[145][1:]
                                x2, y2 = lista[159][1:]
                                x3, y3 = lista[374][1:]
                                x4, y4 = lista[386][1:]
                                longitud1 = math.hypot(x2 - x1, y2 - y1)
                                longitud2 = math.hypot(x4 - x3, y4 - y3)

                                # Parte izq
                                x6, y6 = lista[368][1:]
                                # Parte dcha
                                x5, y5 = lista[139][1:]

                                # Ceja dcha
                                x7, y7 = lista[70][1:]

                                # Ceja izq
                                x8, y8 = lista[300][1:]

                                cv2.circle(frame, (x1, y1), 2, (255, 0, 0), cv2.FILLED)
                                cv2.circle(frame, (x2, y2), 2, (255, 0, 0), cv2.FILLED)
                                cv2.circle(frame, (x3, y3), 2, (255, 0, 0), cv2.FILLED)
                                cv2.circle(frame, (x4, y4), 2, (255, 0, 0), cv2.FILLED)

                                # Detector cara
                                faces = detector.process(frameRGB)
                                if faces.detections is not None:
                                    for face in faces.detections:
                                        score = face.score
                                        score = score[0]
                                        bbox = face.location_data.relative_bounding_box
                                        ih, iw, _ = frame.shape

                                        if score > confThreshold:
                                            # Coger pixels
                                            xi, yi, an, al = int(bbox.xmin * iw), int(bbox.ymin * ih), int(
                                                bbox.width * iw), int(bbox.height * ih)

                                            # Calcular los desplazamientos (offset)
                                            offsetan = (offsetx / 100) * an
                                            offsetal = (offsety / 100) * al

                                            # Ajustar las coordenadas
                                            xi = int(xi - offsetan / 2)
                                            an = int(an + offsetan)
                                            xf = xi + an
                                            yi = int(yi - offsetal)
                                            al = int(al + offsetal)
                                            yf = yi + al

                                            # Dibujar el rectángulo en la imagen
                                            if step == 0:
                                                cv2.rectangle(frame, (xi, yi), (xi + an, yi + al), (255, 0, 255), 2)

                                                # Face ccenter
                                                if x7 > x5 and x8 < x6:
                                                    # Contador parpadeo
                                                    if longitud1 <= 9 and longitud2 <=9 and parpadeo == False:
                                                        conteo = conteo + 1
                                                        parpadeo = True
                                                    elif longitud1 > 9 and longitud2 > 9 and parpadeo == True:
                                                        parpadeo = False

                                                    if conteo >= 3:

                                                        # Open Eyes
                                                        if longitud1 > 10 and longitud2 > 10:
                                                            step = 1
                                                else:
                                                    conteo = 0

                                            if step == 1:
                                                cv2.rectangle(frame, (xi, yi), (xi + an, yi + al), (25, 100, 25), 2)
                                                faces2= fr.face_locations(frameRGB)
                                                facescod = fr.face_encodings(frameRGB, faces2)

                                                for facecod, facesloc in zip(facescod,faces2):
                                                    #Comparar con las caras almacenadas si se parece a alguna
                                                    Match = fr.compare_faces(FaceCode,facecod)
                                                    simi = fr.face_distance(FaceCode, facecod)
                                                    min = np.argmin(simi)

                                                    if LogUser==usuarios[min]:
                                                        if Match[min]:
                                                            UserName = usuarios[min]
                                                            Profile()
                                                    else:
                                                        no_eres()
                                                        return



            im = Image.fromarray(frame)
            img = ImageTk.PhotoImage(image=im)
            lblVideo.configure(image=img)
            lblVideo.image = img
            lblVideo.after(10, Log_Rec)
    else:
        cap.release()


# Funcion para cerrar pantallas
def Close():
    global step,conteo, pantalla2
    conteo=0
    step=0
    pantalla2.destroy()

# Funcion para cerrar pantallas
def Close2():
    global step,conteo, pantalla3
    conteo=0
    step=0
    pantalla3.destroy()

# Funcion de reconocimiento facial sign up

def Reconocimiento():
    global pantalla2, conteo, parpadeo, img_info, step, cap, lblVideo, RegUser

    #Check Cap
    if cap is not None and cap.isOpened():
        ret,frame = cap.read()


        if ret and frame is not None:
            frame = imutils.resize(frame, width= 640)
            frameRGB = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            #Type frame
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frameSave = frame.copy()
            if ret == True:
                resultado = FaceMesh.process(frameRGB)
                px = []
                py = []
                lista = []
                if resultado.multi_face_landmarks:
                    for item in resultado.multi_face_landmarks:
                        #mpDraw.draw_landmarks(frame, i, FacemeshObject.FACEMESH_TESSELATION, ConfigDraw, ConfigDraw)

                        for id,puntos in enumerate(item.landmark):
                            alto, ancho, c = frame.shape
                            x,y = int(puntos.x * ancho), int(puntos.y*alto)
                            px.append(x)
                            py.append(y)
                            lista.append([id, x, y])

                            if len(lista) == 468:
                                #Detectar parpados
                                x1,y1 = lista[145][1:]
                                x2,y2 = lista[159][1:]
                                x3, y3 = lista[374][1:]
                                x4, y4 = lista[386][1:]
                                longitud1= math.hypot(x2-x1, y2-y1)
                                longitud2 = math.hypot(x4-x3,y4-y3)

                                #Parte izq
                                x6, y6 = lista[368][1:]
                                #Parte dcha
                                x5, y5 = lista[139][1:]

                                #Ceja dcha
                                x7,y7 = lista[70][1:]

                                #Ceja izq
                                x8,y8 = lista[300][1:]

                                #Detector cara
                                faces = detector.process(frameRGB)
                                if faces.detections is not None:
                                    for face in faces.detections:
                                        score = face.score
                                        score = score[0]
                                        bbox= face.location_data.relative_bounding_box
                                        ih, iw, _ = frame.shape

                                        if score > confThreshold:
                                            # Coger pixels
                                            xi, yi, an, al = int(bbox.xmin * iw), int(bbox.ymin * ih), int(
                                                bbox.width * iw), int(bbox.height * ih)

                                            # Calcular los desplazamientos (offset)
                                            offsetan = (offsetx / 100) * an
                                            offsetal = (offsety / 100) * al

                                            # Ajustar las coordenadas
                                            xi = int(xi - offsetan / 2)
                                            an = int(an + offsetan)
                                            xf = xi+an
                                            yi = int(yi - offsetal)
                                            al = int(al + offsetal)
                                            yf= yi+al

                                            # Dibujar el rectángulo en la imagen
                                            if step==0:
                                                cv2.rectangle(frame, (xi, yi), (xi + an, yi + al), (255, 0, 255), 2)

                                                #Face ccenter
                                                if x7 > x5 and x8<x6:
                                                    #Contador parpadeo
                                                    if longitud1<=11 and longitud2<=11 and parpadeo == False:
                                                        conteo = conteo + 1
                                                        parpadeo = True
                                                    elif longitud1>11 and longitud2>11 and parpadeo == True:
                                                        parpadeo= False

                                                    if conteo >= 3:

                                                        #Open Eyes
                                                        if longitud1>12 and longitud2>12:
                                                            cut = frameSave[yi:yf, xi:xf]
                                                            cut_bgr = cv2.cvtColor(cut, cv2.COLOR_RGB2BGR)
                                                            cv2.imwrite(f"{FolderPathFace}/{RegUser}.png", cut_bgr)
                                                            step=1
                                                else:
                                                    conteo=0

                                            if step==1:
                                                cv2.rectangle(frame, (xi, yi), (xi + an, yi + al), (25, 100, 25), 2)



            im = Image.fromarray(frame)
            img = ImageTk.PhotoImage(image=im)
            lblVideo.configure(image= img)
            lblVideo.image = img
            lblVideo.after(10, Reconocimiento)
    else:
        cap.release()


# Funcion que selecciona la cara a guardar en la imagen de reconocimiento
def Code_Face(images):
    listacode= []
    for img in images:
        cod = fr.face_encodings(img)[0]
        listacode.append(cod)
    return listacode

# La persona reconocida no coincide con la imagen guardada
def no_eres():
    nueva_ventana_error_no_eres = Toplevel(pantalla)
    nueva_ventana_error_no_eres .title("Error")
    mensaje_error_no_eres  = Label(nueva_ventana_error_no_eres , text="No eres la persona correspondiente a la cuenta")
    mensaje_error_no_eres .pack()




def LoadProfile():
    """Funcion que pone estilo a la pantalla del usuario, desencripta y muestra los mensajes,
    permite enviar mensajes, ver las transacciones y la cantidad de dinero actual"""

    global UserName, pantalla4, InputUserSend, InputMessage, User, usuario_envia, usuario_trans

    UserFile = open(f"{FolderPathUser}/{UserName}.txt", "r")
    InfoUser = UserFile.read().split(",")
    Name = InfoUser[0]
    User = InfoUser[1]
    if User in usuarios:
        texto1 = Label(pantalla4, text=f"BIENVENIDO {Name}")
        texto1.place(x=0, y=0)

        lblimage = Label(pantalla4)
        lblimage.place(x=0, y=50)

        ImgUser = cv2.imread(f"{FolderPathFace}/{User}.png")
        ImgUser = cv2.cvtColor(ImgUser, cv2.COLOR_BGR2RGB)
        ImgUser = Image.fromarray(ImgUser)

        IMG = ImageTk.PhotoImage(image=ImgUser)
        lblimage.configure(image=IMG)
        lblimage.image = IMG

        usuario_envia = User

        #A quien mandar el mensaje
        texto2 = Label(pantalla4, text=f"Introduce nombre de la persona:")
        texto2.place(x=300, y=70)
        InputUserSend= Entry(pantalla4)
        InputUserSend.place(x=300, y=90)

        #Introducir el mensaje
        texto1 = Label(pantalla4, text=f"Dinero a enviar:")
        texto1.place(x=300, y=120)
        InputMessage = Entry(pantalla4)
        InputMessage.place(x=300, y=140)
        ReconocimientoLog = Button(pantalla4, text="Enviar",  height="2", width="10",command=Mensajes)
        ReconocimientoLog.place(x=500, y=105)
        usuario_trans = User
        Transaccion = Button(pantalla4, text="Transacciones", height="2", width="10", command=Transation)
        Transaccion.place(x=100, y=400)
        Importe = Button(pantalla4, text="Importe", height="2", width="10", command=VerImporte)
        Importe.place(x=400, y=500)
        archivo_registro = f"{FolderPathUser}/{User}.txt"
        try:
            # Intenta abrir el archivo de registro
            with (open(archivo_registro, "r") as file):
                # Lee el contenido del archivo
                contenido = file.read()

                componentes = contenido.split(",")
                #Si el usuario tiene algún mensaje
                if len(componentes) >= 11:

                    messages = componentes[6:]

                    # Crear una lista para almacenar los mensajes desencriptados
                    mensajes_desencriptados = []

                    # Itera sobre los mensajes de cinco en cinco
                    for i in range(0, len(messages), 5):
                        symmetric_key_hex = messages[i].strip()
                        encrypted_message_hex = messages[i + 1].strip()
                        signature = bytes.fromhex(messages[i + 2].strip())
                        sign = bytes.fromhex(messages[i + 3].strip())
                        who_sign = messages[i + 4].strip()

                        with open(f"{FolderPEM_public}/{who_sign}.pem", "rb") as key_file:
                            public_key_sender = serialization.load_pem_public_key(key_file.read())
                        if VerifyCertificate_user(Usuario(who_sign)):
                        # Realiza el procesamiento de los mensajes.
                            nombre_usuario = componentes[1].strip()
                            importe = componentes[4].strip()
                            usuario_objetivo = next((u for u in usuarios_class if u.RegUser == nombre_usuario), None)


                            if usuario_objetivo is not None:
                                #usuario_objetivo.verify_signature(public_key_sender, sign, bytes.fromhex(encrypted_message_hex))
                                clave_privada = usuario_objetivo.private_key
                                clave_publica = usuario_objetivo.obtener_clave_publica().public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                encrypted_symmetric_key = bytes.fromhex(symmetric_key_hex)

                                encrypted_message = bytes.fromhex(encrypted_message_hex)


                                decrypted_symmetric_key = decrypt_symmetric_key(encrypted_symmetric_key, clave_privada).hex()

                                if verify_hmac(bytes.fromhex(decrypted_symmetric_key), encrypted_message, signature):


                                    symmetric_key = decrypted_symmetric_key[:64]
                                    symmetric_iv = decrypted_symmetric_key[64:]
                                    mensaje_desencriptado = decrypt_message_AES(encrypted_message, bytes.fromhex(symmetric_key), bytes.fromhex(symmetric_iv))
                                    print(mensaje_desencriptado)
                                    usuario_objetivo.verify_signature(public_key_sender, sign, mensaje_desencriptado)
                                    mensaje_desencriptado = int(mensaje_desencriptado)
                                    ciphertext = bytes.fromhex(importe)
                                    decrypted_value = clave_privada.decrypt(
                                        ciphertext,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                    )

                                    importe = int(decrypted_value)

                                    importe += int(mensaje_desencriptado)
                                    mensajes_desencriptados.append(mensaje_desencriptado)

                                    public_key = serialization.load_pem_public_key(clave_publica)
                                    if VerifyCertificate_user(usuario_objetivo):

                                        ciphertext_recipient = public_key.encrypt(str(importe).encode(),
                                                                                       padding.OAEP(mgf=padding.MGF1(
                                                                                       algorithm=hashes.SHA256()),
                                                                                                algorithm=hashes.SHA256(),
                                                                                                label=None))


                                        componentes[4] = ciphertext_recipient.hex()
                                        componentes[5] = banco.sign_message(str(importe).encode('utf-8')).hex()

                                        with open(archivo_registro, "w") as file:
                                            # Une los componentes en una cadena separada por comas
                                            file.write(",".join(componentes))

                    y_position = 180  # Posición vertical inicial
                    for mensaje in mensajes_desencriptados:
                        mensaje_label = Label(pantalla4, text=str(mensaje), wraplength=300)
                        mensaje_label.place(x=300, y=y_position)
                        y_position += 30  # Ajusta la separación vertical entre mensajes
                    Mensaje = Button(pantalla4, text="Visto", height="2", width="10", command=Borrar())
                    Mensaje.place(x=300, y=500)


        except FileNotFoundError:
            # El archivo de registro del usuario no existe
            pass

def Borrar():
    """Si el usuario ha accedido se borra el mensaje"""

    archivo_registro = f"{FolderPathUser}/{User}.txt"
    with open(archivo_registro, "r") as file:
        # Lee el contenido del archivo
        contenido = file.read()

    componentes = contenido.split(",")

    # Elimina todas las componentes a partir del índice 4 en la lista
    del componentes[6:]
    contenido_modificado = ",".join(componentes)

    # Escribe el contenido modificado en el archivo
    with open(archivo_registro, "w") as file:
        file.write(contenido_modificado)

# Generacion de salt
def generate_salt():
    return os.urandom(16)

def regex_incorrect():
    """Comprobamos que el formato de la contraseña cumpla con unos requisitos,
     al menos 8 caracteres, una mayuscula, un símbolo y un número"""

    nueva_ventana_error_no_eres = Toplevel(pantalla)
    nueva_ventana_error_no_eres.title("Error")
    mensaje_error_no_eres = Label(nueva_ventana_error_no_eres, text="La contraseña no cumpole el formato")
    mensaje_error_no_eres.pack()



def Reg():
    """ Permite al usuario registrarse, el usuario introduce
    los campos necesarios para el registro de la aplicación. """

    global RegName, RegUser, RegPass, InputNameReg, InputPasswordReg, InputMailReg, cap, lblVideo, pantalla2,pantalla
    #Extraer nombre, usuario y contraseña
    RegName, RegUser = InputNameReg.get(), InputMailReg.get()
    RegPass = InputPasswordReg.get()
    regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$#!%*?&])[A-Za-z\d@$!#%*?&]{8,}$')
    if not regex.match(RegPass):
        regex_incorrect()
        return
    #Incompatibilidades
    if len(RegName)==0 or len(RegUser)==0 or len(RegPass)==0:
        print("Error-No cumple con formato")
    else:

        UserList = os.listdir(FolderPathUserCheck)


        #Lista almacena usuarios
        UserNames= []

        #Comprueba la lista
        for user in UserList:
            #Get user
            User = user
            User = User.split(".")
            UserNames.append(User[0])

        #Comprueba usuario
        if RegUser in UserNames:
            print("Ya estas registrado")
        else:
            usuario = Usuario(RegUser)
            usuarios_class.append(usuario)

            clave_publica_pem = usuario.obtener_clave_publica()

            if VerifyCertificate_user(usuario):

                # Guardar la clave pública en un archivo PEM
                with open(f"{FolderPEM_public}/{RegUser}.pem", 'wb') as archivo:
                    clave_publica_pem_bytes = clave_publica_pem.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    archivo.write(clave_publica_pem_bytes)


                info.append(RegName)
                info.append(RegUser)
                info.append(RegPass)

                # Generar un valor aleatorio para que sea más complicado.
                # Un usuario que tenga la misma contraseña tendrá distinto salt.
                salt = generate_salt()
                # Concatenar
                password = RegPass.encode('utf-8')

                # Configuración de Scrypt
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2 ** 14,
                    r=8,
                    p=1
                )
                # Deriva la clave
                key = kdf.derive(password)
                RegName, RegUser, RegPass = InputNameReg.get(), InputMailReg.get(), InputPasswordReg.get()
                # Almacena el salt, la clave secreta y la contraseña en el archivo de registro como cadenas hexadecimal
                salt_hex = binascii.hexlify(salt).decode()
                key_hex = binascii.hexlify(key).decode()
                dinero = 100
                with open(f"{FolderPEM_public}/{RegUser}.pem", "rb") as key_file:
                    public_key = serialization.load_pem_public_key(key_file.read())
                publica_usuario = load_public_key(RegUser)          #Es el mismo usuario y ya se ha verificado, confiamos en el.
                sign_cipher = banco.sign_message(str(dinero).encode('utf-8'))
                ciphertext_recipient = publica_usuario.encrypt(str(dinero).encode(),
                                                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                            algorithm=hashes.SHA256(), label=None))
                # Escribe el salt y la clave en el archivo de registro
                with open(f"{FolderPathUser}/{RegUser}.txt", "w") as file:
                    file.write(RegName + "," + RegUser + "," + salt_hex + "," + key_hex + "," + ciphertext_recipient.hex()+","+sign_cipher.hex())

                InputNameReg.delete(0, END)
                InputMailReg.delete(0, END)
                InputPasswordReg.delete(0, END)

                #REGISTRO FACIAL
                pantalla2 = Toplevel(pantalla)
                pantalla2.title("Reconocimiento facial")
                pantalla2.geometry("640x640")
                lblVideo = Label(pantalla2)
                lblVideo.place(x=0, y=0)
                pantalla2.protocol("WM_DELETE_WINDOW", Close)
                cap = cv2.VideoCapture(0)
                cap.set(3, 640)
                cap.set(4,640)
                Reconocimiento()


def Log():
    """ Se comprueba que el usuario es quien dice ser. Se comparan la contraseña introducida y derivada con la
    guardada en la base de datos con ese usuario correspondiente, si coinciden el usuario se tendrá que volver a
    autenticar con el reconocimiento facial."""

    global LogUser, LogPass, FolderPathFace, cap, lblVideo, pantalla3,clases,usuarios,FaceCode
    LogUser, LogPass = InputNameLog.get(),InputPasswordLog.get()

    LogUser = InputNameLog.get()
    LogPass = InputPasswordLog.get()


    # Verifica si el usuario y la contraseña coinciden con los registros almacenados
    if verificar(LogUser, LogPass):
        # Inicio de sesión exitoso, abre la ventana de reconocimiento facial
        print("Usuario registrado")
        # Sistema más seguro renovando el salt y la contraseña derivada.
        salt = generate_salt()
        password = LogPass.encode('utf-8')
        # Configuración de Scrypt
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1
        )

        # Deriva la clave
        key = kdf.derive(password)
        salt_hex = binascii.hexlify(salt).decode()
        key_hex = binascii.hexlify(key).decode()
        archivo_registro = f"{FolderPathUser}/{LogUser}.txt"

        try:
            # Intenta abrir el archivo de registro
            with open(archivo_registro, "r") as file:
                # Lee el contenido del archivo
                contenido = file.read()

            componentes = contenido.split(",")

            if len(componentes) >= 4:
                # Actualiza el salt y la clave en la lista
                componentes[2] = salt_hex
                componentes[3] = key_hex

                contenido_modificado = ",".join(componentes)

                # Abre el archivo nuevamente para escribir los cambios
                with open(archivo_registro, "w") as file:
                    file.write(contenido_modificado)

        except FileNotFoundError:
            # El archivo de registro del usuario no existe
            pass

        images = []
        usuarios = []
        lista = os.listdir(FolderPathFace)
        lista2 = os.listdir(FolderPathUser)

        for lis in lista:
            imgdb = cv2.imread(f"{FolderPathFace}/{lis}")
            images.append(imgdb)
            usuarios.append(os.path.splitext(lis)[0])
        #Gaurda las caras en Face_Code
        FaceCode = Code_Face(images)

        for u in lista2:
            componentes = u.split(".")
            user = componentes[0]
            # Busca un objeto Usuario con el mismo nombre de usuario en la lista
            existing_user = next((u for u in usuarios_class if u.RegUser == user), None)
            if existing_user is not None:
                # Si ya existe, usa el objeto existente
                print("Usuario ya existe.")
            else:
                # Si no existe, crea un nuevo objeto Usuario
                print("Creando nuevo usuario...")
                usuarios_class.append(Usuario(user))
        for u in usuarios_class:
            nueva_clave_publica_pem = u.obtener_clave_publica()
            usuario_bd = u.RegUser
            with open(f"{FolderPEM_public}/{usuario_bd}.pem", 'wb') as archivo:
                nueva_clave_publica_pem_bytes = nueva_clave_publica_pem.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                archivo.write(nueva_clave_publica_pem_bytes)

        # Ventana
        pantalla3 = Toplevel(pantalla)
        pantalla3.title("Inicio sesion-rec")
        pantalla3.geometry("640x640")
        lblVideo = Label(pantalla3)
        lblVideo.place(x=0, y=0)
        pantalla3.protocol("WM_DELETE_WINDOW", Close2)
        cap = cv2.VideoCapture(0)
        cap.set(3, 640)
        cap.set(4, 640)
        Log_Rec()
    else:
        mostrar_mensaje_error()

def generate_symmetric_AES():
    key = os.urandom(32)
    iv = os.urandom(16)
    return key, iv


def encrypt_message_AES(message, key, iv):
    """ Encriptar el mensaje utilizando la clave simétrica encriptada con la publica del usuario"""

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding_symmetric.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return encrypted_message


def encriptar_publica(symmetric_key, public_key_other_user):
    """Encriptar la simétrica con la pública del usuario para que sólo él(poseedor de la clave privada)
    pueda acceder al mensaje"""

    encrypted_key = public_key_other_user.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Esto seha rayado y he tenido que poner dos parentesis
    return encrypted_key

def decrypt_symmetric_key(encrypted_symmetric_key, privada):
    """ Usar la clave privada del usuario para desencriptar la clave simétrica"""

    decrypted_key = privada.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def generate_hmac(symmetric_key,message):
    h = hmac.HMAC(symmetric_key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_hmac(symmetric_key, message,signature):
    h = hmac.HMAC(symmetric_key, hashes.SHA256())
    h.update(message)
    generated_signature = h.finalize()
    return signature == generated_signature


def decrypt_message_AES(encrypted_message, symmetric_key, symmetric_iv):
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(symmetric_iv))
    decryptor = cipher.decryptor()

    # Desencriptar el mensaje
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Crear el objeto de desrellenado
    unpadder = padding_symmetric.PKCS7(128).unpadder()

    # Desrellenar el mensaje
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    return unpadded_message


def load_public_key(usuario):
    try:
        # Intenta abrir el archivo PEM de la clave pública
        with open(f"{FolderPEM_public}/{usuario}.pem", 'rb') as archivo:
            # Lee la clave pública desde el archivo PEM
            public_key_bytes = archivo.read()
            # Convierte los bytes en una clave pública
            public_key = serialization.load_pem_public_key(public_key_bytes)
            return public_key
    except FileNotFoundError:
        # El archivo de clave pública del usuario no existe
        pass

def VerifyCertificate_user(user):
    """Verifica los certificados tanto del certificador como
    del usuario para verificar su certificado y poder confiar en el"""

    print("\nVerificacion usuario")

    certificate_ok = False
    while not certificate_ok:
        try:
            MASTER.public_key.verify(MASTER.signature, MASTER.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256(),)
            MASTER.public_key.verify(UserCertificator.signature, UserCertificator.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256(),)
            UserCertificator.public_key.verify(user.signature, user.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256(),)
            print("Verificación user exitosa")
            return True
        except:
            print("Verificación user erronea")
            user.renovar_certificado()
            UserCertificator.renovar_certificado()
            MASTER.renovar_certificado()
            certificate_ok = True
    return False

def VerifyCertificate_bank():
    """Verifica los certificados tanto del certificador como
    del banco para verificar su certificado y poder confiar en el"""

    print("\nVerificacion banco")
    certificate_ok = False
    while not certificate_ok:
        try:
            MASTER.public_key.verify(UserCertificator.signature, UserCertificator.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256(),)
            BankCertificator.public_key.verify(banco.signature, banco.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256(),)
            print("Verificación banco exitosa")
            return True
        except:
            print("Verificación banco erronea")
            banco.renovar_certificado()
            BankCertificator.renovar_certificado()
            certificate_ok = True

    return False
def Mensajes():
    """Encargada de transmitir cualquier tipo de mensaje a los usuarios correspondientes """

    global symmetric_key

    # Coger la info de lo introducido
    username = InputUserSend.get()
    message_to_send = InputMessage.get()
    archivo_registro = f"{FolderPathUser}/{LogUser}.txt"
    try:
        # Intenta abrir el archivo de registro
        with (open(archivo_registro, "r") as file):
            # Lee el contenido del archivo
            contenido = file.read()
            componentes = contenido.split(",")
        importe = componentes[4].strip()
        personlog = next((u for u in usuarios_class if u.RegUser == LogUser), None)
        print("Mensaje de "+personlog.RegUser+" enviado.")

        clave_privada = personlog.private_key
        ciphertext = bytes.fromhex(importe)

        decrypted_value = clave_privada.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        importe = int(decrypted_value)

        importe -= int(message_to_send)
        if VerifyCertificate_user(Usuario(LogUser)):
            sign_message = banco.sign_message(str(importe).encode('utf-8'))

            with open(f"{FolderPEM_public}/{LogUser}.pem", "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())
            publica_usuario = load_public_key(LogUser)
            ciphertext_sender_money = publica_usuario.encrypt(str(importe).encode(),
                                                           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                        algorithm=hashes.SHA256(), label=None))

            componentes[4] = ciphertext_sender_money.hex()
            componentes[5] = sign_message.hex()
            with open(archivo_registro, "w") as file:
                file.write(",".join(componentes))
    except FileNotFoundError:
        pass

    usuario_objetivo = next((u for u in usuarios_class if u.RegUser == username), None)

    usuario_objetivo = usuario_objetivo.RegUser

    try:
        with open(f"{FolderTransfers}/{usuario_objetivo}.json", "r") as file:
            # Intenta cargar el archivo JSON
            user_data = json.load(file)
    except (FileNotFoundError, json.decoder.JSONDecodeError):

        user_data = {"messages": []}

    current_datetime = datetime.now()

    formatted_date_time = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
    with open(f"{FolderPEM_public}/{usuario_objetivo}.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    if VerifyCertificate_user(Usuario(usuario_objetivo)):

        public_objetivo = load_public_key(usuario_objetivo)


        ciphertext_message = public_objetivo.encrypt(message_to_send.encode(),
                                                     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=None))
        sign_message = banco.sign_message(message_to_send.encode('utf-8'))

        ciphertext_date_time = public_objetivo.encrypt(formatted_date_time.encode(),
                                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
        sign_date_time = banco.sign_message(formatted_date_time.encode('utf-8'))

        ciphertext_operation = public_objetivo.encrypt("Recibir bizum".encode(),
                                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
        sign_operation = banco.sign_message("Recibir bizum".encode('utf-8'))

        ciphertext_sender = public_objetivo.encrypt(usuario_envia.encode(),
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
        sign_sender = banco.sign_message(usuario_envia.encode('utf-8'))

        ciphertext_recipient = public_objetivo.encrypt(usuario_objetivo.encode(),
                                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
        sign_recipient = banco.sign_message(usuario_objetivo.encode('utf-8'))


        new_message = {
            "content": [ciphertext_message.hex(), sign_message.hex()],
            "date_time": [ciphertext_date_time.hex(), sign_date_time.hex()],
            "operation": [ciphertext_operation.hex(), sign_operation.hex()],
            "sender": [ciphertext_sender.hex(), sign_sender.hex()],
            "receiver": [ciphertext_recipient.hex(), sign_recipient.hex()]
        }

        messages = user_data["messages"]

        messages.append(new_message)

        # Guardar el archivo JSON actualizado
        with open(f"{FolderTransfers}/{usuario_objetivo}.json", "w") as file:
            json.dump(user_data, file, indent=5)


    try:
        with open(f"{FolderTransfers}/{usuario_envia}.json", "r") as file:
            user_data = json.load(file)
    except FileNotFoundError:

        user_data = {"messages": []}

    current_datetime = datetime.now()

    formatted_date_time = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
    with open(f"{FolderPEM_public}/{usuario_envia}.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    public_envia = load_public_key(usuario_envia)
    if VerifyCertificate_user(Usuario(usuario_envia)):

        ciphertext_message = public_envia.encrypt(message_to_send.encode(),
                                                     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=None))
        sign_message = banco.sign_message(message_to_send.encode('utf-8'))

        ciphertext_date_time = public_envia.encrypt(formatted_date_time.encode(),
                                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
        sign_date_time = banco.sign_message(formatted_date_time.encode('utf-8'))

        ciphertext_operation = public_envia.encrypt("Enviar bizum".encode(),
                                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
        sign_operation = banco.sign_message("Enviar bizum".encode('utf-8'))

        ciphertext_sender = public_envia.encrypt(usuario_envia.encode(),
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
        sign_sender = banco.sign_message(usuario_envia.encode('utf-8'))

        ciphertext_recipient = public_envia.encrypt(usuario_objetivo.encode(),
                                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
        sign_recipient = banco.sign_message(usuario_objetivo.encode('utf-8'))


        new_message = {
            "content": [ciphertext_message.hex(), sign_message.hex()],
            "date_time": [ciphertext_date_time.hex(), sign_date_time.hex()],
            "operation": [ciphertext_operation.hex(), sign_operation.hex()],
            "sender": [ciphertext_sender.hex(), sign_sender.hex()],
            "receiver": [ciphertext_recipient.hex(), sign_recipient.hex()]

        }

        messages = user_data["messages"]

        messages.append(new_message)

        # Guardar el archivo JSON actualizado
        with open(f"{FolderTransfers}/{usuario_envia}.json", "w") as file:
            json.dump(user_data, file, indent=5)

    if VerifyCertificate_user(Usuario(usuario_objetivo)):
        # Obtener la clave pública del usuario destinatario.4
        clave_publica_destinatario = load_public_key(usuario_objetivo)


        try:
            with open(f"{FolderSymetric}/{User}.json", "r") as file:
                # Intenta cargar el archivo JSON
                user_data = json.load(file)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            # Si el archivo no existe o no se puede cargar, crea un diccionario vacío para user_data
            user_data = {"messages": []}

        symmetric_key = None
        for message in user_data["messages"]:
            if username in message:
                symmetric_key_hex = message[username]["key"]
                symmetric_iv_hex = message[username]["iv"]
                break
        if symmetric_key is None:
            # Genera una nueva clave simétrica
            symmetric_key, symmetric_iv = generate_symmetric_AES()

            symmetric_key_hex = symmetric_key.hex()
            symmetric_iv_hex = symmetric_iv.hex()

            new_message = {username: {"key": symmetric_key_hex, "iv": symmetric_iv_hex}}
            user_data["messages"].append(new_message)


            # Guarda el JSON actualizado en el archivo
            with open(f"{FolderSymetric}/{User}.json", "w") as file:
                json.dump(user_data, file, indent=1)

    try:
        with open(f"{FolderSymetric}/{username}.json", "r") as file:
            user_data = json.load(file)

    except (FileNotFoundError, json.decoder.JSONDecodeError):
        user_data = {"messages": []}
    found = False
    for message in user_data["messages"]:
        if username in message:
            symmetric_key_hex = message[username]["key"]
            symmetric_iv_hex = message[username]["iv"]

            symmetric_key = bytes.fromhex(symmetric_key_hex)
            symmetric_iv = bytes.fromhex(symmetric_iv_hex)

            found = True
            break

    if not found:
        symmetric_key, symmetric_iv = generate_symmetric_AES()
        symmetric_key_hex = symmetric_key.hex()
        symmetric_iv_hex = symmetric_iv.hex()

        new_message = {username: {"key": symmetric_key_hex, "iv": symmetric_iv_hex}}
        user_data["messages"].append(new_message)

        # Guarda el JSON actualizado en el archivo
        with open(f"{FolderSymetric}/{username}.json", "w") as file:
            json.dump(user_data, file, indent=1)

    symmetric_key_combined = symmetric_key + symmetric_iv


    encrypt_symmetric_key = encriptar_publica(symmetric_key_combined, clave_publica_destinatario)

    user = Usuario(usuario_envia)
    sign = user.sign_message(message_to_send.encode('utf-8'))
    print(message_to_send)
    encrypt_message = encrypt_message_AES(message_to_send.encode('utf-8'), symmetric_key, symmetric_iv)

    hash = generate_hmac(symmetric_key_combined, encrypt_message)

    with open(f"{FolderPathUser}/{username}.txt", "a+") as file:

        file.write(","+encrypt_symmetric_key.hex()+","+encrypt_message.hex()+","+hash.hex()+","+sign.hex()+","+usuario_envia)

    InputUserSend.delete(0, 'end')
    InputMessage.delete(0, 'end')

def verificar(username, password):
    """Se comparan la contraseña introducida y derivada con la guardada en la base de datos con ese usuario correspondiente"""

    archivo_registro = f"{FolderPathUser}/{username}.txt"
    try:
        # Intenta abrir el archivo de registro
        with (open(archivo_registro, "r") as file):
            # Lee el contenido del archivo
            contenido = file.read()

            # Divide el contenido en una lista usando la coma como separador
            componentes = contenido.split(",")
            if len(componentes) >= 4:
                # Extrae el salt, la clave secreta y la contraseña almacenados en el archivo
                salt = componentes[2].strip()
                secret_key = componentes[3].strip()

                # Convertir el salt y la clave almacenados a bytes
                salt = bytes.fromhex(salt)
                contraseña_almacenada = bytes.fromhex(secret_key)

                # Configuración de Scrypt
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2 ** 14,
                    r=8,
                    p=1
                )
                password = password.encode('utf-8')

                # Derivar la clave a partir de la contraseña proporcionada
                contraseña_introducida = kdf.derive(password)

                # Compara la contraseña almacenada con el HMAC calculado
                if contraseña_introducida == contraseña_almacenada:
                    return True

    except FileNotFoundError:
        # El archivo de registro del usuario no existe
        pass

    # Si no se encontró el archivo, no coincidió la contraseña o hubo un error, devuelve False
    return False

# El par usuario-contraseña es incorrecto
def mostrar_mensaje_error():
    nueva_ventana_error = Toplevel(pantalla)
    nueva_ventana_error.title("Error")
    mensaje_error = Label(nueva_ventana_error, text="Usuario o contraseña incorrectos")
    mensaje_error.pack()


""" 
Apartado de constantes
"""
# Initialize 'cap' to None
cap = None
RegUser=""

#PATH
FolderPathUser = PATH + "/DataBase/Users"
FolderPathFace = PATH + "/DataBase/Faces"
FolderPathUserCheck= PATH + "/DataBase/Users/"
FolderPathFaceCheck = PATH + "/DataBase/Faces/"
FolderPEM_private = PATH + "/DataBase/PEM_private/"
FolderPEM_public = PATH + "/DataBase/PEM_public/"
FolderTransfers = PATH + "/DataBase/Transfers/"
FolderSymetric = PATH + "/DataBase/Symmetric"
#info
info = []


#Variables
parpadeo = False
conteo = 0
muestra = 0
step = 0

offsety = 40
offsetx = 20

confThreshold = 0.5

#Herramientas
mpDraw = mp.solutions.drawing_utils
ConfigDraw = mpDraw.DrawingSpec(thickness=1, circle_radius=1)

#Malla Facial
FacemeshObject = mp.solutions.face_mesh
FaceMesh = FacemeshObject.FaceMesh(max_num_faces=1)

#Detector de cara
FaceObject = mp.solutions.face_detection
detector = FaceObject.FaceDetection(min_detection_confidence=0.5, model_selection=1)


# Ventana principal
pantalla = Tk()
pantalla.title("BANCO")
pantalla.geometry("640x640")

#Fondo

image_path = os.path.abspath(PATH + "/SetUp/fondo.png")
img_pillow = Image.open(image_path)
imagenF = ImageTk.PhotoImage(img_pillow)

background = Label(image=imagenF, text="Inicio")
background.place(x=0, y=0, relwidth=1, relheight=1)

#Input text Register
#User
InputNameReg = Entry(pantalla)
InputNameReg.place(x=376, y=320)
#Registro
InputMailReg = Entry(pantalla)
InputMailReg.place(x=376, y=363)
#Contraseña
InputPasswordReg = Entry(pantalla)
InputPasswordReg.place(x=376, y=404)

#Input text Login
#User
InputNameLog = Entry(pantalla)
InputNameLog.place(x=97, y=341)
#Contraseña
InputPasswordLog = Entry(pantalla)
InputPasswordLog.place(x=97, y=393)

#Buttoms
#Reg
reconocimiento_image_path = PATH + "/SetUp/reconocimiento.png"
reconocimiento_img_pillow_reg = Image.open(reconocimiento_image_path)
reconocimiento_img_pillow_reg = reconocimiento_img_pillow_reg.resize((60, 60))
reconocimiento_img_photo_reg = ImageTk.PhotoImage(reconocimiento_img_pillow_reg)
ReconocimientoReg = Button(pantalla, text="Registro", image=reconocimiento_img_photo_reg, height="60", width= "60", command= Reg)
ReconocimientoReg.place(x = 431, y = 550)

#Log
reconocimiento_image_path = PATH + "/SetUp/reconocimiento.png"
reconocimiento_img_pillow = Image.open(reconocimiento_image_path)
reconocimiento_img_pillow = reconocimiento_img_pillow.resize((60, 60))
reconocimiento_img_photo = ImageTk.PhotoImage(reconocimiento_img_pillow)
ReconocimientoLog = Button(pantalla, text="Inicio", image=reconocimiento_img_photo, height="60", width= "60", command= Log)
ReconocimientoLog.place(x = 140, y = 550)




"""
Instanciación de las entidades
"""
MASTER = Master()
UserCertificator = UserCertificator()
BankCertificator = BankCertificator()
banco = Banco("Santander")
usuarios_class = []
pantalla.mainloop()
