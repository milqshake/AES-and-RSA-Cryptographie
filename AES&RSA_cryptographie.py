from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import PySimpleGUI as sg

def key_generation_rsa():
    # key generation
    global keyPair
    keyPair = RSA.generate(2048)
    global pubKey
    pubKey = keyPair.publickey()
    n = pubKey.n
    e = pubKey.e
    d = keyPair.d
    pubKeyPEM = pubKey.exportKey()
    print("N is:" + str(n) + " \n E is:" + str(e))

    print("D is:" + str(d))
    privKeyPEM = keyPair.exportKey()

def key_generation_aes():
    global key
    key = get_random_bytes(16)
    global aes
    aes = AES.new(key, AES.MODE_CBC)
    global iv
    iv = aes.iv
    print('key', [x for x in key])



def rsa_encryption(values):
    # encryption
    msg = values['-Encryption_Text_RSA-']
    msg_bytes = bytes(msg, 'utf-8')
    encryptor = PKCS1_OAEP.new(pubKey)
    global encrypted
    encrypted = encryptor.encrypt(msg_bytes)
    res="Encrypted: " + str(base64.b64encode(encrypted))
    return res


def rsa_decryption(values):
    # decryption
    msg = values['-Decryption_Text_RSA-']
    msg2 = base64.b64decode(msg)
    str(msg2)
    decryptor = PKCS1_OAEP.new(keyPair)
    decrypted = decryptor.decrypt(msg2)
    res='Decrypted: ', str(decrypted)
    return res



def aes_encryption(values):
    data = values['-Encryption_Text_AES-']
    data_bytes = bytes(data, 'utf-8')
    global encd
    encd = aes.encrypt(pad(data_bytes, AES.block_size))
    res= "Crypted text: " + str(base64.b64encode(encd))
    return res


def aes_decryption(values):
    data = values['-Decryption_Text_AES-']
    data2 = base64.b64decode(data)
    str(data2)
    aes = AES.new(key, AES.MODE_CBC, iv)
    decode = aes.decrypt(data2)
    decode = unpad(decode, AES.block_size)
    res= "Plain text is: " + str(decode)
    return res


def signature_creation(values):
    # signer un message
    message = values['-Signature_Text-']
    global message_byte
    message_byte = bytes(message, 'utf-8')

    h = SHA256.new(message_byte)
    global signature
    signature = pkcs1_15.new(keyPair).sign(h)
    res= "Signature is: "+ str(base64.b64encode(signature))
    return res

def signature_verification(values):
    #verifier la signature
    message = values['-Verification_Text-']
    message2 = bytes(message, 'utf-8')
    h = SHA256.new(message2)
    try:
        pkcs1_15.new(pubKey).verify(h, signature)
        res="The signature is valid."
    except (ValueError, TypeError):
       res= "The signature is not valid."
    return res


def main():
    Layout = [
        [sg.Text("Choose your Action")],
        [sg.Button("Encryption and Decryption")],
        [sg.Button("Signature and Verification")]
    ]

    window1 = sg.Window("Demo", Layout)

    event1, values = window1.read()
    if event1 == "Encryption and Decryption":
        Layout = [
            [sg.Text("Choose your Algorithme")],
            [sg.Button("AES")],
            [sg.Button("RSA")]
        ]
        window2 = sg.Window("Demo", Layout)
        event2, values = window2.read()
        if event2 == "AES":
            #Aes encryption starting
            print(key_generation_aes())
            Layout = [
                [sg.Text("Choose your Action")],
                [sg.Button("Encryption")],
                [sg.Button("Decryption")]
            ]
            window3 = sg.Window("Demo", Layout)
            event3, values = window3.read()
            if event3 == "Encryption":
                Layout = [
                    [sg.Text("Write your Text to encrypt: "),
                     sg.Input(key='-Encryption_Text_AES-', do_not_clear=True, size=(20, 1))],
                    [sg.Button("Encrypt")]
                ]
                window4 = sg.Window("Demo", Layout)
                event4, values = window4.read()
                if event4 == "Encrypt":
                    sg.popup(aes_encryption(values))
                    #window5 = sg.Window("Demo", Layout)
                    #event5, values = window5.read()
            elif event3 == "Decryption":
                Layout = [
                    [sg.Text("Write your Text to decrypt: "),
                     sg.Input(key='-Decryption_Text_AES-', do_not_clear=True, size=(20, 1))],
                    [sg.Button("Decrypt")]
                ]
                window5 = sg.Window("Demo", Layout)
                event5, values = window5.read()
                if event5 == "Decrypt":
                    sg.popup(aes_encryption(values))
        elif event2 == "RSA":
            #RSA encryption starting
            print(key_generation_rsa())
            Layout = [
                [sg.Text("Choose your Action")],
                [sg.Button("Encryption")],
                [sg.Button("Decryption")]
            ]
            window3 = sg.Window("Demo", Layout)
            event3, values = window3.read()
            if event3 == "Encryption":
                Layout = [
                    [sg.Text("Write your Text to encrypt: "),
                     sg.Input(key='-Encryption_Text_RSA-', do_not_clear=True, size=(20, 1))],
                    [sg.Button("Encrypt")]
                ]
                window4 = sg.Window("Demo", Layout)
                event4, values = window4.read()
                if event4 == "Encrypt":
                    sg.popup(rsa_encryption(values))
                    # window5 = sg.Window("Demo", Layout)
                    # event5, values = window5.read()
            elif event3 == "Decryption":
                Layout = [
                    [sg.Text("Write your Text to decrypt: "),
                     sg.Input(key='-Decryption_Text_RSA-', do_not_clear=True, size=(20, 1))],
                    [sg.Button("Decrypt")]
                ]
                window5 = sg.Window("Demo", Layout)
                event5, values = window5.read()
                if event5 == "Decrypt":
                    sg.popup(rsa_encryption(values))

    elif event1 == "Signature and Verification":
        print(key_generation_rsa())
        Layout = [
            [sg.Text("Choose your Action")],
            [sg.Button("Signature")],
            [sg.Button("Verification")]
        ]
        window3 = sg.Window("Demo", Layout)
        event7, values = window3.read()
        if event7 == "Signature":
            Layout = [
                [sg.Text("Write your Text to sign: "),
                 sg.Input(key='-Signature_Text-', do_not_clear=True, size=(20, 1))],
                [sg.Button("Sign")]
            ]
            window5 = sg.Window("Demo", Layout)
            event8, values = window5.read()
            if event8 == "Sign":
                sg.popup(signature_creation(values))
        elif event7 == "Verification":
            Layout = [
                [sg.Text("Write your Text to verify: "),
                 sg.Input(key='-Verification_Text-', do_not_clear=True, size=(20, 1))],
                [sg.Button("verify")]
            ]
            window5 = sg.Window("Demo", Layout)
            event8, values = window5.read()
            if event8 == "verify":
                sg.popup(signature_verification(values))


print(main())

#This is work is done by Zied Selmi
#linkedin: linkedin.com/in/ziedselmi/