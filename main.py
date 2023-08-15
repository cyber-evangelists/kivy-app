# import all the relevant classes
from kivy.app import App
from kivy.uix.widget import Widget
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.uix.popup import Popup
from kivy.uix.floatlayout import FloatLayout
import pandas as pd
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json

def generate_client_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

def generate_shared_secret_on_client(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key

def encrypt_message(shared_secret, message):
    kdf = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=None)
    derived_key = kdf.derive(shared_secret)

    iv = b'0123456789abcdef'
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt_message_on_client(shared_secret, ciphertext):
    kdf = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=None)
    derived_key = kdf.derive(shared_secret)

    iv = b'0123456789abcdef'
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_message.decode()

def get_pem_format_key(public_key):
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem

client_private_key = generate_client_keys()
client_public_key = client_private_key.public_key()
client_public_key_pem = get_pem_format_key(client_public_key)
# class to call the popup function
class PopupWindow(Widget):
	def btn(self):
		popFun()

# class to build GUI for a popup window
class P(FloatLayout):
	pass

# function that displays the content
def popFun():
	show = P()
	window = Popup(title = "popup", content = show,
				size_hint = (None, None), size = (300, 300))
	window.open()

# class to accept user info and validate it
class loginWindow(Screen):
	email = ObjectProperty(None)
	pwd = ObjectProperty(None)
	shares_key = None
	def validate(self):
		
		print('validate',self.email.text,self.pwd.text)
		form_data = {
			'username': self.email.text,
			'password': self.pwd.text,
			'userpublickeypem': str(client_public_key_pem.decode('utf-8'))
        }
		headers = {
        'Content-Type': 'application/json',
        'X-CSRFToken': 'vKKHLjDb9PdhwObdF1cOEikBugzWHHvR',
        'User-Agent': 'PostmanRuntime/7.26.8',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'connection': 'keep-alive'
    	}
		responce = requests.post('http://127.0.0.1:8000/login-patient',data= json.dumps(form_data),headers=headers)

		if responce.status_code == 200:
			data = responce.json()
			self.shares_key = data['shared_key']
			print('login success ',data)
			sm.current = 'logdata'
		else:
			print('login failed',responce.headers,responce.status_code,responce.text)
			sm.current = 'error'

		# validating if the email already exists
		# if self.email.text not in users['Email'].unique():
			# popFun()
		# else:

			# switching the current screen to display validation result
			

			# reset TextInput widget
			# self.email.text = ""
			# self.pwd.text = ""


# class to accept sign up info
class signupWindow(Screen):
	name2 = ObjectProperty(None)
	email = ObjectProperty(None)
	pwd = ObjectProperty(None)
	# def signupbtn(self):
        
		# creating a DataFrame of the info
		# user = pd.DataFrame([[self.name2.text, self.email.text, self.pwd.text]],
							# columns = ['Name', 'Email', 'Password'])
		# if self.email.text != "":
			# if self.email.text not in users['Email'].unique():

				# if email does not exist already then append to the csv file
				# change current screen to log in the user now
				# user.to_csv('login.csv', mode = 'a', header = False, index = False)
				# sm.current = 'login'
				# self.name2.text = ""
				# self.email.text = ""
				# self.pwd.text = ""
		# else:
			# if values are empty or invalid show pop up
			# popFun()
	
# class to display validation result
class logDataWindow(Screen):
	def show_key(self):
		return 'user details'


class ErrorScreen(Screen):
	pass
# class for managing screens
class windowManager(ScreenManager):
	pass

# kv file
kv = Builder.load_file('login.kv')
sm = windowManager()

# reading all the data stored
# users=pd.read_csv('login.csv')

# adding screens
sm.add_widget(loginWindow(name='login'))
sm.add_widget(signupWindow(name='signup'))
sm.add_widget(logDataWindow(name='logdata'))
sm.add_widget(ErrorScreen(name='error'))

# class that builds gui
class loginMain(App):
	def build(self):
		return sm

# driver function
if __name__=="__main__":
	loginMain().run()
