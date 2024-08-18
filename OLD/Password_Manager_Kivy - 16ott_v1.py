
import numpy as np
import json
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.recycleview import RecycleView
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.properties import ObjectProperty
from functools import partial


# creo il salt per la generazione della key e lo scrivo in modo da usare sempre lo stesso in futuro (la key generata dopo dovrà infatti essere sempre la stessa, data la stessa master password)
# salt = os.urandom(16)
salt = b'\x80\xfe5<\xabX\x1a\x05u\x10\xde\xeb/\xbc\xe8\xfa'

# creo un salt per la master password dell'utente
salt_mp = 'Tg89hj$!nkF_p9hyermlDR40klpwdSQ'

# imposto i nomi dei file ausiliari per il password manager
rubrica_password = 'big_book.json'
archivio_hash = 'hashed_mp.txt'

# funzione per creare un file json a partire da un dict
def scrivi_file(dict_to_json):

    dict_to_json = json.dumps(dict_to_json)

    with open(rubrica_password, 'w') as file:
        json.dump(dict_to_json, file)
        

# funzione per leggere un file json e salvare il contenuto come un dict (json)
def leggi_file():

    with open(rubrica_password,'r') as file:
        contents = json.load(file)

    return contents

# verifico se esiste già un file contenente le password, altrimenti ne va creato uno vuoto
try:
    with open(rubrica_password,'r') as file:
        pass
except FileNotFoundError:
    diz_vuoto = {}
    scrivi_file(diz_vuoto)
    print('\nRubrica delle password non presente.\nCreata rubrica delle password vuota.\n')

# funzione per convertire la master password salted (in bytes) in versione hash
def hash_mp(j):
    # call the sha512(...) function returns a hash object
    d = hashlib.sha512(j)
    # generate human readable hash of password string
    mp_hash512 = d.hexdigest()
    return mp_hash512

# funzione per mostrare tutti i nomi dei siti presenti nel file
def mostra_le_chiavi():                 
    contents = leggi_file()             # lancio la funzione per leggere dal file json
    contents = json.loads(contents)     # trasformo il contenuto in un dict (json)
    lista_account = contents.keys()     
    return lista_account

def decifratutto(codice):
    # decripto il messaggio cifrato utilizzando la chiave f derivata dal salt e dalla master password che richiedo all'utente (deve essere la stessa inserita all'inizio per funzionare)
    master_password_salted = master_password + salt_mp
    master_password_salted = master_password_salted.encode()

    # genero la chiave derivata dal salt e dalla master password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=500000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password_salted))
    f = Fernet(key)

    # decripto il messaggio cifrato un elemento alla volta (NB 'codice' è una lista con gli elementi criptati) e li accodo in una lista vuota
        
    lista_valori = []

    for i in codice:  
        messaggio_decifrato = f.decrypt(i)
        messaggio_decifrato = messaggio_decifrato.decode()
        lista_valori.append(messaggio_decifrato)

    username = lista_valori[0]
    password = lista_valori[1]
    pin = lista_valori[2]
    username_2 = lista_valori[3]

    return username,password,pin,username_2

# funzione per cifrare. il parametro da passare è il messaggio da cifrare in bytes. la funzione ritorna il messaggio cifrato in bytes
def cifratutto(testo_bytes):
    # cripto il messaggio cifrato utilizzando la chiave f derivata dal salt e dalla master password che richiedo all'utente (deve essere la stessa inserita all'inizio per funzionare)
    master_password_salted = master_password + salt_mp
    master_password_salted = master_password_salted.encode()

    # genero la chiave derivata da salt e da master password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=500000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password_salted))
    f = Fernet(key)

    # cripto il messaggio di esempio con la chiave f appena generata
    messaggio = f.encrypt(testo_bytes)

    return messaggio

# ogni Screen presente nell'app deve essere definito sotto come classe (al limite anche vuota)

class HomePage(Screen):
    def verifica_txt(self):
        try:
            with open(archivio_hash,'r') as file:
                hash_file_contents = file.readline()

                self.parent.current = 'first_page' 
        except FileNotFoundError:
            self.parent.current = 'MP_page'

class MasterPasswordPage(Screen):
    
    def imposta_nuova_mp(self):

        # pulisco la label del warning
        self.ids.label_warning_mp.text = ''
        # registro i valori inseriti dall'utente come variabili (nuova mp e conferma nuova mp)
        master_password = self.ids.input_nuova_mp.text
        conferma_mp = self.ids.input_conferma_nuova_mp.text

        if master_password == conferma_mp and master_password != '':
            # aggiungo il salt alla master password dell'utente
            master_password_salted = master_password + salt_mp             
            master_password_salted = master_password_salted.encode()

            # genero una versione hash della master password
            mp_hashed = hash_mp(master_password_salted)

            # verifico se è un primo accesso (txt non esiste) oppure se l'utente arriva qui dal pulsante 'Reimposta la master password'
            try:
                with open(archivio_hash,'r') as file:
                    hash_file_contents = file.readline()      

                ## inserisco qui la funzione che decritta/reincritta: passo come parametro la nuova master password ##
                self.decritta_reincritta(master_password_salted)

                # crea un popup per conferma la riuscita dell'operazione
                conferma_mp = Popup(title='Avviso', content=Label(text='Master Password creata con successo'), size_hint=(0.8, 0.4))
                conferma_mp.open()
                
                # vado sulla pagina di login
                self.parent.current = 'first_page'  

            except FileNotFoundError:  
                
                # creo il file con la master password in versione hash
                with open(archivio_hash,'w') as file:
                    file.write(mp_hashed)

                # vado sulla pagina di login
                self.parent.current = 'first_page' 
                

        else:
            # ripulisco i campi e scrivo un warning all'utente che le password non coincidono
            self.ids.input_nuova_mp.text = ''
            self.ids.input_conferma_nuova_mp.text = ''
            self.ids.label_warning_mp.text = 'Le password non coincidono!'

    def decritta_reincritta(self, mp_nuova_encoded):
        
        # utilizzo la master password corrente per decrittare tutte le voci crittate presenti in rubrica (user, password, pin e second user)
        contents = leggi_file()
        contents = json.loads(contents)

        # prendo la master password corrente (variabile globale) e la trasformo in bytes
        master_password_salted = master_password + salt_mp             
        master_password_salted = master_password_salted.encode()

        # genero la chiave (f) derivata dal salt e dalla master password corrente per decrittare tutte le voci criptate del dict
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password_salted))
        f = Fernet(key)

        # genero una nuova key derivata (z) dalla nuova master password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(mp_nuova_encoded))
        z = Fernet(key)

        # ciclo nei values (v) del dict. ciascun value in questo caso è una lista, pertanto devo ciclare anche all'interno di ciascuna lista (v) per ciascun elemnto (item)
        nuovi_elementi_cifrati = []
        
        for v in contents.values():
            for item in v:
                # decifro ogni singola voce dei values con la key corrente (f)
                messaggio_cifrato_bytes = item.encode()
                messaggio_decifrato = f.decrypt(messaggio_cifrato_bytes)
                messaggio_decifrato = messaggio_decifrato.decode()
                
                # cripto ogni singola voce dei values con la nuova key (z)
                nuovo_messaggio_bytes = messaggio_decifrato.encode()
                nuovo_messaggio_cifrato = z.encrypt(nuovo_messaggio_bytes)
                nuovo_messaggio_cifrato = nuovo_messaggio_cifrato.decode()
                
                # creo una lista con tutti i valori cifrati con la nuova password
                nuovi_elementi_cifrati.append(nuovo_messaggio_cifrato)
                
        # devo splittare la lista che contiene i valori cifrati in parti uguali, una per ciascuna chiave del dict (uso un metodo di numpy per splittare la lista più grande in piccole "array" di numpy)
        numero_chiavi = len(contents.keys())

        nuovi_elementi_cifrati = np.array_split(nuovi_elementi_cifrati, numero_chiavi)

        # ritrasformo le array di numpy così generate in normali liste di python (tolist() è un metodo di numpy) e le aggrego tutte in una lista (lista_normale)
        lista_normale = []

        for item in nuovi_elementi_cifrati:
            item_normale = item.tolist()
            lista_normale.append(item_normale)

        # creo un nuovo dict con le stesse chiavi dell'originale ma con i valori criptati con la nuova master password
        nuovo_diz = {k: v for k,v in zip(contents.keys(),lista_normale)}
        
        # scrivo il nuovo dict nel file json (la rubrica adesso viene aggiornata con i dati criptati con la nuova master password)
        scrivi_file(nuovo_diz)

        # genero l'hash della nuova master password e la scrivo nel file di testo
        nuova_mp_hashed = hash_mp(mp_nuova_encoded)

        # creo il file con la master password in versione hash
        with open(archivio_hash,'w') as file:
            file.write(nuova_mp_hashed)

class FirstPage(Screen):

    def check_mp(self):
        # imposto la variabile master_password come variabile globale
        global master_password

        # password = b"ciao"
        with open(archivio_hash,'r') as file:
            hash_file_contents = file.readline()

            # confronto la master password digitata dall'utente con quella scritta nel file in hash
            master_password = self.ids.mp_utente.text
            master_password_salted = master_password + salt_mp
            master_password_salted = master_password_salted.encode()

            mp_digitata_hash = hash_mp(master_password_salted)
            
            if mp_digitata_hash != hash_file_contents:
                self.ids.label_welcome.text = 'Accesso negato'
                self.ids.mp_utente.text = ''
            else:
                self.ids.mp_utente.text = ''
                # switcha sulla pagina 'choice_page'
                self.parent.current = 'choice_page'  
            

class ChoicePage(Screen):
    
    def go_to_mp_page(self):
        self.parent.current = 'MP_page'
    
    # funzione per pulire i campi della pagina InserimentoDati quando viene creata
    def pulisci_textinput(self):
        self.manager.get_screen('inserimento_dati').ids.input_account.text = ''   
        self.manager.get_screen('inserimento_dati').ids.input_username.text = ''
        self.manager.get_screen('inserimento_dati').ids.input_password.text = ''
        self.manager.get_screen('inserimento_dati').ids.input_pin.text = ''
        self.manager.get_screen('inserimento_dati').ids.input_username2.text = ''

    # questa funzione serve per aggiornare la lista della rubrica ogni volta che la mostro: si fa creando un istanza del Recycleview tramite id e lanciando la funzione che sta dentro la classe Recycleview
    def refreshview(self):
        # get a reference to the RecycleViewList
        rvobj = self.manager.get_screen('ListaRubrica').ids.rv_list
        # lancio la funzione crea_lista che sta dentro la classe Recycleview
        rvobj.crea_lista()

class Lista(Screen):
    pass

class ChoicePage2(Screen):
    
    def reveal_aggiorna(self,scope):

        contents = leggi_file()             # lancio la funzione per leggere dal file json
        contents = json.loads(contents)     # trasformo il contenuto in un dict (json)

        # individuo gli elementi da mostrare relativi alla chiave scelta nel dict ('selezione' è la variabile globale che riporta il testo dell'account cliccato nel recycleview)
        user_damostrare = contents[selezione][0]    # prendo il primo elemento della lista dei valori della chiave 'site' cioè lo username
        password_damostrare = contents[selezione][1]    # prendo il secondo elemento della lista dei valori della chiave 'site', che è appunto la password, mentre il primo è l'utente
        pin_damostrare = contents[selezione][2] 
        user2_damostrare = contents[selezione][3]

        user_bytes = user_damostrare.encode()
        pwd_bytes = password_damostrare.encode()            # devo trasformare la password criptata in formato bytes
        pin_bytes = pin_damostrare.encode()
        user2_bytes = user2_damostrare.encode()

        lista_dadecifrare = [user_bytes, pwd_bytes, pin_bytes, user2_bytes]

        username,password,pin,username_2 = decifratutto(lista_dadecifrare)      # decripto la password (NB viene ritornata NON più in formato bytes poichè è stata convertita nel 'decifratutto') 

        # verifico se è stato passato l'argomento 'reveal' ('scope'='reveal') per rivelare i dati criptati e passare alla pagina 'vista_Dati', se 'scope' è 'aggiorna' invece la funzione è stata lanciata dal pulsante per aggiornare i dati dell'account e quindi popolo tutti i campi dei textinput con i valori decriptati per essere aggiornati dall'utente
        if scope == 'reveal':
            # cambio il valore del testo di id=label_account che sta nell'altro screen VistaDati e così per tutti gli altri valori
            self.manager.get_screen('vista_dati').ids.label_account.text = selezione    
            self.manager.get_screen('vista_dati').ids.view_username.text = username
            self.manager.get_screen('vista_dati').ids.view_password.text = password
            self.manager.get_screen('vista_dati').ids.view_pin.text = pin
            self.manager.get_screen('vista_dati').ids.view_username_2.text = username_2

        elif scope == 'aggiorna':
            # popolo i campi di testo nella pagina InserimentoDati con i valori decriptati
            self.manager.get_screen('inserimento_dati').ids.input_account.text = selezione    
            self.manager.get_screen('inserimento_dati').ids.input_username.text = username
            self.manager.get_screen('inserimento_dati').ids.input_password.text = password
            self.manager.get_screen('inserimento_dati').ids.input_pin.text = pin
            self.manager.get_screen('inserimento_dati').ids.input_username2.text = username_2

    def rimuovi_account(self):
        contents = leggi_file()             # lancio la funzione per leggere dal file json
        contents = json.loads(contents)         # carica il contenuto e lo converte in dict
        
        site = selezione            # 'selezione' è la variabile globale che riporta il testo dell'account cliccato nel recycleview)
    
        del contents[site]                      # elimina l' elemento 'site'
        scrivi_file(contents)                   # scrive il nuovo contenuto nel file json
        
        # crea un popup per conferma la riuscita dell'operazione
        conferma_eliminazione = Popup(title='Avviso', content=Label(text='Rimozione dati \navvenuta con successo'), size_hint=(0.8, 0.4))
        conferma_eliminazione.open()

        self.parent.current = 'choice_page' 

class InserimentoDati(Screen):

    def aggiungi_password(self):
    
        # imposto le variabili da criptare prendendole dai campi textinput digitati da utente
        site = self.ids.input_account.text
        user = self.ids.input_username.text
        pwd = self.ids.input_password.text
        pin = self.ids.input_pin.text
        user2 = self.ids.input_username2.text
        
        contents = leggi_file()             # lancio la funzione per leggere dal file json
        contents = json.loads(contents)         # carica il contenuto e lo converte in dict
        
        elementi = [user,pwd,pin,user2]
        elementi_criptati = []

        for i in elementi:
            testo_da_cifrare_bytes = i.encode()                      # trasforma lo username da cifrare in bytes
            valore_criptato = cifratutto(testo_da_cifrare_bytes)              # cripto lo username con la chiave generata dalla master password (adesso è in bytes)
            valore_criptato = valore_criptato.decode()                      # trasformo lo username criptata da bytes a stringa
            elementi_criptati.append(valore_criptato)                   # appendo ogni elemento criptato alla lista 

        contents[site] = elementi_criptati             # aggiunge/modifica tutti gli elementi criptati relativi alla chiave 'site' del dict
        
        scrivi_file(contents)                   # scrive il nuovo contenuto nel file json
        
        # crea un popup per conferma la riuscita dell'operazione
        conferma_creazione = Popup(title='Avviso', content=Label(text='Tutti i dati sono stati \ncriptati con successo'), size_hint=(0.8, 0.4))
        conferma_creazione.open()

        self.parent.current = 'choice_page' 

class VistaDati(Screen):
    pass

# dopo gli screen possibili definisco sotto l'oggetto windowmanager che consentirà di switchare dall'uno all'altro
class WindowManager(ScreenManager):
    pass

# creo la classe della lista dei widget (recycleview) per mostrare tutte le voci in rubrica e la metterò dentro la pagina Lista(Screen)
class ListaRubrica(RecycleView):
    
    def __init__(self, **kwargs):
        super(ListaRubrica, self).__init__(**kwargs)

    def printa_account(self, i):
        global selezione # imposto la 'selezione' dell'account cliccato come variabile globale così non devo richiamare la funzione da capo per riaverla (avrei il problema di passargli il parametro di nuovo)
        selezione = self.data[i]["id"]
        return selezione
    
    # imposto la funzione per ricreare la lista del recycleview ogni volta in modo da richiamarla ogni volta che premo il pulsante per entrare in questa pagina
    def crea_lista(self):
        self.lista_account = mostra_le_chiavi()
        self.data = [{
            'text': item, 
            'background_color': (44/255,68/255,68/255),
            'id': item,
            "on_release": partial(self.printa_account, i) 
            } for i, item in enumerate(self.lista_account)]

# qui definisco la classe del pulsante customizzato che voglio usare nella lista rubrica sopra (cioè la Recycleview)
class MyButton(Button):
    pass

class MyButton2(Button):
    pass

# carico il file kv in una variabile e la passerò alla classe App
kv = Builder.load_file('sample_page.kv')

class PasswordManagerApp(App):
    def build(self):
        return kv

PasswordManagerApp().run()
