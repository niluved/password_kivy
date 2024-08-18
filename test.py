
salt = 5

class Esempio:
    def funz(self):
        global variabile
        variabile = 10 + salt
    
a = Esempio()
a.funz()
print(variabile)