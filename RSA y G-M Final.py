#-------------------------------------Funciones utilizadas-------------------------------------------

def XMCD(a,b):               ##### obteniendo el inverso de eB con el algoritmo extendido de euclides ####
    u0 = 0
    u1 = 1
    v0 = 1
    v1 = 0
    while b > 0:
        cociente = a//b
        residuo = a - b * cociente
        u = cociente * u1 + u0
        v = cociente * v1 + v0

        a = b
        b = residuo

        u0 = int(u1)
        u1 = int(u)
        v0 = int(v1)
        v1 = int(v)
    return v0   #aqui puedo agregar 'a' que representa el MCD

def msg2num(s):                            #### Convierte el mensaje a cifrar a codigo ASCII ####
    n = []
    for c in s:
        a = ord(c)
        a = int(a)
        n.append(a)
    return n

def TFPA(exp,mod,num):                     ##### Cifra el mensaje con llave publica de RSA ####
        bas = 2
        resto = []
        while exp > 0:
            residuo = exp % bas
            exp = (exp - residuo) / bas
            resto.append(residuo)
        A = resto

        tamano = len(A)

        pot = []
        x = num % mod
        pot.append(x)
        for i in range(0, tamano - 1):
            x = (x**2) % mod
            pot.append(x)
        R = pot

        res = 1
        for i in range(0,tamano):
            if A[i] == 1:
                producto = (A[i] * R[i]) % mod
                res = int((res * producto) % mod)

        return res

def numbinario(ctex):             #### Cambia cada numero cifrado en RSA a codigo binario ####
    binar = []
    for x in ctex:
        resto = []
        while x > 0:
            residuo = x % 2
            x = (x - residuo) / 2
            resto.append(residuo)
        binar.append(resto)
    return binar

def encrip_G_M(m1,a1,N1):    ##### Cifra el mensaje el codigo binario (ya cifrado con RSA) a Goldwasser-Micali ####
    import random
    r = random.randint(1,N1)

    if m1 == 0:
        c = (r**2) % N1

    else:
        z = r**2
        c = (a1 * z) % N1

    return c

def binario(m1):                     #### Convierte una lista de co a un numero en base 10 ####
    X=[]
    for i in range(0,len(m1)):
        x = 2 ** i
        X.append(x)

    multiplica = []
    for i in range(0,len(m1)):
        if m1[i] == 1:
            mult = m1[i] * X[i]
            multiplica.append(mult)

    for x in multiplica:
        resultado = 0
        i = 0
        while i in range(0,len(multiplica)):
            resultado = resultado + multiplica[i]
            i = i + 1
    return resultado


#---------------------Preparando la llave publica (Esto le corresponde a Bob)-------------------------------
print '(BOB) PREPARANDO LA LLAVE PUBLICA \n'

p =1223 #73939133#1223 #int(raw_input('Ingrese un numero entero primo p: '))
q =1987 #524287#1987 #int(raw_input('Ingrese un numero entero primo q: '))
eB =948047 #987773#948047 #int(raw_input('Ingresa un numero entero eB: ')) #eA debe ser primo relativo a phi.
a =537 #53737#537 #int(raw_input('Ingresa un numero a: ')) #Elegimos a t.q. a es no residuo cuadratico (mod p) y (mod q).
p1= (p - 1) / 2
N = p * q
phi = (p - 1) * (q - 1)

print'La llave publica es kpub',(N,eB,a),'\n'


#----------------------------------Preparando la llave privada de Bob-----------------------------------
print '(BOB) PREPARANDO LA LLAVE PRIVADA \n'



kpriv = XMCD(eB,phi)
print 'La llave privada es kpriv',(kpriv,p),'\n'


#---------------------------Convirtiendo el mensaje de Alice a Codigo ASCCI-------------------------------
print '(ALICE) ENCRIPTANDO EL MENSAJE \n'

mensaje = str(raw_input('Introduce el mensaje a cifrar para Bob: '))
textnum = msg2num(mensaje)

print 'El mensaje en codigo ASCCI es: \n',textnum,'\n'


#---------------------------------- Cifrando con llave publica de RSA (PRIMER CANDADO)------------------------------------

ctext = []
for k in textnum:
    equis = TFPA(eB,N,k)
    ctext.append(equis)

print 'El texto cifrado con kpub de bob en RSA es: \n',ctext,'\n'


#-------------------------Convirtiendo mensaje cifrado con RSA a codigo binario -----------------------------


AX = numbinario(ctext)
print 'El texto cifrado con kpub de RSA en codigo binario es:\n',AX,'\n'


#------------------Cifrando codigo binario con llave publica de sistema Goldwasser-Micali (SEGUNDO CANDADO) ----------------

GM = []
for k in AX:
    gm = []
    for x in k:
        Z = int(encrip_G_M(x,a,N))
        gm.append(Z)
    GM.append(gm)

print 'Tu texto cifrado con RSA y con Goldwasser-Micali es:\n','INICIA MENSAJE CIFRADO \n',GM,'\nFIN DE MENSAJE CIFRADO \n'


#----------------Decifrando ciphertext con llave privada a en sistema Goldwasser-Micali--------------------------
print '(BOB) DECIFRANDO EL MENSAJE \n'

DGM = []
for k in GM:
    dgm = []
    for j in k:
        Z1 = int(TFPA(p1,p,j))
        if Z1 == 1:
            bi = 0
        else:
            bi = 1
        dgm.append(bi)
    DGM.append(dgm)

print 'Desencriptando Goldwasser-Micali: \n',DGM,'\n'

#-------------------------------------Convirtiendo texto cifrado con RSA en binario a base 10-------------------
PENCIL = []
for x in DGM:
    Pencil = binario(x)
    PENCIL.append(Pencil)

print 'De binario a decimal: \n',PENCIL,'\n'

#---------------------------------Desencriptando ctext con llave privada RSA------------------------------------
DRSA = []
for x in PENCIL:
    drsa = int(TFPA(kpriv,N,x))
    DRSA.append(drsa)

print 'Desenciptacion RSA:\n', DRSA,'\n'

#---------------------Convirtiendo los numeros a sus correspondientes caracteres con codigo ASCCI------------------
Mensaje = []
for c in DRSA:
    letter = chr(c)
    Mensaje.append(letter)

MENSAJE = "".join(Mensaje)
print 'MENSAJE ORIGINA DE ALICE:\n',MENSAJE,'\nFIN DE MENSAJE ORIGINAL'