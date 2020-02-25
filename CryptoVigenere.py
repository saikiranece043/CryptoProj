import os,sys,math,numpy as np
from scipy.signal import find_peaks


def arroftext(text):
    arrofasc =[]
    for c in text:
        if ord(c) < 256:
            arrofasc.append(ord(c))
    return arrofasc


def summary(text):
    arr = arroftext(text)
    prob = findpdf(text)
    mean =  np.mean(arr)
    std =  np.std(arr)
    mode = getmostfrequent(prob)
    median = np.median(arr)
    entropy = getentropyioc(prob)
    print("Mean %f, Standard Deviation %f, Mode %d, Median %d, (Entropy,Ioc) %s "%(mean,std,mode,median,entropy))

def compareshift(x1,x2):
    """compare two inputs and return 0 or 1 based on their equality"""
    if x1==x2:
        return 1
    return 0

def getioc(ciphertext,shifts,m=256):
    """find index of coincidence for a given cipher text"""
    n =len(ciphertext)
    n=10000
    ioc =[0]
    # we are going to calculate for number of shifts the summation
    for s in range(1,shifts+1):
        sum =0
        # we are going to sum (n-i) times
        for loc in range(1,n-s+1):
            sum = sum + compareshift(ciphertext[loc],(ciphertext[loc+s]))

        sum = sum/ (n - s)
        ioc.append(sum)
    return ioc

def findpdf(text,m=256):
    """country the number of occurrences of a given character in a big text file
    This plot gives a fair idea on the frequency and distribution of the characters"""
    count =[0] * (m)
    probab =[]
    x=[]
    y=[]
    for c in text:
        if ord(c) < 257:
           count[ord(c)]= count[ord(c)]+1

    for i in count:
        probab.append(i/np.sum(count))

    for index,val in enumerate(probab):
        x.append(index)
        y.append(val)

    return probab


def getentropyioc(p):

    entropy =0
    ioc =0

    for prob in p:
        if prob!=0:
            entropy = entropy + prob * math.log(prob, 2)
            ioc = ioc + prob * prob

    return entropy*(-1),ioc


def decrypt(key,ciphertext,m=256):
    """Decryption using the standard method of vigenere cipher"""
    plaintext = ""
    val=[]
    for c in key:
        val.append(ord(c))

    for i, c in enumerate(ciphertext):
        ascva = ord(c)
        k = val[i%len(val)] % m
        plaintext = plaintext + chr((ascva - k ) % m)
    return plaintext


def encrypt(key, plaintext,m=256):
    """Encryption using the standard vigenere cipher"""
    val =[]
    ciphertext= ""
    for c in key:
        #val.append(ord(c) - 65)
        val.append(ord(c))

    for i,c in enumerate(plaintext):
        #ascva = ord(c) - 97
        ascva = ord(c)
        k = val[i%len(val)] % m
        ciphertext = ciphertext + chr((ascva + k ) % m)

    return ciphertext



def getkeylength(ciphertext):
    """for a given cipher text of a vigenere encryption using index of coincidence to find the keylength"""

    ioc = getioc(ciphertext, 64)
    #print(ioc)
    ioc_maxima_freq = find_peaks(ioc, height=0.05)[0]
    result = np.diff(ioc_maxima_freq.tolist())
    resultlst = list(result)
    # print(np.diff(ioc_maxima_freq.tolist()))
    keylength = max(resultlst, key=resultlst.count)
    return keylength


def breakstring(size,text):
    strings =[]
    for i in range(0,size):
        cipher =""
        for start in range(i,len(text),size):
            cipher = cipher+text[start]

        strings.append(cipher)
    return strings



def getmostfrequent(array):
    for idx, val in enumerate(array):
        if np.amax(array) == val:
            return idx
    return 0


def printkey(ciphers):
    # running for every block of cipher text
    key = ""
    for ciphertxtblock in ciphers:
        ciphertxtloc = findpdf(ciphertxtblock)
        #print(getmostfrequent(ciphertxtloc))
        print(chr(getmostfrequent(ciphertxtloc) - 32))
        key = key+ chr(getmostfrequent(ciphertxtloc) - 32)
    return key

def readfile(file):
    with open(file, mode='r',encoding='utf-8') as f:
        text = ''
        for line in f:
            text = text + line

    return text


if sys.argv[1] == 'encrypt':
    key = "donaldsmickey"
    plaintext = readfile(os.getcwd()+'/sample')
    summary(plaintext)
    ciphertext= encrypt(key,plaintext)
    summary(ciphertext)
    keylen= getkeylength(ciphertext)
    probplaintext  = findpdf(plaintext)
    freqcharplaintext = getmostfrequent(probplaintext)
    ent,ixofcoin = getentropyioc(findpdf(ciphertext))
    ciphers = breakstring(keylen,ciphertext)
    print("Length of the key is ",keylen)
    printkey(ciphers)

else:
    ciphertext = readfile(os.getcwd()+'/encrypt')
    keylen= getkeylength(ciphertext)
    print(keylen)
    ent,ixofcoin = getentropyioc(findpdf(ciphertext))
    ciphers = breakstring(keylen,ciphertext)
    key = printkey(ciphers)
    print(key)
    print(decrypt(key,ciphertext))







