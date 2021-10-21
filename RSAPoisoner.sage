from Crypto.Util.number import *

#==============UTILITIES==============
def helper(func):
	def inner(*args, **kwargs):
		transit()
		func(*args, **kwargs)
		end_helper()
	return inner

def transit():
	print()
	print("============================================================")
	print()

def pause():
	input("\nPress Any Key To Continue...")

def end_helper():
	pause()
	transit()
	mainMenu()


#==============ATTACKS==============
def RSA_Encrypt(N, e, pt):
	return pow(pt, e, N)

def RSA_Decrypt_dKnown(N, d, ct):
	return pow(ct, d, N)

def RSA_Decrypt_factorsKnown(N, e, p, q, ct):
	phi = (p-1)*(q-1)
	d = inverse(e, phi)
	return pow(ct, d, N)

def Common_Modulus_External(N, e1, e2, c1, c2):
	assert GCD(e1, e2) == 1
	tmp, u1, u2 = xgcd(e1, e2)
	return (pow(c1, u1, N) * pow(c2, u2, N)) % N

def Common_Modulus_Internal(N, e_pers, d_pers, e_victim):
	k_guess = (e_pers * d_pers - 1) // N
	while (e_pers * d_pers - 1) % k_guess != 0:
		k_guess += 1
	k = k_guess
	phi = (e_pers * d_pers - 1) // k
	return inverse(e_victim, phi)

def Small_Public_Exponent(e, ct):
	return ct ^ (1/e)

def Hastad_Broadcast(e, N, c):
	m_power = crt(c, N)
	return m_power ^ (1/e)

def Wiener(N, e):
	convs = continued_fraction(e/N).convergents()[1:]
	d = None
	for conv in convs:
		k = conv.numerator()
		d = conv.denominator()
		if d % 2 == 0:
			continue
		elif (e*d - 1) % k != 0:
			continue
		phi = (e*d - 1) // k
		a = 1; b = phi-N-1; c = N
		p = int(-b + sqrt(b**2 - 4*a*c))//(2*a)
		q = int(-b - sqrt(b**2 - 4*a*c))//(2*a)
		if p*q == N:
			break
		d = None
	if d == None:
		return "d not found"
	else:
		return d

def Fermat_Factorisation(N):
	a = int(sqrt(N))
	while not is_square(a**2 - N):
		a += 1
	b = a**2 - N
	p = a + sqrt(b)
	q = a - sqrt(b)
	return (p, q)

def Twin_Primes_Factorisation(N):
	p = int(sqrt(N+1) - 1)
	q = p + 2
	if(p*q == N):
		return (p, q)
	else:
		return "No Twin Primes Factorsiation"

def Extract_Modulus_eKnown(m, c, e):
	multiples = []
	for i in range(len(m)):
		multiples.append(pow(m[i], e) - c[i])
	gcd = multiples[0]
	for i in range(1, len(m)):
		gcd = GCD(gcd, multiples[i])
	return gcd

def Extract_Modulus_eUnknown(m, c, sq_c):
	multiples = []
	for i in range(len(m)):
		multiples.append(c[i]**2 - sq_c[i])
	gcd = multiples[0]
	for i in range(1, len(m)):
		gcd = GCD(gcd, multiples[i])
	return gcd

def String_To_Long(string):
	return bytes_to_long(string.encode())

def Long_To_String(long):
	return long_to_bytes(long).decode()

def Hex_To_Long(hex_string):
	return int(hex_string, 16)

def Long_To_Hex(long):
	return hex(long)[2:]

def String_To_Hex(string):
	return string.encode().hex()

def Hex_To_String(hex_string):
	return bytes.fromhex(hex_string).decode()


#==============HELPERS==============
@helper
def RSA_Encrypt_Helper(c):
	N = int(input("Enter N: "))
	e = int(input("Enter e: "))
	pt = int(input("Enter plaintext: "))
	print("\nCiphertext: " + str(RSA_Encrypt(N, e, pt)))

@helper
def RSA_Decrypt_dKnown_Helper():
	N = int(input("Enter N: "))
	d = int(input("Enter e: "))
	ct = int(input("Enter ciphertext: "))
	print("\nPlaintext: " + str(RSA_Decrypt_dKnown(N, d, ct)))

@helper
def RSA_Decrypt_factorsKnown_Helper():
	N = int(input("Enter N: "))
	e = int(input("Enter e: "))
	p = int(input("Enter p: "))
	q = int(input("Enter q: "))
	ct = int(input("Enter ciphertext: "))
	print("\nPlaintext: " + str(RSA_Decrypt_factorsKnown(N, e, p, q, ct)))

@helper
def Common_Modulus_External_Helper():
	N = int(input("Enter N: "))
	e1 = int(input("Enter e1: "))
	e2 = int(input("Enter e2: "))
	c1 = int(input("Enter ciphertext1: "))
	c2 = int(input("Enter ciphertext2: "))
	print("\nPlaintext: " + str(Common_Modulus_External(N, e1, e2, c1, c2)))

@helper
def Common_Modulus_Internal_Helper():
	N = int(input("Enter N: "))
	e_pers = int(input("Enter personal e: "))
	d_pers = int(input("Enter personal d: "))
	e_victim = int(input("Enter victim's e: "))
	print("\nVictim's d: " + str(Common_Modulus_Internal(N, e_pers, d_pers, e_victim)))

@helper
def Small_Public_Exponent_Helper():
	e = int(input("Enter e: "))
	ct = int(input("Enter ciphertext: "))
	print("\nPlaintext:  " + str(Small_Public_Exponent(e, ct)))

@helper
def Hastad_Broadcast_Helper():
	e = int(input("Enter e: "))
	N = []
	for i in range(e):
		N.append(int(input("Enter N" + str(i+1) + ": ")))
	c = []
	for i in range(e):
		c.append(int(input("Enter c" + str(i+1) + ": ")))
	print("\nPlaintext: " + str(Hastad_Broadcast(e, N, c)))

@helper
def Wiener_Helper():
	N = int(input("Enter N: "))
	e = int(input("Enter e: "))
	print("\nd: " + str(Wiener(N, e)))

@helper
def Fermat_Factorisation_Helper():
	N = int(input("Enter N: "))
	print("\nFactors: " + str(Fermat_Factorisation(N)))

@helper
def Twin_Primes_Factorisation_Helper():
	N = int(input("Enter N: "))
	print("\nFactors: " + str(Twin_Primes_Factorisation(N)))

@helper
def Extract_Modulus_eKnown_Helper():
	e = int(input("Enter e: "))
	num_pairs = int(input("Enter number of plaintext-ciphertext pairs: "))
	m = []
	c = []
	for i in range(num_pairs):
		m.append(int(input("Enter plaintext" + str(i+1) + ": ")))
		c.append(int(input("Enter ciphertext of above plaintext: ")))
	print ("\nPossible N:" + str(Extract_Modulus_eKnown(m, c, e)))

@helper
def Extract_Modulus_eUnknown_Helper():
	num_trips = int(input("Enter number of plaintext-ciphertext-ciphertext(plaintext_squared) triplets: "))
	m = []
	c = []
	sq_c = []
	for i in range(num_trips):
		m.append(int(input("Enter plaintext" + str(i+1) + ": ")))
		c.append(int(input("Enter ciphertext of above plaintext: ")))
		sq_c.append(int(input("Enter ciphertext of square of above plaintext: ")))
	print ("\nPossible N:" + str(Extract_Modulus_eUnknown(m, c, sq_c)))

@helper
def String_To_Long_Helper():
	string = input("Enter string: ")
	print("\nLong: " + str(String_To_Long(string)))

@helper
def Long_To_String_Helper():
	long = int(input("Enter long: "))
	print("\nString: " + str(Long_To_String(long)))

@helper
def Hex_To_Long_Helper():
	hex_string = input("Enter hex: ")
	print("\nLong: " + str(Hex_To_Long(hex_string)))

@helper
def Long_To_Hex_Helper():
	long = int(input("Enter long: "))
	print("\nHex: " + str(Long_To_Hex(long)))

@helper
def String_To_Hex_Helper():
	string = input("Enter string: ")
	print("\nHex: " + str(String_To_Hex(string)))

@helper
def Hex_To_String_Helper():
	hex_string = input("Enter hex: ")
	print("\nString: " + str(Hex_To_String(hex_string)))


#===============MAIN==============

BANNER = """
                     ______
                  .-"      "-.
                 /            \\
                |              |
                |,  .-.  .-.  ,|
                | )(__/  \\__)( |
                |/     /\     \\|
      (@_       (_     ^^     _)
 _     ) \\_______\\__|IIIIII|__/__________________________
(_)@8@8{}<________|-\\IIIIII/-|___________________________>
       )_/        \\          /
      (@           `--------` jgs

-------------------------------------------------------------
               RSAPoisoner v1.0 - Nilabha Saha               
"""
POISONS = ["RSA Encrypt", "RSA Decrypt (d known)", "RSA Decrypt (factors known)", "Common Modulus Attack (External)", "Common Modulus Attack (Internal)", "Small Public Exponent Attack", "Hastad's Broadcast Attack", "Wiener's Attack", "Fermat's Factorisation", "Twin Primes Factorisation", "Extract Modulus (e known)", "Extract Modulus (e unknown)", "String To Long", "Long To String", "Hex To Long", "Long To Hex", "String To Hex", "Hex To String", "Exit"]

def mainMenu():
	print(BANNER)
	print("Choose your poison:")
	for idx in range(len(POISONS)):
		print(str(idx+1) + ". " + POISONS[idx])

	choice = int(input("\nPour me some <Choose Poison Number> -> "))
	choiceDungeon(choice-1)
	
def choiceDungeon(choice):
	if POISONS[choice] == "RSA Encrypt":
		RSA_Encrypt_Helper(2)
	elif POISONS[choice] == "RSA Decrypt (d known)":
		RSA_Decrypt_dKnown_Helper()
	elif POISONS[choice] == "RSA Decrypt (factors known)":
		RSA_Decrypt_factorsKnown_Helper()
	elif POISONS[choice] == "Common Modulus Attack (External)":
		Common_Modulus_External_Helper()
	elif POISONS[choice] == "Common Modulus Attack (Internal)":
		Common_Modulus_Internal_Helper()
	elif POISONS[choice] == "Small Public Exponent Attack":
		Small_Public_Exponent_Helper()
	elif POISONS[choice] == "Hastad's Broadcast Attack":
		Hastad_Broadcast_Helper()
	elif POISONS[choice] == "Wiener's Attack":
		Wiener_Helper()
	elif POISONS[choice] == "Fermat's Factorisation":
		Fermat_Factorisation_Helper()
	elif POISONS[choice] == "Twin Primes Factorisation":
		Twin_Primes_Factorisation_Helper()
	elif POISONS[choice] == "Extract Modulus (e known)":
		Extract_Modulus_eKnown_Helper()		
	elif POISONS[choice] == "Extract Modulus (e known)":
		Extract_Modulus_eUnkown_Helper()
	elif POISONS[choice] == "String To Long":
		String_To_Long_Helper()
	elif POISONS[choice] == "Long To String":
		Long_To_String_Helper()
	elif POISONS[choice] == "Hex To Long":
		Hex_To_Long_Helper()
	elif POISONS[choice] == "Long To Hex":
		Long_To_Hex_Helper()
	elif POISONS[choice] == "String To Hex":
		String_To_Hex_Helper()
	elif POISONS[choice] == "Hex To String":
		Hex_To_String_Helper()
	elif POISONS[choice] == "Exit":
		exit()

if __name__ == "__main__":
	mainMenu()