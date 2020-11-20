from random import randint, choice

#The Ap Uri data definition zone
def RandomNumber32():
    return randint(1, 1<<32-1)

def RandomNumber64():
    return randint(1, 1<<64-1)

def RandomString(length = 32):
    letters = "ABCDE1234567890"
    return ''.join(choice(letters) for i in range(length))