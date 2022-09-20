import hashlib
import re

regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

def signup():
    email = input("Enter email address: ")
    pwd = input("Enter password: ")
    conf_pwd = input("Confirm password: ")
    
    #Validating the email using regex
    if(re.fullmatch(regex, email)):
        print("Valid Email")
        #Validating the password and writing them on file
        if conf_pwd == pwd:
                if (password_check(conf_pwd)):
                    print("Password is valid")
                    enc = conf_pwd.encode()
                    hash1 = hashlib.md5(enc).hexdigest()
                    with open("credentials.txt", "w") as f:
                         f.write(email + "\n")
                         f.write(hash1)
                    f.close()
                    print("You have registered successfully!")
                else:
                    print("Invalid Password !!")

        else:
            print("Password is not same as above! \n")
    else:
        print("Invalid Email")
    
def login():
    email = input("Enter email: ")
    pwd = input("Enter password: ")
    
    if(re.fullmatch(regex, email)):
        auth = pwd.encode()
        auth_hash = hashlib.md5(auth).hexdigest()
        with open("credentials.txt", "r") as f:
            stored_email, stored_pwd = f.read().split("\n")
        f.close()
        if email == stored_email and auth_hash == stored_pwd:
             print("Logged in Successfully!")
        else:
             print("Login failed! \n")
    else:
        print("Invalid Email")
        

# Function to validate the password
def password_check(passwd):
      
    SpecialSym =['$', '@', '#', '%']
    val = True
      
    if len(passwd) < 5:
        print('length should be at least 5')
        val = False
          
    if len(passwd) > 16:
        print('length should be not be greater than 16')
        val = False
          
    if not any(char.isdigit() for char in passwd):
        print('Password should have at least one numeral')
        val = False
          
    if not any(char.isupper() for char in passwd):
        print('Password should have at least one uppercase letter')
        val = False
          
    if not any(char.islower() for char in passwd):
        print('Password should have at least one lowercase letter')
        val = False
          
    if not any(char in SpecialSym for char in passwd):
        print('Password should have at least one of the symbols $@#')
        val = False
    if val:
        return val

while 1:
    print("********** Login System **********")
    print("1.Signup")
    print("2.Login")
    print("3.Exit")
    ch = int(input("Enter your choice: "))
    if ch == 1:
        signup()
    elif ch == 2:
        login()
    elif ch == 3:
        break
    else:
        print("Wrong Choice!")