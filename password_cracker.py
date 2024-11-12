import hashlib

def password_cracker(hash_to_check, use_salts=False):
    # Read the list of top 10,000 passwords from the file
    try:
        with open('top-10000-passwords.txt', 'r') as f:
            passwords = f.read().splitlines()
    except FileNotFoundError:
        return "Error: Password list file not found"
    
    # Read the list of salts from the file (if use_salts is True)
    if use_salts:
        try:
            with open('known-salts.txt', 'r') as f:
                salts = f.read().splitlines()
        except FileNotFoundError:
            return "Error: Salts file not found"
    
    # Try hashing each password (with or without salts) and compare
    for password in passwords:
        if use_salts:
            for salt in salts:
                # Hash the password with the salt appended and prepended
                salted_password = salt + password + salt
                hashed_password = hashlib.sha1(salted_password.encode('utf-8')).hexdigest()
                if hashed_password == hash_to_check:
                    return password
        else:
            # Hash the password without salts
            hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
            if hashed_password == hash_to_check:
                return password
    
    return "PASSWORD NOT IN DATABASE"
