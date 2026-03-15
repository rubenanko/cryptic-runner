import sys
import os
import random

def encrypt_payload(payload, key):
    """
    Chiffre le payload avec un algorithme XOR à clé tournante (Rolling XOR).
    Chaque octet du payload est XORé avec un octet de la clé, 
    et la clé est mise à jour dynamiquement.
    """
    encrypted = bytearray()
    key_len = len(key)
    current_key = bytearray(key)
    
    for i in range(len(payload)):
        # XOR avec l'octet correspondant de la clé
        val = payload[i] ^ current_key[i % key_len]
        encrypted.append(val)
        
        # Mise à jour de la clé (Rolling XOR) pour plus de complexité
        # On ajoute l'octet chiffré à la clé pour les itérations suivantes
        current_key[i % key_len] = (current_key[i % key_len] + val) & 0xFF
        
    return encrypted

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_binary>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"Erreur: Le fichier {input_file} n'existe pas.")
        sys.exit(1)
        
    with open(input_file, "rb") as f:
        payload = f.read()
        
    # Génération d'une clé aléatoire de 16 octets
    key = bytes([random.randint(0, 255) for _ in range(16)])
    
    encrypted_payload = encrypt_payload(payload, key)
    
    # Génération du fichier de sortie (payload chiffré brut)
    output_file = "payload.enc"
    with open(output_file, "wb") as f:
        f.write(encrypted_payload)
        
    # Affichage des informations pour le stub ASM
    print(f"Payload chiffré généré: {output_file} ({len(encrypted_payload)} octets)")
    print(f"Clé (hex): {key.hex()}")
    print(f"Taille du payload: {len(payload)}")
    
    # Génération d'un fichier header C/ASM pour faciliter l'intégration
    with open("payload_info.h", "w") as f:
        f.write(f"#define PAYLOAD_SIZE {len(payload)}\n")
        f.write(f"#define ENCRYPTED_SIZE {len(encrypted_payload)}\n")
        f.write("unsigned char key[] = {" + ", ".join([hex(b) for b in key]) + "};\n")

if __name__ == "__main__":
    main()
