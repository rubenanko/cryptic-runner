#!/bin/bash

# -----------------------------------------------------------------------------
# build.sh - Script d'automatisation du crypter
# -----------------------------------------------------------------------------
# Ce script prend un binaire brut, le chiffre via Python,
# compile le stub ASM et concatène le tout pour créer le binaire final.
# -----------------------------------------------------------------------------

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <input_binary>"
    exit 1
fi

INPUT_BIN=$1
OUTPUT_BIN="cryptic_runner.bin"

# 1. Chiffrement du payload via Python
echo "[*] Chiffrement du payload $INPUT_BIN..."
python3 encrypt.py "$INPUT_BIN" > encryption_info.txt

# Récupération des informations de chiffrement
PAYLOAD_SIZE=$(grep "Taille du payload:" encryption_info.txt | awk '{print $4}')
KEY_HEX=$(grep "Clé (hex):" encryption_info.txt | awk '{print $3}')

echo "[+] Payload chiffré : payload.enc ($PAYLOAD_SIZE octets)"
echo "[+] Clé générée : $KEY_HEX"

# 2. Préparation du stub ASM (patching de la clé et de la taille)
# On va créer une version temporaire du stub avec les bonnes valeurs
cp stub.nasm stub_temp.nasm

# Patch de la taille du payload (dq payload_size)
# On utilise sed pour remplacer la valeur par défaut
sed -i "s/payload_size: dq 0x0000000000000000/payload_size: dq $PAYLOAD_SIZE/" stub_temp.nasm

# Patch de la clé (db key)
# On convertit la clé hex en format db pour nasm
KEY_ASM=$(echo $KEY_HEX | sed 's/\(..\)/0x\1,/g' | sed 's/,$//')
sed -i "s/key:          db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0/key:          db $KEY_ASM/" stub_temp.nasm

# 3. Compilation du stub ASM
echo "[*] Compilation du stub ASM..."
nasm -f bin stub_temp.nasm -o stub.bin

# 4. Concaténation du stub et du payload chiffré
echo "[*] Génération du binaire final $OUTPUT_BIN..."
cat stub.bin payload.enc > "$OUTPUT_BIN"

# Nettoyage
rm stub_temp.nasm stub.bin payload.enc encryption_info.txt payload_info.h

echo "[+] Terminé ! Le binaire final est disponible dans $OUTPUT_BIN"
echo "[!] Note : Ce binaire contient le stub de déchiffrement suivi du payload chiffré."
