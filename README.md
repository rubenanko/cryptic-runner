# Cryptic Runner : Crypter Binaire Rapide et Discret

Ce projet implémente un **crypter binaire** (ou packer) conçu pour chiffrer un code binaire brut (shellcode) et l'exécuter de manière furtive en mémoire. Il utilise un algorithme de **Rolling XOR** pour le chiffrement et un stub compact en **Assembleur x64** pour le déchiffrement et l'exécution.

## Caractéristiques

- **Chiffrement Rolling XOR** : Un algorithme de flux rapide où la clé est mise à jour dynamiquement à chaque octet, rendant l'analyse statistique plus difficile qu'un XOR simple.
- **Stub ASM Compact** : Un déchiffreur écrit en assembleur x64 pur, minimisant l'empreinte binaire et les dépendances.
- **Exécution en Place** : Le payload est déchiffré directement dans sa section mémoire avant d'être exécuté.
- **Automatisation Complète** : Un script Bash gère le chiffrement, le patching du stub et la génération du binaire final.

## Structure du Projet

- `encrypt.py` : Script Python pour chiffrer le binaire d'entrée avec une clé aléatoire.
- `stub.nasm` : Code source du déchiffreur en assembleur x64.
- `build.sh` : Script d'automatisation pour générer le binaire final.
- `README.md` : Documentation du projet.

## Utilisation

Pour générer un binaire chiffré à partir d'un fichier brut (ex: `shellcode.bin`) :

```bash
./build.sh shellcode.bin
```

Le résultat sera un fichier `cryptic_runner.bin` contenant le stub de déchiffrement suivi du payload chiffré.

## Fonctionnement Technique

1.  **Chiffrement** : Le script Python génère une clé de 16 octets. Chaque octet du payload est XORé avec un octet de la clé, puis la clé est mise à jour en ajoutant l'octet chiffré à l'octet de clé correspondant.
2.  **Stub ASM** : Lors de l'exécution, le stub récupère l'adresse du payload chiffré, applique l'algorithme inverse pour retrouver le texte clair en mémoire, puis saute directement à l'adresse du payload déchiffré.
3.  **Discrétion** : L'utilisation d'une clé tournante et d'un stub minimaliste aide à contourner les signatures statiques simples des antivirus.

## Compatibilité

- Architecture x86_64.
- Conçu pour être intégré dans des injecteurs de DLL ou des chargeurs de shellcode.
