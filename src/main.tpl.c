#include <windows.h>

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    unsigned char bytecode[SET_BYTECODE_SIZE] = SET_BYTECODE_ARRAY;
    int bytecode_size = SET_BYTECODE_SIZE;
    DWORD dummy;

    VirtualProtect(bytecode, bytecode_size,
                PAGE_EXECUTE_READWRITE, &dummy);

    // cast en fonction
    void (*function)(void) = (void (*)(void))bytecode;
    
    // appel de la fonction
    function();
    return 0;
}