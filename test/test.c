#include <windows.h>
#include <peb-lookup.h>

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    InitDynamicAPIs();
    HANDLE hOut = g_Api.pGetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dummy;
    char buffer [40] = "The peb-lookup library is working fine\n";
    g_Api.pWriteFile(hOut, buffer, 40, &dummy, NULL);
}