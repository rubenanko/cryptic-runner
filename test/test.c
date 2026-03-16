#include <windows.h>
#include <peb-lookup.h>

DOT_TEXT static const char msg[] = "The peb-lookup library is working fine\n";

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    DYNAMIC_APIS * api = InitDynamicAPIs();
    HANDLE hOut = api->pGetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dummy;
    api->pWriteFile(hOut, msg, 40, &dummy, NULL);
}