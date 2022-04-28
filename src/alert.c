#include <windows.h>
__declspec(dllexport) int WinMain(HINSTANCE a, HINSTANCE b, LPSTR lpCmdLine, int nCmdShow)
{
    MessageBoxA(NULL, "hello world", "test program", MB_OK);
}