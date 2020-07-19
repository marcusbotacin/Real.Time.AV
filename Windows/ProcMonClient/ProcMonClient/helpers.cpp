#include"definitions.h"

void get_process_path(UINT64 pid, char *path)
{
	char name[MAX_STR];
	HANDLE p = OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pid);
	GetProcessImageFileNameA(p,name,MAX_STR);
	/* Adjust Volume (ugly way)*/		
	strcpy(path,USUAL_VOLUME);
	strcat(path,name+USUAL_VOLUME_OFFSET);
	CloseHandle(p);
}

DWORD WINAPI call_yara(
  _In_ LPVOID lpParameter
)
{
	STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
	/* Create Command Line */
	char cmd[MAX_STR];
	sprintf(cmd,"%s -w %s %s",YARA_BINARY_NAME,YARA_RULES_PATH,(char*)lpParameter);
	
	if(!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)){
        printf("[PROMON] CreateProcess failed: %d\n", GetLastError());
        return FINISHED;
    }
    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

	// its over
	return FINISHED;
}