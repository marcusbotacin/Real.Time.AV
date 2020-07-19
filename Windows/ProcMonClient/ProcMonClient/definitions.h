/* Include Block */
#include<Windows.h>
#include<stdio.h>
#include<fltuser.h>
#include <psapi.h>

/* Auxiliary Function */
void get_process_path(UINT64 pid, char *path);
DWORD WINAPI call_yara(_In_ LPVOID lpParameter);

/* I/O Port Name */
#define AV_SCAN_PORT_NAME L"\\AVScanPort"
/* MAX STRING */
#define MAX_STR 4096
/* Paths and names */
#define YARA_BINARY_NAME "yara64.exe"
#define YARA_RULES_PATH "C:\\Users\\Win\\Downloads\\rules-master\\rules-master\\packers_index.yar"
#define USUAL_VOLUME "C:\\"
#define USUAL_VOLUME_OFFSET 24

/* I/O communication struct */
typedef struct _AV_MESSAGE {
	FILTER_MESSAGE_HEADER p;	// Windows Headers
	UINT64 pid;					// Data itself
}AVmsg,*PAVmsg;

/* Check Macro */
#define SUCCESS(X) X==S_OK
#define YARA_WHITELIST(X) strstr(X,YARA_BINARY_NAME)==NULL

/* Helpers */
#define FINISHED 0
#define FOREVER 1