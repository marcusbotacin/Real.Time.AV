/* Client for the ProcMon driver
 * Receives messages when new processes are created
 * Marcus Botacin - UFPR - 2020
 */

#pragma comment(lib, "fltlib.lib")
#include "definitions.h"

int main()
{
	char path[MAX_STR];
	HANDLE hport;
	AVmsg msg;
	/* Starting */
	printf("[PROCMON] Starting...\n");
	/* Connect to I/O port */
	HRESULT h = FilterConnectCommunicationPort(AV_SCAN_PORT_NAME, 0, NULL, 0, NULL, &hport);
	if(!SUCCESS(h))
	{
		printf("[PROCMON] Connection Fail\n");
		exit(FINISHED);
	}
	printf("[PROCMON] Connected\n");
	while(FOREVER){
		h = FilterGetMessage(hport,&msg.p,sizeof(msg),NULL);
		if(!SUCCESS(h))
		{
			printf("[PROCMON] GetMsg Fail: %x\n",h);
			exit(FINISHED);
		}
		get_process_path(msg.pid,path);
		/* Avoid Recursive Calls */
		if(YARA_WHITELIST(path))
		{
			printf("[PROCMON] Created: %s\n",path);
			/* Avoid Blocking */
			CreateThread(NULL,0,call_yara,path,0,NULL);
		}
	}
	return FINISHED;
}