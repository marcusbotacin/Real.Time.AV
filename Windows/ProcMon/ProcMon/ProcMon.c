/* ProcMon driver
 * Sends messages when new processes are created
 * Marcus Botacin - UFPR - 2020
 */

#include "definitions.h"	// local definitions

/* Globals */

/* FS filter struct */
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    NULL,								//  Context
    NULL,								//  Operation callbacks
    FsUnload,                           //  MiniFilterUnload
    NULL,								//  InstanceSetup
    NULL,								//  InstanceQueryTeardown
    NULL,								//  InstanceTeardownStart
    NULL,								//  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  NormalizeNameComponentCallback
    NULL,                               //  NormalizeContextCleanupCallback
    NULL,								//  TransactionNotificationCallback
    NULL,                               //  NormalizeNameComponentExCallback
    NULL								//  SectionNotificationCallback
};

BOOLEAN enabled = FALSE;		// Start I/O
PFLT_FILTER filter = NULL;		// Filter obj
PFLT_PORT pServerPort = NULL;	// Server I/O Port
PFLT_PORT pClientPort = NULL;	// Client I/O Port

/* Process Callback */
void ProcessCallback(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create){
	NTSTATUS status;
	UINT64 pid;
	UNREFERENCED_PARAMETER(ParentId);
	/* Only Create Process */
	if(Create){
		/* Notify User */
		DbgPrint("[PROCMON] Created Process: %x\n",ProcessId);
		/* I/O enabled*/
		if(enabled){
			/* Send PID */
			pid = (UINT64)ProcessId;
			status = FltSendMessage(filter,&pClientPort,&pid,sizeof(pid),NULL,0,0);
			/* Notify User */
			DbgPrint("[PROCMON] Send Status: %x",status);
		}
	}
}

/* I/O Connection */
NTSTATUS FsConnectNotifyCallback (
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    )
{
	/* Save client port */
	/* Assume only one connection */
	pClientPort = ClientPort;
	/* Enable I/O */
	enabled = TRUE;
	/* Notify User */
	DbgPrint("[PROCMON] Connect\n");
	/* Finished */
	return STATUS_SUCCESS;
}

/* Disconnect */
VOID FsDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie
   )
{
	/* Notify User */
	DbgPrint("[PROCMON] Disconnect\n");
	return;
}

/* Message */
NTSTATUS FsMessageNotifyCallback (
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
	/* Notify User */
	DbgPrint("[PROCMON] Message\n");
	return STATUS_SUCCESS;
}

/* Filesystem Unload */
NTSTATUS FsUnload (_Unreferenced_parameter_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	/* Notify User */
	DbgPrint("[PROCMON] Removing FS Filter");
	/* Close Port*/
	FltCloseCommunicationPort(pServerPort);
	/* Some bug here, need to investigate */
	//FltUnregisterFilter(filter);
	/* removed */
	return STATUS_SUCCESS;
}

/* Unload Routine */
VOID DriverUnload(PDRIVER_OBJECT Driverobject)
{
	UNREFERENCED_PARAMETER(Driverobject);
	/* Remove Process Callback */
	PsSetCreateProcessNotifyRoutine(ProcessCallback,TRUE);
	/* Notify Removal */
	DbgPrint("[PROCMON] Driver Unloading\n");
}

/* Driver Entry */
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
	/* Declarations */
	OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
	LONG maxConnections = 1;
    PCWSTR portName = NULL; 
    NTSTATUS status=STATUS_SUCCESS; /* OK, I guess it will suceed */
	PSECURITY_DESCRIPTOR sd = NULL;
	UNREFERENCED_PARAMETER(RegistryPath); /*No Use. You may want to take a copy of the mount point, but i don't */
	/* Notify it is running */
	DbgPrint("[PROCMON] Driver Running");
	/* Register the unload routine */
	DriverObject->DriverUnload=DriverUnload; 
	/* Add the process callback */
	status = PsSetCreateProcessNotifyRoutine(ProcessCallback,FALSE);
	/* init structures for register filesystem filter */
	RtlInitUnicodeString(&uniString, IO_PORT_NAME );
	status = FltBuildDefaultSecurityDescriptor(&sd,FLT_PORT_ALL_ACCESS);
	if(!NT_SUCCESS(status)){
		DbgPrint("[PROCMON] Descriptor Creation Failed!");
	}
	InitializeObjectAttributes( &oa, &uniString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
	/* Register the FS filter */
	FltRegisterFilter(DriverObject,&FilterRegistration,&filter);
	/* Create the I/O Port */
	status =  FltCreateCommunicationPort(filter,&pServerPort, &oa, NULL, FsConnectNotifyCallback, FsDisconnectNotifyCallback, FsMessageNotifyCallback, maxConnections );
	/* Finished Loading */
    return status;
}