/* Include block */
#include <fltKernel.h>		// kernel stuff
#include <ntstrsafe.h>		// strings
#include <dontuse.h>		// deprecateds
#include <suppress.h>		// warnings
#include<ntifs.h>			// file system filter

/* I/O Port Name */
#define IO_PORT_NAME L"\\AVScanPort"

/* Fs Unloading Routine */
NTSTATUS FsUnload (_Unreferenced_parameter_ FLT_FILTER_UNLOAD_FLAGS Flags);

/* I/O Connection */
NTSTATUS FsConnectNotifyCallback (
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    );

/* I/O Disconnection */
VOID FsDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie
   );

/* I/O Message */
NTSTATUS FsMessageNotifyCallback (
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    );