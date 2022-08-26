#include <ntddk.h>

#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0301, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0302, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos;

ULONG csgoId, ClientAddress;

typedef struct _KERNEL_READ_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	ULONG Response;
	ULONG Size;

} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	ULONG Value;
	ULONG Size;

} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);

NTSTATUS ReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
NTSTATUS WriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);

NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
	IN HANDLE ProcessId,
	OUT PEPROCESS* Process
);

NTSTATUS ReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

NTSTATUS WriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ControlCode == IO_READ_REQUEST)
	{
		PKERNEL_READ_REQUEST ReadInput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		PKERNEL_READ_REQUEST ReadOutput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ReadInput->ProcessId, &Process)))
			ReadVirtualMemory(Process, ReadInput->Address,
				&ReadInput->Response, ReadInput->Size);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_READ_REQUEST);
	}
	else if (ControlCode == IO_WRITE_REQUEST)
	{
		PKERNEL_WRITE_REQUEST WriteInput = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(WriteInput->ProcessId, &Process)))
			WriteVirtualMemory(Process, &WriteInput->Value,
				WriteInput->Address, WriteInput->Size);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_WRITE_REQUEST);
	}
	else
	{
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	RtlInitUnicodeString(&dev, L"\\Device\\IOCTL_Drv");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\IOCTL_Drv");

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	pDriverObject->DriverUnload = UnloadDriver;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}