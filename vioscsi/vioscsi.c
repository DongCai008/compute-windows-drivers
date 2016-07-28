/**********************************************************************
 * Copyright (c) 2012-2015 Red Hat, Inc.
 *
 * File: vioscsi.c
 *
 * Author(s):
 *  Vadim Rozenfeld <vrozenfe@redhat.com>
 *
 * This file contains vioscsi StorPort miniport driver
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
**********************************************************************/
#include "ntstatus.h"
#include "helper.h"
#include "snapshot.h"
#include "utils.h"
#include "vioscsi.h"

#define VioScsiWmi_MofResourceName        L"MofResource"

#define VIOSCSI_SETUP_GUID_INDEX 0

BOOLEAN IsCrashDumpMode;

#if (NTDDI_VERSION > NTDDI_WIN7)
sp_DRIVER_INITIALIZE DriverEntry;
HW_INITIALIZE        VioScsiHwInitialize;
HW_BUILDIO           VioScsiBuildIo;
HW_STARTIO           VioScsiStartIo;
HW_FIND_ADAPTER      VioScsiFindAdapter;
HW_RESET_BUS         VioScsiResetBus;
HW_ADAPTER_CONTROL   VioScsiAdapterControl;
HW_INTERRUPT         VioScsiInterrupt;
HW_DPC_ROUTINE       VioScsiCompleteDpcRoutine;
HW_PASSIVE_INITIALIZE_ROUTINE         VioScsiIoPassiveInitializeRoutine;
#if (MSI_SUPPORTED == 1)
HW_MESSAGE_SIGNALED_INTERRUPT_ROUTINE VioScsiMSInterrupt;
#endif
#endif

BOOLEAN
VioScsiHwInitialize(
    IN PVOID DeviceExtension
    );

BOOLEAN
VioScsiBuildIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    );

BOOLEAN
VioScsiStartIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    );

ULONG
VioScsiFindAdapter(
    IN PVOID DeviceExtension,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    IN PBOOLEAN Again
    );

BOOLEAN
VioScsiResetBus(
    IN PVOID DeviceExtension,
    IN ULONG PathId
    );

SCSI_ADAPTER_CONTROL_STATUS
VioScsiAdapterControl(
    IN PVOID DeviceExtension,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters
    );

NTSTATUS
FORCEINLINE
PreProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    );

VOID
FORCEINLINE
PostProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    );

VOID
FORCEINLINE
CompleteRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    );

VOID
FORCEINLINE
DispatchQueue(
    IN PVOID DeviceExtension,
    IN ULONG MessageID
    );

BOOLEAN
VioScsiInterrupt(
    IN PVOID DeviceExtension
    );

VOID
TransportReset(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

VOID
ParamChange(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

VOID
CompleteSrbSnapshotRequested(
    IN PADAPTER_EXTENSION adaptExt,
    IN UCHAR Target,
    IN UCHAR Lun,
    BOOLEAN DeviceAck
    );

VOID
CompleteSrbSnapshotCanProceed(
    IN PADAPTER_EXTENSION adaptExt,
    IN UCHAR Target,
    IN UCHAR Lun,
    IN ULONG ReturnCode
    );

VOID
RequestSnapshot(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

VOID
ProcessSnapshotCompletion(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    );

#if (MSI_SUPPORTED == 1)
BOOLEAN
VioScsiMSInterrupt(
    IN PVOID  DeviceExtension,
    IN ULONG  MessageID
    );
#endif

BOOLEAN
SetSrbSnapshotRequested(
    IN PADAPTER_EXTENSION adaptExt,
    IN PSRB_TYPE Srb
    )
{
    PSRB_TYPE current = InterlockedCompareExchangePointer(
        &(adaptExt->srb_snapshot_requested), Srb, NULL);
    if (current == NULL)
        return TRUE;
    else
        return FALSE;
}

PSRB_TYPE
ClearSrbSnapshotRequested(
    IN PADAPTER_EXTENSION adaptExt
    )
{
    PSRB_TYPE current = (PSRB_TYPE)adaptExt->srb_snapshot_requested;
    return (PSRB_TYPE)InterlockedCompareExchangePointer(
        &(adaptExt->srb_snapshot_requested), NULL, current);
}

BOOLEAN
SetSrbSnapshotCanProceed(
    IN PADAPTER_EXTENSION adaptExt,
    IN PSRB_TYPE Srb
    )
{
    PSRB_TYPE current = InterlockedCompareExchangePointer(
        &(adaptExt->srb_snapshot_can_proceeed), Srb, NULL);
    if (current == NULL)
        return TRUE;
    else
        return FALSE;
}

PSRB_TYPE
ClearSrbSnapshotCanProceed(
    IN PADAPTER_EXTENSION adaptExt
    )
{
    PSRB_TYPE current = (PSRB_TYPE)adaptExt->srb_snapshot_can_proceeed;
    return (PSRB_TYPE)InterlockedCompareExchangePointer(
        &(adaptExt->srb_snapshot_can_proceeed), NULL, current);
}

ULONG
DriverEntry(
    IN PVOID  DriverObject,
    IN PVOID  RegistryPath
    )
{

    HW_INITIALIZATION_DATA hwInitData;
    ULONG                  initResult;
    TRACE_CONTEXT_NO_DEVICE_EXTENSION();

    InitializeDriverOptions((PDRIVER_OBJECT)DriverObject, (PUNICODE_STRING)RegistryPath);

    TRACE1(TRACE_LEVEL_WARNING, DRIVER_START, "Vioscsi driver started", "build", _NT_TARGET_MIN);
    IsCrashDumpMode = FALSE;
    if (RegistryPath == NULL) {
        TRACE(TRACE_LEVEL_WARNING, DRIVER_START, "DriverEntry: Crash dump mode");
        IsCrashDumpMode = TRUE;
    }

    memset(&hwInitData, 0, sizeof(HW_INITIALIZATION_DATA));

    hwInitData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);

    hwInitData.HwFindAdapter            = VioScsiFindAdapter;
    hwInitData.HwInitialize             = VioScsiHwInitialize;
    hwInitData.HwStartIo                = VioScsiStartIo;
    hwInitData.HwInterrupt              = VioScsiInterrupt;
    hwInitData.HwResetBus               = VioScsiResetBus;
    hwInitData.HwAdapterControl         = VioScsiAdapterControl;
    hwInitData.HwBuildIo                = VioScsiBuildIo;
    hwInitData.NeedPhysicalAddresses    = TRUE;
    hwInitData.TaggedQueuing            = TRUE;
    hwInitData.AutoRequestSense         = TRUE;
    hwInitData.MultipleRequestPerLu     = TRUE;

    hwInitData.DeviceExtensionSize      = sizeof(ADAPTER_EXTENSION);
    hwInitData.SrbExtensionSize         = sizeof(SRB_EXTENSION);

    hwInitData.AdapterInterfaceType     = PCIBus;

    hwInitData.NumberOfAccessRanges     = 1;
    hwInitData.MapBuffers               = STOR_MAP_NON_READ_WRITE_BUFFERS;

#if (NTDDI_VERSION > NTDDI_WIN7)
    /* Specify support/use SRB Extension for Windows 8 and up */
    hwInitData.SrbTypeFlags = SRB_TYPE_FLAG_STORAGE_REQUEST_BLOCK;
    hwInitData.FeatureSupport = STOR_FEATURE_FULL_PNP_DEVICE_CAPABILITIES;
#endif

    initResult = StorPortInitialize(DriverObject,
                                    RegistryPath,
                                    &hwInitData,
                                    NULL);

    TRACE1(TRACE_LEVEL_VERBOSE, DRIVER_START, "Initialize returned", "Result", initResult);

    return initResult;

}

#ifdef ENABLE_WMI
ULONG PortNumber = 0;
#endif

ULONG
VioScsiFindAdapter(
    IN PVOID DeviceExtension,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    IN PBOOLEAN Again
    )
{
    PADAPTER_EXTENSION adaptExt;
    ULONG              pageNum;
    ULONG              Size;
    ULONG              index;
    ULONG              num_cpus;
#if (MSI_SUPPORTED == 1)
    PPCI_COMMON_CONFIG pPciConf = NULL;
    UCHAR              pci_cfg_buf[256];
    ULONG              pci_cfg_len;
#endif
    TRACE_CONTEXT_NO_SRB();
    UNREFERENCED_PARAMETER( HwContext );
    UNREFERENCED_PARAMETER( BusInformation );
    UNREFERENCED_PARAMETER( ArgumentString );
    UNREFERENCED_PARAMETER( Again );

ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    memset(adaptExt, 0, sizeof(ADAPTER_EXTENSION));

    adaptExt->dump_mode  = IsCrashDumpMode;

    ConfigInfo->Master                      = TRUE;
    ConfigInfo->ScatterGather               = TRUE;
    ConfigInfo->Dma32BitAddresses           = TRUE;
#if (NTDDI_VERSION > NTDDI_WIN7)
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_FULL64BIT_SUPPORTED;
#else
    ConfigInfo->Dma64BitAddresses = TRUE;
#endif
    ConfigInfo->AlignmentMask = 0x3;
    ConfigInfo->MapBuffers                  = STOR_MAP_NON_READ_WRITE_BUFFERS;
    ConfigInfo->SynchronizationModel        = StorSynchronizeFullDuplex;
#if (MSI_SUPPORTED == 1)
    ConfigInfo->HwMSInterruptRoutine        = VioScsiMSInterrupt;
    ConfigInfo->InterruptSynchronizationMode=InterruptSynchronizePerMessage;
#endif
#ifdef ENABLE_WMI
    ConfigInfo->WmiDataProvider = TRUE;
    WmiInitializeContext(adaptExt);
#if (NTDDI_VERSION <= NTDDI_WIN7)
    adaptExt->PortNumber = (USHORT) InterlockedIncrement(&PortNumber);
#endif
#else
    ConfigInfo->WmiDataProvider = FALSE;
#endif
    if (!InitHW(DeviceExtension, ConfigInfo)) {
        TRACE(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot initialize HardWare");
        return SP_RETURN_NOT_FOUND;
    }

#if (MSI_SUPPORTED == 1)
    pci_cfg_len = StorPortGetBusData (DeviceExtension,
                                           PCIConfiguration,
                                           ConfigInfo->SystemIoBusNumber,
                                           (ULONG)ConfigInfo->SlotNumber,
                                           (PVOID)pci_cfg_buf,
                                           (ULONG)256);
    if (pci_cfg_len == 256)
    {
        UCHAR CapOffset;
        PPCI_MSIX_CAPABILITY pMsixCapOffset;
        PPCI_COMMON_HEADER   pPciComHeader;
        pPciConf = (PPCI_COMMON_CONFIG)pci_cfg_buf;
        pPciComHeader = (PPCI_COMMON_HEADER)pci_cfg_buf;
        if ( (pPciComHeader->Status & PCI_STATUS_CAPABILITIES_LIST) == 0)
        {
            TRACE(TRACE_LEVEL_INFORMATION, DRIVER_START, "NO CAPABILITIES_LIST\n");
        }
        else
        {
           if ( (pPciComHeader->HeaderType & (~PCI_MULTIFUNCTION)) == PCI_DEVICE_TYPE )
           {
              CapOffset = pPciComHeader->u.type0.CapabilitiesPtr;
              while (CapOffset != 0)
              {
                 pMsixCapOffset = (PPCI_MSIX_CAPABILITY)(pci_cfg_buf + CapOffset);
                 if ( pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_MSIX )
                 {
                     TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "TableSize", pMsixCapOffset->MessageControl.TableSize);
                     TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "FunctionMask", pMsixCapOffset->MessageControl.FunctionMask);
                     TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "MSIXEnable", pMsixCapOffset->MessageControl.MSIXEnable);

                     TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "MessageTable", *(ULONGLONG*)&pMsixCapOffset->MessageTable);
                     TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "PBATable", *(ULONGLONG*)&pMsixCapOffset->PBATable);
                     adaptExt->msix_enabled = (pMsixCapOffset->MessageControl.MSIXEnable == 1);
                 }
                 else
                 {
                     TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "CapabilityID", pMsixCapOffset->Header.CapabilityID, "Next CapOffset", CapOffset);
                 }
                 CapOffset = pMsixCapOffset->Header.Next;
              }
              TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MessageControl", "msix_enabled", adaptExt->msix_enabled);
              VirtIODeviceSetMSIXUsed(adaptExt->pvdev, adaptExt->msix_enabled);
           }
           else
           {
               TRACE(TRACE_LEVEL_FATAL, DRIVER_START, "NOT A PCI_DEVICE_TYPE");
           }
        }
    }
    else
    {
        TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "CANNOT READ PCI CONFIGURATION SPACE", "pci_cfg_len", pci_cfg_len);
    }
#endif

    GetScsiConfig(DeviceExtension);

    ConfigInfo->NumberOfBuses               = 1;
    ConfigInfo->MaximumNumberOfTargets      = min((UCHAR)adaptExt->scsi_config.max_target, 255/*SCSI_MAXIMUM_TARGETS_PER_BUS*/);
    ConfigInfo->MaximumNumberOfLogicalUnits = min((UCHAR)adaptExt->scsi_config.max_lun, SCSI_MAXIMUM_LUNS_PER_TARGET);
    if(adaptExt->dump_mode) {
        ConfigInfo->NumberOfPhysicalBreaks  = 8;
    } else {
        ConfigInfo->NumberOfPhysicalBreaks  = min((MAX_PHYS_SEGMENTS + 1), adaptExt->scsi_config.seg_max);
    }
    ConfigInfo->MaximumTransferLength       = 0x00FFFFFF;

    VirtIODeviceReset(adaptExt->pvdev);

#if (NTDDI_VERSION >= NTDDI_WIN7)
    num_cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
#else
    num_cpus = KeQueryActiveProcessorCount(NULL);
#endif
    adaptExt->num_queues = adaptExt->scsi_config.num_queues;
    if (adaptExt->dump_mode || !adaptExt->msix_enabled)
    {
        adaptExt->num_queues = 1;
    }
    if (adaptExt->num_queues > 1) {
        for (index = 0; index < num_cpus; index++) {
            adaptExt->cpu_to_vq_map[index] =
                (UCHAR)(index % adaptExt->num_queues);
        }
    } else {
        memset(adaptExt->cpu_to_vq_map, 0, MAX_CPU);
    }

    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "Multiqueue", "Queue", adaptExt->num_queues, "CPUs", num_cpus);

    if (adaptExt->dump_mode) {
        // In dump mode, StorPortGetUncachedExtension fails if queues have more than 256 descriptors
        #define MAX_DUMP_MODE_QUEUE_NUM 256
        for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
            StorPortWritePortUshort(DeviceExtension, (PUSHORT)(adaptExt->device_base + VIRTIO_PCI_QUEUE_SEL), (USHORT)index);
            StorPortWritePortUlong(DeviceExtension, (PULONG)(adaptExt->device_base + VIRTIO_PCI_QUEUE_PFN), (ULONG)0);
            adaptExt->original_queue_num[index] = StorPortReadPortUshort(adaptExt, (PUSHORT)(adaptExt->vdev.addr + VIRTIO_PCI_QUEUE_NUM));
            if (adaptExt->original_queue_num[index] > MAX_DUMP_MODE_QUEUE_NUM) {
                TRACE(TRACE_LEVEL_WARNING, DRIVER_START, "Virtual queue num descriptors reduced in dump mode.");
                StorPortWritePortUshort(DeviceExtension, (PUSHORT)(adaptExt->device_base + VIRTIO_PCI_QUEUE_NUM), MAX_DUMP_MODE_QUEUE_NUM);
            } else {
                adaptExt->original_queue_num[index] = 0;
            }
        }
    }

    adaptExt->features = StorPortReadPortUlong(DeviceExtension, (PULONG)(adaptExt->device_base + VIRTIO_PCI_HOST_FEATURES));

    adaptExt->allocationSize = PAGE_SIZE;
    adaptExt->offset = 0;
    Size = 0;
    for (index = VIRTIO_SCSI_CONTROL_QUEUE; index <= VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
        VirtIODeviceQueryQueueAllocation(adaptExt->pvdev, index, &pageNum, &Size);
        if (Size == 0) {
            LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);
            TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Virtual queue config failed", "queue", index);
            return SP_RETURN_ERROR;
        }
        adaptExt->allocationSize += ROUND_TO_PAGES(Size);
    }
    adaptExt->allocationSize += (ROUND_TO_PAGES(Size) * (adaptExt->num_queues - 1));
    if (adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0 > MAX_QUEUES_PER_DEVICE_DEFAULT)
    {
        adaptExt->allocationSize += ROUND_TO_PAGES(VirtIODeviceSizeRequired((USHORT)(adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0)));
    }
    adaptExt->allocationSize += ROUND_TO_PAGES(sizeof(SRB_EXTENSION));
    adaptExt->allocationSize += ROUND_TO_PAGES(sizeof(VirtIOSCSIEventNode) * 8);
    // NOTE: Do not allocate anything else in the uncached extension.
    // Its size is limited to 64KB in dump mode and any new members will cause its allocation to fail.

#if (INDIRECT_SUPPORTED == 1)
    if(!adaptExt->dump_mode) {
        adaptExt->indirect = CHECKBIT(adaptExt->features, VIRTIO_RING_F_INDIRECT_DESC);
    }
#else
    adaptExt->indirect = 0;
#endif

    if(adaptExt->indirect) {
        adaptExt->queue_depth = max(20, (pageNum / 4));
    } else {
        // Each message uses one virtqueue descriptor for the scsi command, one descriptor
        // for scsi response and up to ConfigInfo->NumberOfPhysicalBreaks for the data.
        adaptExt->queue_depth = pageNum / (ConfigInfo->NumberOfPhysicalBreaks + 2) - 1;
    }
#if (NTDDI_VERSION > NTDDI_WIN7)
    ConfigInfo->MaxIOsPerLun = adaptExt->queue_depth * adaptExt->num_queues;
    ConfigInfo->InitialLunQueueDepth = ConfigInfo->MaxIOsPerLun;
    if (ConfigInfo->MaxIOsPerLun * ConfigInfo->MaximumNumberOfTargets > ConfigInfo->MaxNumberOfIO) {
        ConfigInfo->MaxNumberOfIO = ConfigInfo->MaxIOsPerLun * ConfigInfo->MaximumNumberOfTargets;
    }
#else
    // Prior to win8, lun queue depth must be at most 254.
    adaptExt->queue_depth = min(254, adaptExt->queue_depth);
#endif

    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "ConfigInfo", "NumberOfPhysicalBreaks", ConfigInfo->NumberOfPhysicalBreaks, "QueueDepth", adaptExt->queue_depth);

    adaptExt->uncachedExtensionVa = StorPortGetUncachedExtension(DeviceExtension, ConfigInfo, adaptExt->allocationSize);
    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "StorPortGetUncachedExtension", "uncachedExtensionVa", adaptExt->uncachedExtensionVa, "allocation size", adaptExt->allocationSize);
    if (!adaptExt->uncachedExtensionVa) {
        LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);

        TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Can't get uncached extension", "allocation size", adaptExt->allocationSize);
        return SP_RETURN_ERROR;
    }
    adaptExt->uncachedExtensionVa = (PVOID)(((ULONG_PTR)(adaptExt->uncachedExtensionVa) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "StorPortGetUncachedExtension", "uncachedExtensionVa", adaptExt->uncachedExtensionVa, "allocation size", adaptExt->allocationSize);
    if (!adaptExt->dump_mode && (adaptExt->num_queues > 1) && (adaptExt->pmsg_affinity == NULL)) {
        ULONG Status =
            StorPortAllocatePool(DeviceExtension,
            sizeof(GROUP_AFFINITY) * (adaptExt->num_queues + 3),
            VIOSCSI_POOL_TAG,
            (PVOID*)&adaptExt->pmsg_affinity);
        TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "StorPortAllocatePool", "pmsg_affinity", adaptExt->pmsg_affinity, "Status", Status);
    }
EXIT_FN();
    return SP_RETURN_FOUND;
}

BOOLEAN
VioScsiPassiveInitializeRoutine(
    IN PVOID DeviceExtension
    )
{
    ULONG index;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
ENTER_FN();
    for (index = 0; index < adaptExt->num_queues; ++index) {
        StorPortInitializeDpc(DeviceExtension,
            &adaptExt->dpc[index],
            VioScsiCompleteDpcRoutine);
    }
    adaptExt->dpc_ok = TRUE;
    ReportDriverVersion(DeviceExtension);
EXIT_FN();
    return TRUE;
}


static struct virtqueue *FindVirtualQueue(PADAPTER_EXTENSION adaptExt, ULONG index, ULONG vector)
{
    struct virtqueue *vq = NULL;
    TRACE_CONTEXT_SET_DEVICE_EXTENSION(adaptExt);
    if (adaptExt->uncachedExtensionVa)
    {
        ULONG len = 0;
        PVOID  ptr = (PVOID)((ULONG_PTR)adaptExt->uncachedExtensionVa + adaptExt->offset);
        PHYSICAL_ADDRESS pa = StorPortGetPhysicalAddress(adaptExt, NULL, ptr, &len);
        BOOLEAN useEventIndex = CHECKBIT(adaptExt->features, VIRTIO_RING_F_EVENT_IDX);
        if (pa.QuadPart)
        {
           ULONG Size = 0;
           ULONG dummy = 0;
           VirtIODeviceQueryQueueAllocation(adaptExt->pvdev, index, &dummy, &Size);
           ASSERT((adaptExt->offset + Size) < adaptExt->allocationSize);
           vq = VirtIODevicePrepareQueue(adaptExt->pvdev, index, pa, ptr, Size, NULL, useEventIndex);
           if (vq == NULL)
           {
               TRACE7(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot create virtual queue",
                   "index", index, "vector", vector, "ptr", ptr, "pa", pa.QuadPart,
                   "Size", Size, "uncachedExtensionVa", adaptExt->uncachedExtensionVa, "offset", adaptExt->offset);
               return NULL;
           }
           adaptExt->offset += ROUND_TO_PAGES(Size);
           TRACE3(TRACE_LEVEL_INFORMATION, DRIVER_START, "Virtual queue created",
               "index", index, "Size", Size, "offset", adaptExt->offset);
        }

        if (vq == NULL)
        {
            TRACE3(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot create virtual queue",
                "index", index, "vector", vector, "pa", pa.QuadPart);
           return NULL;
        }
        if (vector)
        {
           unsigned res = VIRTIO_MSI_NO_VECTOR;
           StorPortWritePortUshort(adaptExt, (PUSHORT)(adaptExt->pvdev->addr + VIRTIO_MSI_QUEUE_VECTOR),(USHORT)vector);
           res = StorPortReadPortUshort(adaptExt, (PUSHORT)(adaptExt->pvdev->addr + VIRTIO_MSI_QUEUE_VECTOR));
           TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "Virtual queue msix", "vector", vector, "res", res);
           if(res == VIRTIO_MSI_NO_VECTOR)
           {
              VirtIODeviceDeleteQueue(vq, NULL);
              vq = NULL;
              TRACE(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot create vq vector");
              return NULL;
           }
           StorPortWritePortUshort(adaptExt, (PUSHORT)(adaptExt->pvdev->addr + VIRTIO_MSI_CONFIG_VECTOR),(USHORT)vector);
           res = StorPortReadPortUshort(adaptExt, (PUSHORT)(adaptExt->pvdev->addr + VIRTIO_MSI_CONFIG_VECTOR));
           if (res != vector)
           {
              VirtIODeviceDeleteQueue(vq, NULL);
              vq = NULL;
              TRACE(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot set config vector");
              return NULL;
           }
        }
    }
    return vq;
}

BOOLEAN
VioScsiHwInitialize(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    ULONG              i;
    ULONG              guestFeatures = 0;
    ULONG              index;

#if (MSI_SUPPORTED == 1)
    PERF_CONFIGURATION_DATA perfData = { 0 };
    ULONG              status = STOR_STATUS_SUCCESS;
    MESSAGE_INTERRUPT_INFORMATION msi_info = { 0 };
#endif
    TRACE_CONTEXT_NO_SRB();

ENTER_FN();
    if (CHECKBIT(adaptExt->features, VIRTIO_RING_F_EVENT_IDX)) {
        guestFeatures |= (1ul << VIRTIO_RING_F_EVENT_IDX);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_CHANGE)) {
        guestFeatures |= (1ul << VIRTIO_SCSI_F_CHANGE);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_HOTPLUG)) {
        guestFeatures |= (1ul << VIRTIO_SCSI_F_HOTPLUG);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_GOOGLE_REPORT_DRIVER_VERSION)) {
        guestFeatures |= (1ul << VIRTIO_SCSI_F_GOOGLE_REPORT_DRIVER_VERSION);
    }
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_GOOGLE_SNAPSHOT)) {
        guestFeatures |= (1ul << VIRTIO_SCSI_F_GOOGLE_SNAPSHOT);
    }

    StorPortWritePortUlong(DeviceExtension,
             (PULONG)(adaptExt->device_base + VIRTIO_PCI_GUEST_FEATURES), guestFeatures);

    adaptExt->msix_vectors = 0;
    adaptExt->offset = 0;

#if (MSI_SUPPORTED == 1)
    while(StorPortGetMSIInfo(DeviceExtension, adaptExt->msix_vectors, &msi_info) == STOR_STATUS_SUCCESS) {
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "MessageId", msi_info.MessageId);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "MessageData", msi_info.MessageData);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "InterruptVector", msi_info.InterruptVector);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "InterruptLevel", msi_info.InterruptLevel);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "InterruptMode", msi_info.InterruptMode);
        TRACE1(TRACE_LEVEL_INFORMATION, DRIVER_START, "MSIInfo", "MessageAddress", msi_info.MessageAddress.QuadPart);
        ++adaptExt->msix_vectors;
    }

    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "StartInfo", "Queues", adaptExt->num_queues, "msix_vectors", adaptExt->msix_vectors);
    if (adaptExt->num_queues > 1 &&
        ((adaptExt->num_queues + 3) > adaptExt->msix_vectors)) {
        //FIXME
        adaptExt->num_queues = 1;
    }

    if (!adaptExt->dump_mode &&
        (adaptExt->msix_vectors >= adaptExt->num_queues + 3)) {
//HACK
        if (adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0 > MAX_QUEUES_PER_DEVICE_DEFAULT)
        {
            ULONG_PTR ptr = ((ULONG_PTR)adaptExt->uncachedExtensionVa + adaptExt->offset);
            ULONG size = ROUND_TO_PAGES(VirtIODeviceSizeRequired((USHORT)(adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0)));
            adaptExt->offset += size;
            memcpy((PVOID)ptr, (PVOID)adaptExt->pvdev, sizeof(VirtIODevice));
            adaptExt->pvdev = (VirtIODevice*)ptr;
            VirtIODeviceInitialize(adaptExt->pvdev,  adaptExt->device_base, size);
        }

        for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
            adaptExt->vq[index] = FindVirtualQueue(adaptExt, index, index + 1);
        }
    }
#else
    adaptExt->num_queues = 1;
#endif
    for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
        if (!adaptExt->vq[index]) {
            adaptExt->vq[index] = FindVirtualQueue(adaptExt, index, 0);
        }
        if (!adaptExt->vq[index]) {
            TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot find virtual queue", "index", index);
            return FALSE;
        }
    }

    adaptExt->tmf_cmd.SrbExtension = (PSRB_EXTENSION)((ULONG_PTR)adaptExt->uncachedExtensionVa + adaptExt->offset);
    adaptExt->offset += ROUND_TO_PAGES(sizeof(SRB_EXTENSION));
    adaptExt->events = (PVirtIOSCSIEventNode)((ULONG_PTR)adaptExt->uncachedExtensionVa + adaptExt->offset);
    adaptExt->offset += ROUND_TO_PAGES(sizeof(VirtIOSCSIEventNode)* 8);

    if (!adaptExt->dump_mode && CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_HOTPLUG)) {
        PVirtIOSCSIEventNode events = adaptExt->events;
        for (i = 0; i < 8; i++) {
           if (!KickEvent(DeviceExtension, (PVOID)(&events[i]))) {
               TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Can't add event", "index", i);
           }
        }
    }
    if (!adaptExt->dump_mode)
    {
#if (MSI_SUPPORTED == 1)
        if ((adaptExt->num_queues > 1) && (adaptExt->perfFlags == 0)) {
            perfData.Version = STOR_PERF_VERSION;
            perfData.Size = sizeof(PERF_CONFIGURATION_DATA);

            status = StorPortInitializePerfOpts(DeviceExtension, TRUE, &perfData);

            TRACE5(TRACE_LEVEL_INFORMATION, DRIVER_START, "PerfOpts", "Pref Version", perfData.Version, "Flags", perfData.Flags,
                "ConcurrentChannels", perfData.ConcurrentChannels, "FirstRedirectionMessageNumber", perfData.FirstRedirectionMessageNumber,
                "LastRedirectionMessageNumber", perfData.LastRedirectionMessageNumber);
            if (status == STOR_STATUS_SUCCESS) {
                perfData.Flags &= (~disabledPerfOptions);
                if (CHECKFLAG(perfData.Flags, STOR_PERF_DPC_REDIRECTION)) {
                    adaptExt->perfFlags |= STOR_PERF_DPC_REDIRECTION;
                }
                if (CHECKFLAG(perfData.Flags, STOR_PERF_CONCURRENT_CHANNELS)) {
                    adaptExt->perfFlags |= STOR_PERF_CONCURRENT_CHANNELS;
                    perfData.ConcurrentChannels = adaptExt->num_queues;
                }
                if (CHECKFLAG(perfData.Flags, STOR_PERF_INTERRUPT_MESSAGE_RANGES)) {
                    adaptExt->perfFlags |= STOR_PERF_INTERRUPT_MESSAGE_RANGES;
                    perfData.FirstRedirectionMessageNumber = 3;
                    perfData.LastRedirectionMessageNumber = perfData.FirstRedirectionMessageNumber + adaptExt->num_queues - 1;
                    if ((adaptExt->pmsg_affinity != NULL) && CHECKFLAG(perfData.Flags, STOR_PERF_ADV_CONFIG_LOCALITY)) {
                        RtlZeroMemory((PCHAR)adaptExt->pmsg_affinity, sizeof(GROUP_AFFINITY)* (adaptExt->num_queues + 3));
                        adaptExt->perfFlags |= STOR_PERF_ADV_CONFIG_LOCALITY;
                        perfData.MessageTargets = adaptExt->pmsg_affinity;
                    }
                }
                if (CHECKFLAG(perfData.Flags, STOR_PERF_DPC_REDIRECTION_CURRENT_CPU)) {
                    adaptExt->perfFlags |= STOR_PERF_DPC_REDIRECTION_CURRENT_CPU;
                }
                if (CHECKFLAG(perfData.Flags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO)) {
                    adaptExt->perfFlags |= STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO;
                }
                perfData.Flags = adaptExt->perfFlags;
                TRACE5(TRACE_LEVEL_INFORMATION, DRIVER_START, "PerfOpts", "Pref Version", perfData.Version, "Flags", perfData.Flags,
                    "ConcurrentChannels", perfData.ConcurrentChannels, "FirstRedirectionMessageNumber", perfData.FirstRedirectionMessageNumber,
                    "LastRedirectionMessageNumber", perfData.LastRedirectionMessageNumber);
                status = StorPortInitializePerfOpts(DeviceExtension, FALSE, &perfData);
                if (status != STOR_STATUS_SUCCESS) {
                    adaptExt->perfFlags = 0;
                    TRACE1(TRACE_LEVEL_WARNING, DRIVER_START, "StorPortInitializePerfOpts FALSE", "status", status);
                }
                else {
                    UCHAR msg = 0;
                    PGROUP_AFFINITY ga;
                    UCHAR cpu = 0;
                    if (CHECKFLAG(perfData.Flags, STOR_PERF_ADV_CONFIG_LOCALITY)) {
                        for (msg = 3; msg < adaptExt->num_queues + 3; msg++) {
                            ga = &adaptExt->pmsg_affinity[msg];
                            if (ga->Mask > 0) {
                                cpu = RtlFindLeastSignificantBit((ULONGLONG)ga->Mask);
                                adaptExt->cpu_to_vq_map[cpu] = msg - 3;
                                TRACE5(TRACE_LEVEL_INFORMATION, DRIVER_START, "Affinity",
                                    "msg", msg, "mask", ga->Mask, "group", ga->Group, "cpu", cpu, "vq", adaptExt->cpu_to_vq_map[cpu]);
                            }
                        }
                    }
                    TRACE5(TRACE_LEVEL_INFORMATION, DRIVER_START, "Actual PerfOpts", "Pref Version", perfData.Version, "Flags", perfData.Flags,
                        "ConcurrentChannels", perfData.ConcurrentChannels, "FirstRedirectionMessageNumber", perfData.FirstRedirectionMessageNumber,
                        "LastRedirectionMessageNumber", perfData.LastRedirectionMessageNumber);
                }
            }
            else {
                TRACE1(TRACE_LEVEL_WARNING, DRIVER_START, "StorPortInitializePerfOpts TRUE", "status", status);
            }
        }
#endif
        if (!adaptExt->dpc_ok && !StorPortEnablePassiveInitialization(DeviceExtension, VioScsiPassiveInitializeRoutine)) {
            return FALSE;
        }
    }

    StorPortWritePortUchar(DeviceExtension,
           (PUCHAR)(adaptExt->device_base + VIRTIO_PCI_STATUS),
           (UCHAR)VIRTIO_CONFIG_S_DRIVER_OK);
EXIT_FN();
    return TRUE;
}

BOOLEAN
VioScsiStartIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    )
{
ENTER_FN();
    NTSTATUS status = PreProcessRequest(DeviceExtension, (PSRB_TYPE)Srb);
    switch (status)
    {
    case STATUS_SUCCESS:
        CompleteRequest(DeviceExtension, (PSRB_TYPE)Srb);
        break;
    case STATUS_MORE_PROCESSING_REQUIRED:
        return SendSRB(DeviceExtension, (PSRB_TYPE)Srb);
    case STATUS_PENDING:
    default:
        break;
    }
EXIT_FN();
    return TRUE;
}

FORCEINLINE
void HandleResponse(PVOID DeviceExtension, PVirtIOSCSICmd cmd, int queue) {
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_TYPE Srb = (PSRB_TYPE)(cmd->sc);
    PSRB_EXTENSION srbExt = SRB_EXTENSION(Srb);
    VirtIOSCSICmdResp *resp = &cmd->resp.cmd;
    UCHAR senseInfoBufferLength = 0;
    PVOID senseInfoBuffer = NULL;
    UCHAR srbStatus = SRB_STATUS_SUCCESS;
    ULONG srbDataTransferLen = SRB_DATA_TRANSFER_LENGTH(Srb);

    switch (resp->response) {
    case VIRTIO_SCSI_S_OK:
        SRB_SET_SCSI_STATUS(Srb, resp->status);
        srbStatus = (resp->status == SCSISTAT_GOOD) ? SRB_STATUS_SUCCESS : SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_UNDERRUN:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_UNDERRUN");
        srbStatus = SRB_STATUS_DATA_OVERRUN;
        break;
    case VIRTIO_SCSI_S_ABORTED:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_ABORTED");
        srbStatus = SRB_STATUS_ABORTED;
        break;
    case VIRTIO_SCSI_S_BAD_TARGET:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_BAD_TARGET");
        srbStatus = SRB_STATUS_INVALID_TARGET_ID;
        break;
    case VIRTIO_SCSI_S_RESET:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_RESET");
        srbStatus = SRB_STATUS_BUS_RESET;
        break;
    case VIRTIO_SCSI_S_BUSY:
        adaptExt->QueueStats[queue].BusyRequests++;
        adaptExt->TargetStats[SRB_TARGET_ID(Srb)].BusyRequests++;
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_BUSY");
        srbStatus = SRB_STATUS_BUSY;
        break;
    case VIRTIO_SCSI_S_TRANSPORT_FAILURE:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_TRANSPORT_FAILURE");
        srbStatus = SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_TARGET_FAILURE:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_TARGET_FAILURE");
        srbStatus = SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_NEXUS_FAILURE:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_NEXUS_FAILURE");
        srbStatus = SRB_STATUS_ERROR;
        break;
    case VIRTIO_SCSI_S_FAILURE:
        TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "VIRTIO_SCSI_S_FAILURE");
        srbStatus = SRB_STATUS_ERROR;
        break;
    default:
        srbStatus = SRB_STATUS_ERROR;
        TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unknown response", "response", resp->response);
        break;
    }
    if (srbStatus == SRB_STATUS_SUCCESS &&
        resp->resid &&
        srbDataTransferLen > resp->resid)
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, srbDataTransferLen - resp->resid);
        srbStatus = SRB_STATUS_DATA_OVERRUN;
    }
    else if (srbStatus != SRB_STATUS_SUCCESS)
    {
        SRB_GET_SENSE_INFO(Srb, senseInfoBuffer, senseInfoBufferLength);
        if (senseInfoBufferLength >= FIELD_OFFSET(SENSE_DATA, CommandSpecificInformation)) {
            memcpy(senseInfoBuffer, resp->sense,
                min(resp->sense_len, senseInfoBufferLength));
            if (srbStatus == SRB_STATUS_ERROR) {
                srbStatus |= SRB_STATUS_AUTOSENSE_VALID;
            }
        }
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
    }
    else if (srbExt && srbExt->Xfer && srbDataTransferLen > srbExt->Xfer)
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, srbExt->Xfer);
        srbStatus = SRB_STATUS_DATA_OVERRUN;
    }
    SRB_SET_SRB_STATUS(Srb, srbStatus);
    CompleteRequest(DeviceExtension, Srb);
}

// Check and respond if control call returned with an error.
void HandleGoogleControlMsg(PVOID DeviceExtension, PVirtIOSCSICmd cmd) {
    if (cmd->req.google.type != VIRTIO_SCSI_T_GOOGLE) {
        return;
    }
    VirtIOSCSICtrlGoogleResp *resp = &cmd->resp.google;
    switch(cmd->req.google.subtype) {
        case VIRTIO_SCSI_T_GOOGLE_REPORT_SNAPSHOT_READY:
            // If the guest is reporting a failure status or a snapshot
            // completion status or the host has returned the control msg with
            // an error status, there will be no resume operation from host.
            // Complete the SRB here so that the guest ioctl can return.
            if (cmd->req.google.data != VIRTIO_SCSI_SNAPSHOT_PREPARE_COMPLETE) {
                CompleteSrbSnapshotCanProceed(DeviceExtension, 0, 0,
                                              SNAPSHOT_STATUS_SUCCEED);
            } else if (resp->response != VIRTIO_SCSI_S_FUNCTION_SUCCEEDED &&
                       resp->response != VIRTIO_SCSI_S_OK) {
                CompleteSrbSnapshotCanProceed(DeviceExtension, 0, 0,
                                              SNAPSHOT_STATUS_INVALID_REQUEST);
            }
            break;
        default:
            break;
    }
}

BOOLEAN
VioScsiInterrupt(
    IN PVOID DeviceExtension
    )
{
    PVirtIOSCSICmd      cmd;
    PVirtIOSCSIEventNode evtNode;
    unsigned int        len;
    PADAPTER_EXTENSION  adaptExt;
    BOOLEAN             isInterruptServiced = FALSE;
    PSRB_TYPE           Srb = NULL;
    PSRB_EXTENSION      srbExt;
    ULONG               intReason = 0;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    ENTER_FN1("Irql", KeGetCurrentIrql());
    intReason = VirtIODeviceISR(adaptExt->pvdev);

    if ( intReason == 1) {
        isInterruptServiced = TRUE;
        while((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_REQUEST_QUEUE_0], &len)) != NULL) {
           HandleResponse(DeviceExtension, cmd, 0);
        }

        while((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE], &len)) != NULL) {
            if (cmd->req.tmf.type == VIRTIO_SCSI_T_TMF) {
                Srb = (PSRB_TYPE)cmd->sc;
                ASSERT(Srb == (PSRB_TYPE)&adaptExt->tmf_cmd.Srb);
                StorPortResume(DeviceExtension);
            } else if (cmd->req.tmf.type == VIRTIO_SCSI_T_GOOGLE) {
                HandleGoogleControlMsg(DeviceExtension, cmd);
            }
            VirtIOSCSICtrlTMFResp *resp;
            resp = &cmd->resp.tmf;
            switch(resp->response) {
            case VIRTIO_SCSI_S_OK:
            case VIRTIO_SCSI_S_FUNCTION_SUCCEEDED:
                break;
            default:
                TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unknown response", "response", resp->response);
                ASSERT(0);
                break;
            }
        }
        adaptExt->tmf_infly = FALSE;

        while((evtNode = (PVirtIOSCSIEventNode)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE], &len)) != NULL) {
           PVirtIOSCSIEvent evt = &evtNode->event;
           switch (evt->event) {
           case VIRTIO_SCSI_T_NO_EVENT:
               break;
           case VIRTIO_SCSI_T_TRANSPORT_RESET:
               TransportReset(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_PARAM_CHANGE:
               ParamChange(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_SNAPSHOT_START:
               RequestSnapshot(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_SNAPSHOT_COMPLETE:
               ProcessSnapshotCompletion(DeviceExtension, evt);
               break;
           default:
               TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unsupport virtio scsi", "event", evt->event);
               break;
           }
           SynchronizedKickEventRoutine(DeviceExtension, evtNode);
        }
    }
    TRACE1(TRACE_LEVEL_VERBOSE, DRIVER_IO, "ISR", "isInterruptServiced", isInterruptServiced);
    return isInterruptServiced;
}

#if (MSI_SUPPORTED == 1)
BOOLEAN
VioScsiMSInterrupt (
    IN PVOID  DeviceExtension,
    IN ULONG  MessageID
    )
{
    PVirtIOSCSICmd      cmd;
    PVirtIOSCSIEventNode evtNode;
    unsigned int        len;
    PADAPTER_EXTENSION  adaptExt;
    BOOLEAN             isInterruptServiced = FALSE;
    PSRB_TYPE           Srb = NULL;
    PSRB_EXTENSION      srbExt;
    ULONG               intReason = 0;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    ENTER_FN1("MessageID", MessageID);

    if (MessageID == 0)
    {
       return TRUE;
    }
    if (MessageID == 1)
    {
        while((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE], &len)) != NULL)
        {
            if (cmd->req.tmf.type == VIRTIO_SCSI_T_TMF) {
                Srb = (PSRB_TYPE)cmd->sc;
                ASSERT(Srb == (PSRB_TYPE)&adaptExt->tmf_cmd.Srb);
                StorPortResume(DeviceExtension);
            } else if (cmd->req.tmf.type == VIRTIO_SCSI_T_GOOGLE) {
                HandleGoogleControlMsg(DeviceExtension, cmd);
            }
            VirtIOSCSICtrlTMFResp *resp;
            resp = &cmd->resp.tmf;
            switch(resp->response) {
            case VIRTIO_SCSI_S_OK:
            case VIRTIO_SCSI_S_FUNCTION_SUCCEEDED:
                break;
            default:
                TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unknown response", "response", resp->response);
                ASSERT(0);
                break;
            }
        }
        adaptExt->tmf_infly = FALSE;
        return TRUE;
    }
    if (MessageID == 2) {
        while((evtNode = (PVirtIOSCSIEventNode)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE], &len)) != NULL) {
           PVirtIOSCSIEvent evt = &evtNode->event;
           switch (evt->event) {
           case VIRTIO_SCSI_T_NO_EVENT:
               break;
           case VIRTIO_SCSI_T_TRANSPORT_RESET:
               TransportReset(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_PARAM_CHANGE:
               ParamChange(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_SNAPSHOT_START:
               RequestSnapshot(DeviceExtension, evt);
               break;
           case VIRTIO_SCSI_T_SNAPSHOT_COMPLETE:
               ProcessSnapshotCompletion(DeviceExtension, evt);
               break;
           default:
               TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Unsupport virtio scsi", "event", evt->event);
               break;
           }
           SynchronizedKickEventRoutine(DeviceExtension, evtNode);
        }
        return TRUE;
    }
    if (MessageID > 2)
    {
#ifdef ENABLE_WMI
        adaptExt->QueueStats[MessageID - 3].TotalInterrupts++;
#endif
        DispatchQueue(DeviceExtension, MessageID);
        return TRUE;
    }
    return FALSE;
}
#endif

BOOLEAN
VioScsiResetBus(
    IN PVOID DeviceExtension,
    IN ULONG PathId
    )
{
    TRACE_CONTEXT_NO_SRB();
    UNREFERENCED_PARAMETER(PathId);

    TRACE(TRACE_LEVEL_WARNING, DRIVER_IO, "Bus reset!");
    return DeviceReset(DeviceExtension);
}

SCSI_ADAPTER_CONTROL_STATUS
VioScsiAdapterControl(
    IN PVOID DeviceExtension,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters
    )
{
    PSCSI_SUPPORTED_CONTROL_TYPE_LIST ControlTypeList;
    ULONG                             AdjustedMaxControlType;
    ULONG                             Index;
    PADAPTER_EXTENSION                adaptExt;
    SCSI_ADAPTER_CONTROL_STATUS       status = ScsiAdapterControlUnsuccessful;
    BOOLEAN SupportedConrolTypes[5] = {TRUE, TRUE, TRUE, FALSE, FALSE};
    TRACE_CONTEXT_NO_SRB();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

ENTER_FN1("ControlType", ControlType);

    switch (ControlType) {

    case ScsiQuerySupportedControlTypes: {
        ControlTypeList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST)Parameters;
        AdjustedMaxControlType =
            (ControlTypeList->MaxControlType < 5) ?
            ControlTypeList->MaxControlType :
            5;
        for (Index = 0; Index < AdjustedMaxControlType; Index++) {
            ControlTypeList->SupportedTypeList[Index] =
                SupportedConrolTypes[Index];
        }
        status = ScsiAdapterControlSuccess;
        break;
    }
    case ScsiStopAdapter: {
        ShutDown(DeviceExtension);
        status = ScsiAdapterControlSuccess;
        break;
    }
    case ScsiRestartAdapter: {
        ULONG index;
        VirtIODeviceReset(adaptExt->pvdev);
        for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
            StorPortWritePortUshort(DeviceExtension, (PUSHORT)(adaptExt->device_base + VIRTIO_PCI_QUEUE_SEL), (USHORT)index);
            StorPortWritePortUlong(DeviceExtension, (PULONG)(adaptExt->device_base + VIRTIO_PCI_QUEUE_PFN), (ULONG)0);
            adaptExt->vq[index] = NULL;
        }

        if (!VioScsiHwInitialize(DeviceExtension))
        {
            TRACE(TRACE_LEVEL_FATAL, DRIVER_START, "Cannot Initialize HW");
            break;
        }
        status = ScsiAdapterControlSuccess;
        break;
    }
    default:
        break;
    }

EXIT_FN();
    return status;
}

BOOLEAN
VioScsiBuildIo(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    )
{
    PCDB                  cdb;
    ULONG                 i;
    ULONG                 fragLen;
    ULONG                 sgElement;
    ULONG                 sgMaxElements;
    PADAPTER_EXTENSION    adaptExt;
    PSRB_EXTENSION        srbExt;
    PSTOR_SCATTER_GATHER_LIST sgList;
    VirtIOSCSICmd         *cmd;
    UCHAR                 TargetId;
    UCHAR                 Lun;

ENTER_FN();
    cdb      = SRB_CDB(Srb);
    srbExt   = SRB_EXTENSION(Srb);
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    TargetId = SRB_TARGET_ID(Srb);
    Lun      = SRB_LUN(Srb);

    if ((SRB_PATH_ID(Srb) > 0) ||
        (TargetId >= adaptExt->scsi_config.max_target) ||
        (Lun >= adaptExt->scsi_config.max_lun) ) {
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_NO_DEVICE);
        StorPortNotification(RequestComplete,
                             DeviceExtension,
                             Srb);
        return FALSE;
    }

    TRACE4(TRACE_LEVEL_VERBOSE, DRIVER_IO, "SrbInfo",
        "OpCode", ((PCDB)Srb->Cdb)->CDB6GENERIC.OperationCode,
        "PathId", Srb->PathId, "TargetId", Srb->TargetId, "Lun", Srb->Lun);

#ifdef DEBUG
    memset(srbExt, 0xFF, sizeof(SRB_EXTENSION));
#endif
    srbExt->Xfer = 0;
    srbExt->Srb = Srb;
    StorPortGetCurrentProcessorNumber(DeviceExtension, &srbExt->procNum);
    cmd = &srbExt->cmd;
    cmd->sc = Srb;
    cmd->comp = NULL;
    cmd->req.cmd.lun[0] = 1;
    cmd->req.cmd.lun[1] = TargetId;
    cmd->req.cmd.lun[2] = 0;
    cmd->req.cmd.lun[3] = Lun;
    cmd->req.cmd.lun[4] = 0;
    cmd->req.cmd.lun[5] = 0;
    cmd->req.cmd.lun[6] = 0;
    cmd->req.cmd.lun[7] = 0;
    cmd->req.cmd.tag = (ULONG_PTR)(Srb);
    cmd->req.cmd.task_attr = VIRTIO_SCSI_S_SIMPLE;
    cmd->req.cmd.prio = 0;
    cmd->req.cmd.crn = 0;
    if (cdb != NULL) {
        memcpy(cmd->req.cmd.cdb, cdb, min(VIRTIO_SCSI_CDB_SIZE, SRB_CDB_LENGTH(Srb)));
    }

    sgElement = 0;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->req.cmd, &fragLen);
    srbExt->sg[sgElement].length   = sizeof(cmd->req.cmd);
    sgElement++;

    sgList = StorPortGetScatterGatherList(DeviceExtension, Srb);
    if (sgList)
    {
        sgMaxElements = sgList->NumberOfElements;

        if ((SRB_FLAGS(Srb) & SRB_FLAGS_DATA_OUT) == SRB_FLAGS_DATA_OUT) {
            for (i = 0; i < sgMaxElements; i++, sgElement++) {
                srbExt->sg[sgElement].physAddr = sgList->List[i].PhysicalAddress;
                srbExt->sg[sgElement].length = sgList->List[i].Length;
                srbExt->Xfer += sgList->List[i].Length;
            }
        }
    }
    srbExt->out = sgElement;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->resp.cmd, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->resp.cmd);
    sgElement++;
    if (sgList)
    {
        sgMaxElements = sgList->NumberOfElements;

        if ((SRB_FLAGS(Srb) & SRB_FLAGS_DATA_OUT) != SRB_FLAGS_DATA_OUT) {
            for (i = 0; i < sgMaxElements; i++, sgElement++) {
                srbExt->sg[sgElement].physAddr = sgList->List[i].PhysicalAddress;
                srbExt->sg[sgElement].length = sgList->List[i].Length;
                srbExt->Xfer += sgList->List[i].Length;
            }
        }
    }
    srbExt->in = sgElement - srbExt->out;

EXIT_FN();
    return TRUE;
}

VOID
FORCEINLINE
DispatchQueue(
    IN PVOID DeviceExtension,
    IN ULONG MessageID
    )
{
    PADAPTER_EXTENSION  adaptExt;
    ULONG queue;
    ULONG cpu;
#if (NTDDI_VERSION >= NTDDI_WIN7)
    PROCESSOR_NUMBER ProcNumber;
    KeGetCurrentProcessorNumberEx(&ProcNumber);
    cpu = ProcNumber.Number;
#else
    cpu = KeGetCurrentProcessorNumber();
#endif
ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    queue = MessageID - 3;
    if (adaptExt->num_queues == 1) {
        cpu = 0;
    }
    if (!adaptExt->dump_mode && adaptExt->dpc_ok && MessageID > 0) {
        // FIXME: This will fail with cpu hot plug.
        StorPortIssueDpc(DeviceExtension,
            &adaptExt->dpc[queue],
            ULongToPtr(MessageID),
            ULongToPtr(cpu));
EXIT_FN();
        return;
    }
    ProcessQueue(DeviceExtension, MessageID, FALSE);
EXIT_FN();
}

VOID
ProcessQueue(
    IN PVOID DeviceExtension,
    IN ULONG MessageID,
    IN BOOLEAN dpc
    )
{
    PVirtIOSCSICmd      cmd;
    unsigned int        len;
    PADAPTER_EXTENSION  adaptExt;
    PSRB_TYPE           Srb;
    PSRB_EXTENSION      srbExt;
    ULONG               msg = MessageID - 3;
    STOR_LOCK_HANDLE    LockHandle = { 0 };
    ULONGLONG           tsc = 0;
    ULONGLONG           srbLatency;
    ULONG               TargetId;

#if (NTDDI_VERSION >= NTDDI_WIN7)
        PROCESSOR_NUMBER ProcNumber;
        KeGetCurrentProcessorNumberEx(&ProcNumber);
#else
        ULONG processor = KeGetCurrentProcessorNumber();
#endif
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
ENTER_FN();
#ifdef ENABLE_WMI
    tsc = ReadTimeStampCounter();
#endif
    if (dpc) {
        Lock(DeviceExtension, MessageID, &LockHandle);
    }
    while ((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_REQUEST_QUEUE_0 + msg], &len)) != NULL)
    {
        Srb = (PSRB_TYPE)cmd->sc;
        srbExt = SRB_EXTENSION(Srb);
#ifdef ENABLE_WMI
        TargetId = SRB_TARGET_ID(Srb);
        adaptExt->QueueStats[msg].CompletedRequests++;
        adaptExt->TargetStats[TargetId].CompletedRequests++;
        srbLatency = tsc - srbExt->startTsc;
        if (srbLatency > adaptExt->QueueStats[msg].MaxLatency) adaptExt->QueueStats[msg].MaxLatency = srbLatency;
        if (srbLatency > adaptExt->TargetStats[TargetId].MaxLatency) adaptExt->TargetStats[TargetId].MaxLatency = srbLatency;
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
        CHECK_CPU(Srb);
#endif
        if ((adaptExt->num_queues > 1) &&
            !(CHECKFLAG(adaptExt->perfFlags, STOR_PERF_ADV_CONFIG_LOCALITY)) &&
#if (NTDDI_VERSION >= NTDDI_WIN7)
            (ProcNumber.Group != srbExt->procNum.Group ||
            ProcNumber.Number != srbExt->procNum.Number)
#else
            processor != srbExt->procNum.Number
#endif
            )
        {
            ULONG tmp;
            TRACE6(TRACE_LEVEL_INFORMATION, DRIVER_IO, "Srb info", "issued on", srbExt->procNum.Number,
                "issued group", srbExt->procNum.Group, "received on", ProcNumber.Number,
                "received group", ProcNumber.Group, "MessageID", MessageID, "Queue", VIRTIO_SCSI_REQUEST_QUEUE_0 + msg);

#if (NTDDI_VERSION >= NTDDI_WIN7)
            tmp = adaptExt->cpu_to_vq_map[ProcNumber.Number];
            adaptExt->cpu_to_vq_map[ProcNumber.Number] = adaptExt->cpu_to_vq_map[srbExt->procNum.Number];
#else
            tmp = adaptExt->cpu_to_vq_map[processor];
            adaptExt->cpu_to_vq_map[processor] = adaptExt->cpu_to_vq_map[srbExt->procNum.Number];
#endif
            adaptExt->cpu_to_vq_map[srbExt->procNum.Number] = (UCHAR)tmp;
        }
        HandleResponse(DeviceExtension, cmd, msg);
    }
    if (dpc) {
        Unlock(DeviceExtension, MessageID, &LockHandle);
    }
EXIT_FN();
}

VOID
VioScsiCompleteDpcRoutine(
    IN PSTOR_DPC  Dpc,
    IN PVOID Context,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    )
{
    ULONG MessageId;

    MessageId = PtrToUlong(SystemArgument1);
    ProcessQueue(Context, MessageId, TRUE);
}

VOID
CompleteSrbSnapshotRequested(
    IN PADAPTER_EXTENSION adaptExt,
    IN UCHAR Target,
    IN UCHAR Lun,
    IN BOOLEAN DeviceAck
    )
{
    PSRB_TYPE Srb = ClearSrbSnapshotRequested(adaptExt);
    if (Srb) {
        PSRB_VSS_BUFFER vssBuffer = (PSRB_VSS_BUFFER)SRB_DATA_BUFFER(Srb);
        vssBuffer->SrbIoControl.ReturnCode = SNAPSHOT_STATUS_SUCCEED;
        vssBuffer->Target = Target;
        vssBuffer->Lun = Lun;

        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
        CompleteRequest(adaptExt, Srb);
    } else {
         if (DeviceAck) {
             // No pending Srb found, report that Vss snapshots are currently
             // unavailable.
             ReportSnapshotStatus(adaptExt, NULL, Target, Lun,
                                  VIRTIO_SCSI_SNAPSHOT_PREPARE_UNAVAILABLE);
         }
    }
}

VOID
CompleteSrbSnapshotCanProceed(
    IN PADAPTER_EXTENSION adaptExt,
    IN UCHAR Target,
    IN UCHAR Lun,
    IN ULONG ReturnCode
    )
{
    PSRB_TYPE Srb = ClearSrbSnapshotCanProceed(adaptExt);
    if (Srb) {
        PSRB_VSS_BUFFER vssBuffer = (PSRB_VSS_BUFFER)SRB_DATA_BUFFER(Srb);
        vssBuffer->SrbIoControl.ReturnCode = ReturnCode;
        vssBuffer->Target = Target;
        vssBuffer->Lun = Lun;

        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
        CompleteRequest(adaptExt, Srb);
    }
}

// For the request being processed, return appropriate status back to the
// StartIo driver entry.
//   STATUS_SUCCESS:
//       the request has been successfully processed and can be "completed".
//   STATUS_PENDING:
//       the request is not finished yet and will be left in pending state.
//   STATUS_BUSY:
//       the request will be discarded without processing.
//   STATUS_MORE_PROCESSING_REQUIRED:
//       the SRB will be sent to the device for more processing.
NTSTATUS
FORCEINLINE
PreProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
    PADAPTER_EXTENSION adaptExt;
    ULONG PnPFlags = 0;
    ULONG PnPAction = 0;
    PSTOR_DEVICE_CAPABILITIES_TYPE pDevCapabilities = NULL;
    NTSTATUS status = STATUS_MORE_PROCESSING_REQUIRED;
ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    switch (SRB_FUNCTION(Srb)) {
        case SRB_FUNCTION_PNP:
#if (NTDDI_VERSION > NTDDI_WIN7)
            SRB_GET_PNP_INFO(Srb, PnPFlags, PnPAction);
            if (((PnPFlags & SRB_PNP_FLAGS_ADAPTER_REQUEST) == 0) &&
                (PnPAction == StorQueryCapabilities) &&
                (SRB_DATA_TRANSFER_LENGTH(Srb) >= sizeof(STOR_DEVICE_CAPABILITIES))) {
                pDevCapabilities = (PSTOR_DEVICE_CAPABILITIES_TYPE)SRB_DATA_BUFFER(Srb);
                pDevCapabilities->Version = 0;
                pDevCapabilities->DeviceD1 = 0;
                pDevCapabilities->DeviceD2 = 0;
                pDevCapabilities->LockSupported = 0;
                pDevCapabilities->EjectSupported = 0;
                pDevCapabilities->Removable = 1;
                pDevCapabilities->DockDevice = 0;
                pDevCapabilities->UniqueID = 0;
                pDevCapabilities->SilentInstall = 0;
                pDevCapabilities->SurpriseRemovalOK = 1;
                pDevCapabilities->NoDisplayInUI = 0;
            }
#endif
            // fallthrough
        case SRB_FUNCTION_POWER: {
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
            status = STATUS_SUCCESS;
            break;
        }
        case SRB_FUNCTION_RESET_LOGICAL_UNIT:
            adaptExt->TargetStats[SRB_TARGET_ID(Srb)].ResetRequests++;
        case SRB_FUNCTION_RESET_DEVICE:
        case SRB_FUNCTION_RESET_BUS:
            TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Hierarchical reset", "function", adaptExt->queue_depth);
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
            status = STATUS_SUCCESS;
            break;
#ifdef ENABLE_WMI
        case SRB_FUNCTION_WMI:
            WmiSrb(adaptExt, Srb);
            status = STATUS_SUCCESS;
            break;
#endif
        case SRB_FUNCTION_IO_CONTROL: {
            ULONG controlCode;
            PSRB_IO_CONTROL SrbIoctl = SRB_DATA_BUFFER(Srb);
            controlCode = SrbIoctl->ControlCode;
            status = STATUS_SUCCESS;
            // Validate the input buffer.
            if ((SRB_DATA_TRANSFER_LENGTH(Srb) <
                 SrbIoctl->Length + sizeof(SRB_IO_CONTROL)) ||
                SRB_DATA_TRANSFER_LENGTH(Srb) < sizeof(SRB_VSS_BUFFER)) {

                SRB_SET_SRB_STATUS(Srb, SRB_STATUS_ERROR);
                SrbIoctl->ReturnCode = SNAPSHOT_STATUS_INVALID_REQUEST;
            } else {
                switch (controlCode) {
                    case IOCTL_SNAPSHOT_REQUESTED:
                        if (!SetSrbSnapshotRequested(adaptExt, Srb)) {
                            // If there is an existing pending request, discard
                            // any new request until the current one completes.
                            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BUSY);
                        } else {
                            // We are not completing the request right away,
                            // it will stay pending.
                            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_PENDING);
                            status = STATUS_PENDING;
                        }
                        break;
                    case IOCTL_SNAPSHOT_CAN_PROCEED:
                        if (!SetSrbSnapshotCanProceed(adaptExt, Srb)) {
                            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BUSY);
                        } else {
                            PSRB_VSS_BUFFER vssBuf= (PSRB_VSS_BUFFER)SrbIoctl;
                            if (ReportSnapshotStatus(adaptExt,
                                                     Srb,
                                                     vssBuf->Target,
                                                     vssBuf->Lun,
                                                     vssBuf->Status)) {
                                // SRB will be completed once the backend send
                                // event to resume writer.
                                SRB_SET_SRB_STATUS(Srb, SRB_STATUS_PENDING);
                                status = STATUS_PENDING;
                            } else {
                                // Sth went wrong.
                                SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BUSY);
                            }
                        }
                        break;
                    case IOCTL_SNAPSHOT_DISCARD:
                        // Discard any pending SRB for snapshot.
                        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
                        CompleteSrbSnapshotRequested(adaptExt, 0, 0, false);
                        CompleteSrbSnapshotCanProceed(
                            adaptExt, 0, 0, SNAPSHOT_STATUS_CANCELLED);
                        break;
                    default:
                        break;
                }
            }
        }
    }
EXIT_FN();
    return status;
}

VOID
PostProcessRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
    PCDB                  cdb;
    PADAPTER_EXTENSION    adaptExt;
    PSRB_EXTENSION        srbExt;
#ifdef ENABLE_WMI
    ULONG                 target, TargetId;
#endif

ENTER_FN();
    cdb      = SRB_CDB(Srb);
    srbExt   = SRB_EXTENSION(Srb);
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    if (cdb == NULL) return;
    switch (cdb->CDB6GENERIC.OperationCode)
    {
        case SCSIOP_READ_CAPACITY:
        case SCSIOP_READ_CAPACITY16:
            if (!StorPortSetDeviceQueueDepth(DeviceExtension, SRB_PATH_ID(Srb),
                SRB_TARGET_ID(Srb), SRB_LUN(Srb), adaptExt->queue_depth)) {
               TRACE1(TRACE_LEVEL_ERROR, DRIVER_IO, "StorPortSetDeviceQueueDepth failed", "queue_depth", adaptExt->queue_depth);
           }
#ifdef ENABLE_WMI
           // Update adaptExt->MaxLun with interlocked operations.
           // There is a chance that another thread will collide with this and we will have
           // to iterate again, but it's very small.
            TargetId = (ULONG)SRB_TARGET_ID(Srb);
            while ((target = adaptExt->MaxTarget) < TargetId + 1) {
                InterlockedCompareExchange(&adaptExt->MaxTarget, TargetId + 1, target);
            }
#endif
           break;
        default:
           break;

    }
EXIT_FN();
}

VOID
CompleteRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
ENTER_FN();
    PostProcessRequest(DeviceExtension, Srb);
    StorPortNotification(RequestComplete,
                         DeviceExtension,
                         Srb);
EXIT_FN();
}

VOID
LogError(
    IN PVOID DeviceExtension,
    IN ULONG ErrorCode,
    IN ULONG UniqueId
    )
{
#if (NTDDI_VERSION > NTDDI_WIN7)
    STOR_LOG_EVENT_DETAILS logEvent;
    ULONG sz = 0;
    memset( &logEvent, 0, sizeof(logEvent) );
    logEvent.InterfaceRevision         = STOR_CURRENT_LOG_INTERFACE_REVISION;
    logEvent.Size                      = sizeof(logEvent);
    logEvent.EventAssociation          = StorEventAdapterAssociation;
    logEvent.StorportSpecificErrorCode = TRUE;
    logEvent.ErrorCode                 = ErrorCode;
    logEvent.DumpDataSize              = sizeof(UniqueId);
    logEvent.DumpData                  = &UniqueId;
    StorPortLogSystemEvent( DeviceExtension, &logEvent, &sz );
#else
    StorPortLogError(DeviceExtension,
                         NULL,
                         0,
                         0,
                         0,
                         ErrorCode,
                         UniqueId);
#endif
}

VOID
TransportReset(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    TRACE_CONTEXT_NO_SRB();
    switch (evt->reason)
    {
        case VIRTIO_SCSI_EVT_RESET_RESCAN:
            StorPortNotification( BusChangeDetected, DeviceExtension, 0);
            break;
        case VIRTIO_SCSI_EVT_RESET_REMOVED:
            StorPortNotification( BusChangeDetected, DeviceExtension, 0);
            break;
        default:
            TRACE1(TRACE_LEVEL_VERBOSE, DRIVER_START, "<-->Unsupport virtio scsi event reason", "reason", evt->reason);
    }
}

bool
DecodeAddress(
    UCHAR* TargetId,
    UCHAR* LunId,
    const u8 lun[8]
    )
{
    // Interleaved quotes from virtio spec follow.
    // "first byte set to 1,"
    if (lun[0] != 1) {
        return false;
    }

    // "second byte set to target,"
    *TargetId = lun[1];

    *LunId = ((lun[2] & 0x3F) << 8) | lun[3];

    // "followed by four zero bytes."
    if (lun[4] || lun[5] || lun[6] || lun[7]) {
        return false;
    }

    return true;
}

void
RequestSnapshot(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    UCHAR targetId;
    UCHAR lunId;

    if (DecodeAddress(&targetId, &lunId, evt->lun)) {
        CompleteSrbSnapshotRequested(adaptExt, targetId, lunId, true);
    }
}

VOID
ProcessSnapshotCompletion(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    UCHAR targetId;
    UCHAR lunId;

    if (DecodeAddress(&targetId, &lunId, evt->lun)) {
        CompleteSrbSnapshotCanProceed(adaptExt, targetId, lunId,
                                      SNAPSHOT_STATUS_SUCCEED);
    }
}

VOID
ParamChange(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEvent evt
    )
{
    UCHAR AdditionalSenseCode = (UCHAR)(evt->reason & 255);
    UCHAR AdditionalSenseCodeQualifier = (UCHAR)(evt->reason >> 8);

    if (AdditionalSenseCode == SCSI_ADSENSE_PARAMETERS_CHANGED &&
       (AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_PARAMETERS_CHANGED ||
        AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_MODE_PARAMETERS_CHANGED ||
        AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_CAPACITY_DATA_HAS_CHANGED))
    {
        StorPortNotification( BusChangeDetected, DeviceExtension, 0);
    }
}

