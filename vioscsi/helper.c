/**********************************************************************
 * Copyright (c) 2012-2015 Red Hat, Inc.
 *
 * File: helper.c
 *
 * Author(s):
 * Vadim Rozenfeld <vrozenfe@redhat.com>
 *
 * This file contains various virtio queue related routines.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
**********************************************************************/
#include "helper.h"
#include "utils.h"

#if (INDIRECT_SUPPORTED == 1)
#define SET_VA_PA() { ULONG len; va = adaptExt->indirect ? srbExt->desc : NULL; \
                      pa = va ? StorPortGetPhysicalAddress(DeviceExtension, NULL, va, &len).QuadPart : 0; \
                    }
#else
#define SET_VA_PA()   va = NULL; pa = 0;
#endif

VOID
Lock(
    IN PVOID DeviceExtension,
    IN ULONG MessageID,
    OUT PSTOR_LOCK_HANDLE LockHandle
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    if (adaptExt->num_queues > 1) {
        // Queue numbers start at 0, message ids at 1.
        NT_ASSERT(MessageID > VIRTIO_SCSI_REQUEST_QUEUE_0);
        StorPortAcquireSpinLock(DeviceExtension, DpcLock, &adaptExt->dpc[MessageID - VIRTIO_SCSI_REQUEST_QUEUE_0 - 1], LockHandle);
    }
    else {
        StorPortAcquireSpinLock(DeviceExtension, InterruptLock, NULL, LockHandle);
    }
}

VOID
Unlock(
    IN PVOID DeviceExtension,
    IN ULONG MessageID,
    IN PSTOR_LOCK_HANDLE LockHandle
    )
{
    StorPortReleaseSpinLock(DeviceExtension, LockHandle);
}

BOOLEAN
SendSRB(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_EXTENSION      srbExt   = SRB_EXTENSION(Srb);
    PVOID               va = NULL;
    ULONGLONG           pa = 0;
    ULONG               QueueNumber = 0;
    ULONG               MessageId = 0;
    BOOLEAN             result = FALSE;
    bool                notify = FALSE;
    STOR_LOCK_HANDLE    LockHandle = { 0 };
#ifdef ENABLE_WMI
    ULONGLONG           timeSinceLastStartIo;
    PVIRTQUEUE_STATISTICS queueStats;
#endif
ENTER_FN();
    SET_VA_PA();
    QueueNumber = adaptExt->cpu_to_vq_map[srbExt->procNum.Number] + VIRTIO_SCSI_REQUEST_QUEUE_0;
    TRACE3(TRACE_LEVEL_INFORMATION, DRIVER_IO, "SrbInfo", "issued on", srbExt->procNum.Number,
        "group", srbExt->procNum.Group, "QueueNumber", QueueNumber);

    MessageId = QueueNumber + 1;
#ifdef ENABLE_WMI
    queueStats = &adaptExt->QueueStats[QueueNumber - VIRTIO_SCSI_REQUEST_QUEUE_0];
    srbExt->startTsc = ReadTimeStampCounter();
#endif
    Lock(DeviceExtension, MessageId, &LockHandle);
    if (CHECKFLAG(adaptExt->perfFlags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO)) {
        ProcessQueue(DeviceExtension, MessageId, FALSE);
    }
#ifdef ENABLE_WMI
    if (queueStats->LastStartIo != 0) {
        timeSinceLastStartIo = srbExt->startTsc - queueStats->LastStartIo;
        if (queueStats->MaxStartIoDelay < timeSinceLastStartIo) {
            queueStats->MaxStartIoDelay = timeSinceLastStartIo;
        }
    }
    queueStats->LastStartIo = srbExt->startTsc;
#endif
    if (virtqueue_add_buf(adaptExt->vq[QueueNumber],
                     &srbExt->sg[0],
                     srbExt->out, srbExt->in,
                     &srbExt->cmd, va, pa) >= 0){
#ifdef ENABLE_WMI
        queueStats->TotalRequests++;
        adaptExt->TargetStats[SRB_TARGET_ID(Srb)].TotalRequests++;
#endif
        result = TRUE;
        notify = virtqueue_kick_prepare(adaptExt->vq[QueueNumber]);
    }
    else {
#ifdef ENABLE_WMI
        queueStats->QueueFullEvents++;
#endif
        TRACE1(TRACE_LEVEL_WARNING, DRIVER_IO, "Cant add packet to queue", "QueueNumber", QueueNumber);
    }
    Unlock(DeviceExtension, MessageId, &LockHandle);
    if (notify) {
        virtqueue_notify(adaptExt->vq[QueueNumber]);
#ifdef ENABLE_WMI
        queueStats->TotalKicks++;
#endif
    }
    else {
#ifdef ENABLE_WMI
        queueStats->SkippedKicks++;
#endif
    }
    return result;
EXIT_FN();
}

BOOLEAN
SynchronizedTMFRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSCSI_REQUEST_BLOCK Srb      = (PSCSI_REQUEST_BLOCK) Context;
    PSRB_EXTENSION      srbExt   = (PSRB_EXTENSION)Srb->SrbExtension;
    PVOID               va;
    ULONGLONG           pa;

ENTER_FN();
    SET_VA_PA();
    if (virtqueue_add_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE],
                     &srbExt->sg[0],
                     srbExt->out, srbExt->in,
                     &srbExt->cmd, va, pa) >= 0){
        virtqueue_kick(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE]);
        return TRUE;
    }
    Srb->SrbStatus = SRB_STATUS_BUSY;
    StorPortBusy(DeviceExtension, adaptExt->queue_depth);
EXIT_ERR();
    return FALSE;
}

BOOLEAN
SendTMF(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    )
{
ENTER_FN();
    return StorPortSynchronizeAccess(DeviceExtension, SynchronizedTMFRoutine, (PVOID)Srb);
EXIT_FN();
}

BOOLEAN
SynchronizedVssControlRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_TYPE           Srb      = (PSRB_TYPE)Context;
    PSRB_EXTENSION      srbExt   = SRB_EXTENSION(Srb);
    PVOID               va;
    ULONGLONG           pa;

ENTER_FN();
    SET_VA_PA();
    if (virtqueue_add_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE],
                     &srbExt->sg[0],
                     srbExt->out, srbExt->in,
                     &srbExt->cmd, va, pa) >= 0){
        virtqueue_kick(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE]);
        return TRUE;
    }
    Srb->SrbStatus = SRB_STATUS_BUSY;
    StorPortBusy(DeviceExtension, adaptExt->queue_depth);
EXIT_ERR();
    return FALSE;
}

BOOLEAN
SendVssControl(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
ENTER_FN();
    return StorPortSynchronizeAccess(DeviceExtension,
                                     SynchronizedVssControlRoutine,
                                     (PVOID)Srb);
EXIT_FN();
}

BOOLEAN
DeviceReset(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSCSI_REQUEST_BLOCK   Srb = &adaptExt->tmf_cmd.Srb;
    PSRB_EXTENSION        srbExt = adaptExt->tmf_cmd.SrbExtension;
    VirtIOSCSICmd         *cmd = &srbExt->cmd;
    ULONG                 fragLen;
    ULONG                 sgElement;

ENTER_FN();
    if (adaptExt->dump_mode) {
        return TRUE;
    }
    ASSERT(adaptExt->tmf_infly == FALSE);
    Srb->SrbExtension = srbExt;
    memset((PVOID)cmd, 0, sizeof(VirtIOSCSICmd));
    cmd->sc = Srb;
    cmd->req.tmf.lun[0] = 1;
    cmd->req.tmf.lun[1] = 0;
    cmd->req.tmf.lun[2] = 0;
    cmd->req.tmf.lun[3] = 0;
    cmd->req.tmf.type = VIRTIO_SCSI_T_TMF;
    cmd->req.tmf.subtype = VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET;

    sgElement = 0;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->req.tmf, &fragLen);
    srbExt->sg[sgElement].length   = sizeof(cmd->req.tmf);
    sgElement++;
    srbExt->out = sgElement;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->resp.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->resp.tmf);
    sgElement++;
    srbExt->in = sgElement - srbExt->out;
    StorPortPause(DeviceExtension, 60);
    if (!SendTMF(DeviceExtension, Srb)) {
        StorPortResume(DeviceExtension);
        return FALSE;
    }
    adaptExt->tmf_infly = TRUE;
    return TRUE;
}

BOOLEAN
ReportDriverVersion(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSCSI_REQUEST_BLOCK   Srb = &adaptExt->tmf_cmd.Srb;
    PSRB_EXTENSION        srbExt = adaptExt->tmf_cmd.SrbExtension;
    VirtIOSCSICmd         *cmd = &srbExt->cmd;
    ULONG                 fragLen;
    ULONG                 sgElement;

    ENTER_FN();
    if (adaptExt->dump_mode ||
        !CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_GOOGLE_REPORT_DRIVER_VERSION)) {
        return TRUE;
    }
    ASSERT(adaptExt->tmf_infly == FALSE);
    Srb->SrbExtension = srbExt;
    memset((PVOID)cmd, 0, sizeof(VirtIOSCSICmd));
    cmd->sc = Srb;
    cmd->req.google.lun[0] = 1;
    cmd->req.google.lun[1] = 0;
    cmd->req.google.lun[2] = 0;
    cmd->req.google.lun[3] = 0;
    cmd->req.google.type = VIRTIO_SCSI_T_GOOGLE;
    cmd->req.google.subtype = VIRTIO_SCSI_T_GOOGLE_REPORT_DRIVER_VERSION;
    cmd->req.google.data = _NT_TARGET_MIN;

    sgElement = 0;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->req.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->req.google);
    sgElement++;
    srbExt->out = sgElement;
    srbExt->sg[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->resp.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->resp.google);
    sgElement++;
    srbExt->in = sgElement - srbExt->out;

    if (!SendTMF(DeviceExtension, Srb)) {
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
ReportSnapshotStatus(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb,
    IN UCHAR Target,
    IN UCHAR Lun,
    IN u64 Status
    )
{
    PSRB_TYPE  workingSrb = NULL;
    PSRB_EXTENSION srbExt = NULL;
    PADAPTER_EXTENSION    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    BOOLEAN ignoreStorportSync = false;
    ENTER_FN();
    if (adaptExt->dump_mode) {
        return TRUE;
    }
    if (!Srb) {
        // If there is no Srb present, use the global structure in the device
        // extension to allow fast failure.
        workingSrb = (PSRB_TYPE) &adaptExt->snapshot_fail_srb;
        srbExt = &adaptExt->snapshot_fail_extension;

        srbExt->Srb = (PSCSI_REQUEST_BLOCK) workingSrb;
        ((PSCSI_REQUEST_BLOCK) workingSrb)->SrbExtension = srbExt;
        ignoreStorportSync = true;
    } else {
        workingSrb = Srb;
        srbExt = SRB_EXTENSION(workingSrb);
    }

    VirtIOSCSICmd         *cmd = &srbExt->cmd;
    ULONG                 fragLen;
    ULONG                 sgElement;

    memset((PVOID)cmd, 0, sizeof(VirtIOSCSICmd));
    cmd->sc = workingSrb;
    cmd->req.google.lun[0] = 1;
    cmd->req.google.lun[1] = Target;
    cmd->req.google.lun[2] = 0;
    cmd->req.google.lun[3] = Lun;
    cmd->req.google.lun[4] = 0;
    cmd->req.google.lun[5] = 0;
    cmd->req.google.lun[6] = 0;
    cmd->req.google.lun[7] = 0;

    cmd->req.google.type = VIRTIO_SCSI_T_GOOGLE;
    cmd->req.google.subtype = VIRTIO_SCSI_T_GOOGLE_REPORT_SNAPSHOT_READY;
    cmd->req.google.data = Status;

    sgElement = 0;
    srbExt->sg[sgElement].physAddr =
        StorPortGetPhysicalAddress(
            DeviceExtension, NULL, &cmd->req.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->req.google);
    sgElement++;
    srbExt->out = sgElement;
    srbExt->sg[sgElement].physAddr =
        StorPortGetPhysicalAddress(
            DeviceExtension, NULL, &cmd->resp.tmf, &fragLen);
    srbExt->sg[sgElement].length = sizeof(cmd->resp.google);
    sgElement++;
    srbExt->in = sgElement - srbExt->out;

    if (ignoreStorportSync) {
        return SynchronizedVssControlRoutine(DeviceExtension, workingSrb);
    }
    return SendVssControl(DeviceExtension, workingSrb);
}

VOID
ShutDown(
    IN PVOID DeviceExtension
    )
{
    ULONG index;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
ENTER_FN();
    VirtIODeviceReset(adaptExt->pvdev);
    StorPortWritePortUshort(DeviceExtension, (PUSHORT)(adaptExt->device_base + VIRTIO_PCI_GUEST_FEATURES), 0);
    for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
        if (adaptExt->vq[index]) {
            virtqueue_shutdown(adaptExt->vq[index]);
            VirtIODeviceDeleteQueue(adaptExt->vq[index], NULL);
            if (adaptExt->dump_mode && adaptExt->original_queue_num[index] != 0) {
                 StorPortWritePortUshort(DeviceExtension, (PUSHORT)(adaptExt->device_base + VIRTIO_PCI_QUEUE_NUM), adaptExt->original_queue_num[index]);
            }
            adaptExt->vq[index] = NULL;
        }
    }
    if (adaptExt->pmsg_affinity != NULL) {
        StorPortFreePool(DeviceExtension, adaptExt->pmsg_affinity);
        adaptExt->pmsg_affinity = NULL;
    }
EXIT_FN();
}

VOID
GetScsiConfig(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
ENTER_FN();

    adaptExt->features = StorPortReadPortUlong(DeviceExtension, (PULONG)(adaptExt->device_base + VIRTIO_PCI_HOST_FEATURES));

    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, seg_max),
                      &adaptExt->scsi_config.seg_max, sizeof(adaptExt->scsi_config.seg_max));
    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, num_queues),
                      &adaptExt->scsi_config.num_queues, sizeof(adaptExt->scsi_config.num_queues));
    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, max_sectors),
                      &adaptExt->scsi_config.max_sectors, sizeof(adaptExt->scsi_config.max_sectors));
    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, cmd_per_lun),
                      &adaptExt->scsi_config.cmd_per_lun, sizeof(adaptExt->scsi_config.cmd_per_lun));
    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, event_info_size),
                      &adaptExt->scsi_config.event_info_size, sizeof(adaptExt->scsi_config.event_info_size));
    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, sense_size),
                      &adaptExt->scsi_config.sense_size, sizeof(adaptExt->scsi_config.sense_size));
    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, cdb_size),
                      &adaptExt->scsi_config.cdb_size, sizeof(adaptExt->scsi_config.cdb_size));
    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, max_channel),
                      &adaptExt->scsi_config.max_channel, sizeof(adaptExt->scsi_config.max_channel));
    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, max_target),
                      &adaptExt->scsi_config.max_target, sizeof(adaptExt->scsi_config.max_target));
    VirtIODeviceGet( adaptExt->pvdev, FIELD_OFFSET(VirtIOSCSIConfig, max_lun),
                      &adaptExt->scsi_config.max_lun, sizeof(adaptExt->scsi_config.max_lun));

EXIT_FN();
}

BOOLEAN
InitHW(
    IN PVOID DeviceExtension,
    IN PPORT_CONFIGURATION_INFORMATION ConfigInfo
    )
{
    PACCESS_RANGE      accessRange;
    PADAPTER_EXTENSION adaptExt;
    TRACE_CONTEXT_NO_SRB();

ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    accessRange = &(*ConfigInfo->AccessRanges)[0];

    ASSERT (FALSE == accessRange->RangeInMemory) ;

    TRACE2(TRACE_LEVEL_INFORMATION, DRIVER_START, "Port  Resource",
        "Range start", accessRange->RangeStart.QuadPart,
        "Range end", accessRange->RangeStart.QuadPart + accessRange->RangeLength);

    if ( accessRange->RangeLength < IO_PORT_LENGTH) {
        LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);
        TRACE1(TRACE_LEVEL_FATAL, DRIVER_START, "Wrong access range", "bytes", accessRange->RangeLength);
        return FALSE;
    }

    adaptExt->device_base = (ULONG_PTR)StorPortGetDeviceBase(DeviceExtension,
                                           ConfigInfo->AdapterInterfaceType,
                                           ConfigInfo->SystemIoBusNumber,
                                           accessRange->RangeStart,
                                           accessRange->RangeLength,
                                           (BOOLEAN)!accessRange->RangeInMemory);

    if (adaptExt->device_base == (ULONG_PTR)NULL) {
        LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);

        TRACE2(TRACE_LEVEL_FATAL, DRIVER_START, "Couldn't map",
            "RangeStart", (*ConfigInfo->AccessRanges)[0].RangeStart.LowPart,
            "bytes", (*ConfigInfo->AccessRanges)[0].RangeLength);
        return FALSE;
    }

    adaptExt->pvdev = &adaptExt->vdev;
    VirtIODeviceInitialize(adaptExt->pvdev, adaptExt->device_base, sizeof(VirtIODevice));

EXIT_FN();
    return TRUE;
}

BOOLEAN
SynchronizedKickEventRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PVirtIOSCSIEventNode eventNode   = (PVirtIOSCSIEventNode) Context;
    PVOID               va = NULL;
    ULONGLONG           pa = 0;

ENTER_FN();
    if (virtqueue_add_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE],
                     &eventNode->sg,
                     0, 1,
                     eventNode, va, pa) >= 0){
        virtqueue_kick(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE]);
        return TRUE;
    }
EXIT_ERR();
    return FALSE;
}


BOOLEAN
KickEvent(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEventNode EventNode
    )
{
    PADAPTER_EXTENSION adaptExt;
    ULONG              fragLen;

ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    memset((PVOID)EventNode, 0, sizeof(VirtIOSCSIEventNode));
    EventNode->sg.physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &EventNode->event, &fragLen);
    EventNode->sg.length   = sizeof(VirtIOSCSIEvent);
    return SynchronizedKickEventRoutine(DeviceExtension, (PVOID)EventNode);
EXIT_FN();
}
