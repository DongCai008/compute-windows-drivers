#ifndef ___SNAPSHOT_H__
#define ___SNAPSHOT_H__

#include <ntddscsi.h>

#define GOOGLE_VSS_AGENT_SIG "GOOOGVSS"

#ifndef PSRB_TYPE
#if (NTDDI_VERSION > NTDDI_WIN7)
#define PSRB_TYPE PSTORAGE_REQUEST_BLOCK
#else
#define PSRB_TYPE PSCSI_REQUEST_BLOCK
#endif
#endif

/* VSS Feature Bits*/
#define VIRTIO_SCSI_F_GOOGLE_ALLDISK_SNAPSHOT      21
#define VIRTIO_SCSI_F_GOOGLE_SNAPSHOT              22
#define VIRTIO_SCSI_F_GOOGLE_REPORT_DRIVER_VERSION 23

/* Controlq type codes.  */
#define VIRTIO_SCSI_T_GOOGLE                   0x80000000

/* Valid Google control queue message subtypes. */
#define VIRTIO_SCSI_T_GOOGLE_REPORT_DRIVER_VERSION 0
#define VIRTIO_SCSI_T_GOOGLE_REPORT_SNAPSHOT_READY 1

// Google VSS SnapshotRequest events:
#define VIRTIO_SCSI_T_SNAPSHOT_START           100
#define VIRTIO_SCSI_T_SNAPSHOT_COMPLETE        101
#define VIRTIO_SCSI_T_ALLDISK_SNAPSHOT_START   102
#define VIRTIO_SCSI_T_ALLDISK_SNAPSHOT_COMPLETE 103

/* Google control message */
#pragma pack(1)
typedef struct {
  u32 type;
  u32 subtype;
  u8 lun[8];
  u64 data;
} VirtIOSCSICtrlGoogleReq, *PVirtIOSCSICtrlGoogleReq;
#pragma pack()

#pragma pack(1)
typedef struct {
  u8 response;
} VirtIOSCSICtrlGoogleResp, *PVirtIOSCSICtrlGoogleResp;
#pragma pack()

// DeviceIoControl functions of the driver.
#define SNAPSHOT_REQUESTED         0xE000
#define SNAPSHOT_CAN_PROCEED       0xE010
#define SNAPSHOT_DISCARD           0xE020
#define ALLDISK_SNAPSHOT_REQUESTED 0xE030

// Control codes for the DeviceIoContol functions of the driver.
#define IOCTL_SNAPSHOT_REQUESTED \
    CTL_CODE(SNAPSHOT_REQUESTED, 0x8FF, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SNAPSHOT_CAN_PROCEED \
    CTL_CODE(SNAPSHOT_CAN_PROCEED, 0x8FF, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SNAPSHOT_DISCARD \
    CTL_CODE(SNAPSHOT_DISCARD, 0x8FF, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ALLDISK_SNAPSHOT_REQUESTED \
    CTL_CODE(ALLDISK_SNAPSHOT_REQUESTED, 0x8FF, METHOD_NEITHER, FILE_ANY_ACCESS)

// Constants for ReturnCode in SRB_IO_CONTROL.
//
// Operation succeed.
#define SNAPSHOT_STATUS_SUCCEED           0x00
// Backend failed to create sanpshot.
#define SNAPSHOT_STATUS_BACKEND_FAILED    0x01
// Invalid Target or lun.
#define SNAPSHOT_STATUS_INVALID_DEVICE    0x02
// Wrong parameter.
#define SNAPSHOT_STATUS_INVALID_REQUEST   0x03
// Operation is cancelled.
#define SNAPSHOT_STATUS_CANCELLED         0x04

/* Status codes for report snapshot ready controlq command */
#define VIRTIO_SCSI_SNAPSHOT_PREPARE_COMPLETE 0
#define VIRTIO_SCSI_SNAPSHOT_PREPARE_UNAVAILABLE 1
#define VIRTIO_SCSI_SNAPSHOT_PREPARE_ERROR 2
#define VIRTIO_SCSI_SNAPSHOT_COMPLETE 3
#define VIRTIO_SCSI_SNAPSHOT_ERROR 4

//
// Structure for Data buffer related with IOCTL_SCSI_MINIPORT.
//
typedef struct {
    SRB_IO_CONTROL SrbIoControl;
    // SNAPSHOT_REQUESTED - output buffer contain the target.
    // SNAPSHOT_CAN_PROCEED - input buffer contain the target.
    UCHAR          Target;
    UCHAR          Lun;
    ULONGLONG      Status;
} SRB_VSS_BUFFER, *PSRB_VSS_BUFFER;

#endif  // ___VIOSCSI_H__
