/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-s1ap.c                                                              */
/* asn2wrs.py -p s1ap -c ./s1ap.cnf -s ./packet-s1ap-template -D . -O ../.. S1AP-CommonDataTypes.asn S1AP-Constants.asn S1AP-Containers.asn S1AP-IEs.asn S1AP-PDU-Contents.asn S1AP-PDU-Descriptions.asn */

/* Input file: packet-s1ap-template.c */

#line 1 "./asn1/s1ap/packet-s1ap-template.c"
/* packet-s1ap.c
 * Routines for E-UTRAN S1 Application Protocol (S1AP) packet dissection
 * Copyright 2007-2016, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Based on the RANAP dissector
 *
 * References: 3GPP TS 36.413 V16.3.0 (2020-09)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-sccp.h"
#include "packet-lte-rrc.h"
#include "packet-ranap.h"
#include "packet-bssgp.h"
#include "packet-s1ap.h"
#include "packet-a21.h"
#include "packet-gsm_map.h"
#include "packet-cell_broadcast.h"
#include "packet-gsm_a_common.h"
#include "packet-ntp.h"
#include "packet-ngap.h"

#define PNAME  "S1 Application Protocol"
#define PSNAME "S1AP"
#define PFNAME "s1ap"

/* Dissector will use SCTP PPID 18 or SCTP port. IANA assigned port = 36412 */
#define SCTP_PORT_S1AP 36412

void proto_register_s1ap(void);
void proto_reg_handoff_s1ap(void);

static dissector_handle_t gcsna_handle;
static dissector_handle_t nas_eps_handle;
static dissector_handle_t lppa_handle;
static dissector_handle_t bssgp_handle;
static dissector_handle_t lte_rrc_ue_radio_access_cap_info_handle;
static dissector_handle_t lte_rrc_ue_radio_access_cap_info_nb_handle;
static dissector_handle_t nr_rrc_ue_radio_access_cap_info_handle;
static dissector_handle_t lte_rrc_ue_radio_paging_info_handle;
static dissector_handle_t lte_rrc_ue_radio_paging_info_nb_handle;


/*--- Included file: packet-s1ap-val.h ---*/
#line 1 "./asn1/s1ap/packet-s1ap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfCSGs                    256
#define maxnoofE_RABs                  256
#define maxNrOfTE_RABs                 8
#define maxnoofTAIs                    256
#define maxnoofTACs                    256
#define maxNrOfErrors                  256
#define maxnoofBPLMNs                  6
#define maxnoofPLMNsPerMME             32
#define maxnoofEPLMNs                  15
#define maxnoofEPLMNsPlusOne           16
#define maxnoofForbLACs                4096
#define maxnoofForbTACs                4096
#define maxNrOfIndividualS1ConnectionsToReset 256
#define maxnoofCells                   16
#define maxnoofTAIforWarning           65535
#define maxnoofCellID                  65535
#define maxnoofEmergencyAreaID         65535
#define maxnoofCellinTAI               65535
#define maxnoofCellinEAI               65535
#define maxnoofeNBX2TLAs               2
#define maxnoofRATs                    8
#define maxnoofGroupIDs                65535
#define maxnoofMMECs                   256
#define maxNrOfIndividualS1GroupConnectionsToReset 256
#define maxnoofGroupCall               256
#define maxnoofCellsineNB              256
#define maxNrOfeNBs                    32

typedef enum _ProcedureCode_enum {
  id_HandoverPreparation =   0,
  id_HandoverResourceAllocation =   1,
  id_HandoverNotification =   2,
  id_PathSwitchRequest =   3,
  id_HandoverCancel =   4,
  id_E_RABSetup =   5,
  id_E_RABModify =   6,
  id_E_RABRelease =   7,
  id_E_RABReleaseIndication =   8,
  id_InitialContextSetup =   9,
  id_Paging    =  10,
  id_downlinkNASTransport =  11,
  id_initialUEMessage =  12,
  id_uplinkNASTransport =  13,
  id_Reset     =  14,
  id_ErrorIndication =  15,
  id_NASNonDeliveryIndication =  16,
  id_S1Setup   =  17,
  id_UEContextReleaseRequest =  18,
  id_DownlinkS1cdma2000tunneling =  19,
  id_UplinkS1cdma2000tunneling =  20,
  id_UEContextModification =  21,
  id_UECapabilityInfoIndication =  22,
  id_UEContextRelease =  23,
  id_eNBStatusTransfer =  24,
  id_MMEStatusTransfer =  25,
  id_DeactivateTrace =  26,
  id_TraceStart =  27,
  id_TraceFailureIndication =  28,
  id_ENBConfigurationUpdate =  29,
  id_MMEConfigurationUpdate =  30,
  id_LocationReportingControl =  31,
  id_LocationReportingFailureIndication =  32,
  id_LocationReport =  33,
  id_OverloadStart =  34,
  id_OverloadStop =  35,
  id_WriteReplaceWarning =  36,
  id_eNBDirectInformationTransfer =  37,
  id_MMEDirectInformationTransfer =  38,
  id_PrivateMessage =  39,
  id_eNBConfigurationTransfer =  40,
  id_MMEConfigurationTransfer =  41,
  id_CellTrafficTrace =  42,
  id_Kill      =  43,
  id_downlinkUEAssociatedLPPaTransport =  44,
  id_uplinkUEAssociatedLPPaTransport =  45,
  id_downlinkNonUEAssociatedLPPaTransport =  46,
  id_uplinkNonUEAssociatedLPPaTransport =  47,
  id_GroupCallContextSetup = 200,
  id_GroupCallContextModification = 201,
  id_GroupCallContextRelease = 202,
  id_GroupTE_RABSetup = 203,
  id_GroupTE_RABModify = 204,
  id_GroupTE_RABRelease = 205,
  id_GroupTE_RABReleaseIndication = 206,
  id_GroupCallContextReleaseIndication = 207,
  id_InstantGroupCallConfigNotify = 208,
  id_GroupCallContextExpansion = 209,
  id_TrunkingIndividualPaging = 210,
  id_GroupDownlinkNASTransport = 211,
  id_TrunkingErrorIndication = 212,
  id_GroupReset = 213,
  id_TrunkingMessageTransport = 214,
  id_TrunkingServingCellUpdateIndication = 215,
  id_eNBGroupCallConfigurationTransfer = 216,
  id_MMEGroupCallConfigurationTransfer = 217
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_MME_UE_S1AP_ID =   0,
  id_HandoverType =   1,
  id_Cause     =   2,
  id_SourceID  =   3,
  id_TargetID  =   4,
  id_eNB_UE_S1AP_ID =   8,
  id_E_RABSubjecttoDataForwardingList =  12,
  id_E_RABtoReleaseListHOCmd =  13,
  id_E_RABDataForwardingItem =  14,
  id_E_RABReleaseItemBearerRelComp =  15,
  id_E_RABToBeSetupListBearerSUReq =  16,
  id_E_RABToBeSetupItemBearerSUReq =  17,
  id_E_RABAdmittedList =  18,
  id_E_RABFailedToSetupListHOReqAck =  19,
  id_E_RABAdmittedItem =  20,
  id_E_RABFailedtoSetupItemHOReqAck =  21,
  id_E_RABToBeSwitchedDLList =  22,
  id_E_RABToBeSwitchedDLItem =  23,
  id_E_RABToBeSetupListCtxtSUReq =  24,
  id_TraceActivation =  25,
  id_NAS_PDU   =  26,
  id_E_RABToBeSetupItemHOReq =  27,
  id_E_RABSetupListBearerSURes =  28,
  id_E_RABFailedToSetupListBearerSURes =  29,
  id_E_RABToBeModifiedListBearerModReq =  30,
  id_E_RABModifyListBearerModRes =  31,
  id_E_RABFailedToModifyList =  32,
  id_E_RABToBeReleasedList =  33,
  id_E_RABFailedToReleaseList =  34,
  id_E_RABItem =  35,
  id_E_RABToBeModifiedItemBearerModReq =  36,
  id_E_RABModifyItemBearerModRes =  37,
  id_E_RABReleaseItem =  38,
  id_E_RABSetupItemBearerSURes =  39,
  id_SecurityContext =  40,
  id_HandoverRestrictionList =  41,
  id_UEPagingID =  43,
  id_pagingDRX =  44,
  id_TAIList   =  46,
  id_TAIItem   =  47,
  id_E_RABFailedToSetupListCtxtSURes =  48,
  id_E_RABReleaseItemHOCmd =  49,
  id_E_RABSetupItemCtxtSURes =  50,
  id_E_RABSetupListCtxtSURes =  51,
  id_E_RABToBeSetupItemCtxtSUReq =  52,
  id_E_RABToBeSetupListHOReq =  53,
  id_GERANtoLTEHOInformationRes =  55,
  id_UTRANtoLTEHOInformationRes =  57,
  id_CriticalityDiagnostics =  58,
  id_Global_ENB_ID =  59,
  id_eNBname   =  60,
  id_MMEname   =  61,
  id_ServedPLMNs =  63,
  id_SupportedTAs =  64,
  id_TimeToWait =  65,
  id_uEaggregateMaximumBitrate =  66,
  id_TAI       =  67,
  id_E_RABReleaseListBearerRelComp =  69,
  id_cdma2000PDU =  70,
  id_cdma2000RATType =  71,
  id_cdma2000SectorID =  72,
  id_SecurityKey =  73,
  id_UERadioCapability =  74,
  id_GUMMEI_ID =  75,
  id_E_RABInformationListItem =  78,
  id_Direct_Forwarding_Path_Availability =  79,
  id_UEIdentityIndexValue =  80,
  id_cdma2000HOStatus =  83,
  id_cdma2000HORequiredIndication =  84,
  id_E_UTRAN_Trace_ID =  86,
  id_RelativeMMECapacity =  87,
  id_SourceMME_UE_S1AP_ID =  88,
  id_Bearers_SubjectToStatusTransfer_Item =  89,
  id_eNB_StatusTransfer_TransparentContainer =  90,
  id_UE_associatedLogicalS1_ConnectionItem =  91,
  id_ResetType =  92,
  id_UE_associatedLogicalS1_ConnectionListResAck =  93,
  id_E_RABToBeSwitchedULItem =  94,
  id_E_RABToBeSwitchedULList =  95,
  id_S_TMSI    =  96,
  id_cdma2000OneXRAND =  97,
  id_RequestType =  98,
  id_UE_S1AP_IDs =  99,
  id_EUTRAN_CGI = 100,
  id_OverloadResponse = 101,
  id_cdma2000OneXSRVCCInfo = 102,
  id_E_RABFailedToBeReleasedList = 103,
  id_Source_ToTarget_TransparentContainer = 104,
  id_ServedGUMMEIs = 105,
  id_SubscriberProfileIDforRFP = 106,
  id_UESecurityCapabilities = 107,
  id_CSFallbackIndicator = 108,
  id_CNDomain  = 109,
  id_E_RABReleasedList = 110,
  id_MessageIdentifier = 111,
  id_SerialNumber = 112,
  id_WarningAreaList = 113,
  id_RepetitionPeriod = 114,
  id_NumberofBroadcastRequest = 115,
  id_WarningType = 116,
  id_WarningSecurityInfo = 117,
  id_DataCodingScheme = 118,
  id_WarningMessageContents = 119,
  id_BroadcastCompletedAreaList = 120,
  id_Inter_SystemInformationTransferTypeEDT = 121,
  id_Inter_SystemInformationTransferTypeMDT = 122,
  id_Target_ToSource_TransparentContainer = 123,
  id_SRVCCOperationPossible = 124,
  id_SRVCCHOIndication = 125,
  id_NAS_DownlinkCount = 126,
  id_CSG_Id    = 127,
  id_CSG_IdList = 128,
  id_SONConfigurationTransferECT = 129,
  id_SONConfigurationTransferMCT = 130,
  id_TraceCollectionEntityIPAddress = 131,
  id_MSClassmark2 = 132,
  id_MSClassmark3 = 133,
  id_RRC_Establishment_Cause = 134,
  id_NASSecurityParametersfromE_UTRAN = 135,
  id_NASSecurityParameterstoE_UTRAN = 136,
  id_DefaultPagingDRX = 137,
  id_Source_ToTarget_TransparentContainer_Secondary = 138,
  id_Target_ToSource_TransparentContainer_Secondary = 139,
  id_EUTRANRoundTripDelayEstimationInfo = 140,
  id_BroadcastCancelledAreaList = 141,
  id_ConcurrentWarningMessageIndicator = 142,
  id_Data_Forwarding_Not_Possible = 143,
  id_ExtendedRepetitionPeriod = 144,
  id_CellAccessMode = 145,
  id_CSGMembershipStatus = 146,
  id_LPPa_PDU  = 147,
  id_Routing_ID = 148,
  id_Time_Synchronization_Info = 149,
  id_PS_ServiceNotAvailable = 150,
  id_RegisteredLAI = 159,
  id_GroupIdentity = 2000,
  id_MME_Group_S1AP_ID = 2001,
  id_CallPriority = 2002,
  id_CallSequence = 2003,
  id_GroupAggregateMaximumBitrate = 2004,
  id_TE_RABToBeSetupListGroupCtxtSUReq = 2005,
  id_TE_RABToBeSetupItemGroupCtxtSUReq = 2006,
  id_GroupCallAreaGroupCtxtSUReq = 2007,
  id_GroupCallSecurityInformation = 2008,
  id_eNB_Group_S1AP_ID = 2009,
  id_TE_RABSetupListGroupCtxtSURes = 2010,
  id_TE_RABSetupItemGroupCtxtSURes = 2011,
  id_TE_RABFailedToSetupListGroupCtxtSURes = 2012,
  id_GroupCallAreaGroupCtxtModReq = 2013,
  id_TAIListItemGroupServiceArea = 2014,
  id_CellListItemGroupServiceArea = 2015,
  id_Group_S1AP_IDs = 2016,
  id_ListOfTargetTAIsTrunkingIndividualPaging = 2017,
  id_ListOfTargetTAIsItemTrunkingIndividualPaging = 2018,
  id_NAS_PDUType = 2019,
  id_GroupResetType = 2020,
  id_Group_associatedLogicalS1_ConnectionItemGroupReset = 2021,
  id_Group_associatedLogicalS1_ConnectionListGroupResetAck = 2022,
  id_Group_associatedLogicalS1_ConnectionItemGroupResetAck = 2023,
  id_TE_RABToBeSetupListGroupBearerSUReq = 2024,
  id_TE_RABToBeSetupItemGroupBearerSUReq = 2025,
  id_MessageServiceArea = 2026,
  id_TE_RABSetupListGroupBearerSURes = 2027,
  id_TE_RABSetupItemGroupBearerSURes = 2028,
  id_TE_RABFailedToSetupListGroupBearerSURes = 2029,
  id_TE_RABToBeModifiedListGroupBearerModReq = 2030,
  id_TE_RABToBeModifiedItemGroupBearerModReq = 2031,
  id_TE_RABModifyListGroupBearerModRes = 2032,
  id_TE_RABModifyItemGroupBearerModRes = 2033,
  id_TE_RABFailedToModifyListGroupBearerModRes = 2034,
  id_TE_RABToBeReleasedListGroupBearerRelCmd = 2035,
  id_TE_RABToBeReleasedItemGroupBearerRelCmd = 2036,
  id_TE_RABReleaseListGroupBearerRelRes = 2037,
  id_TE_RABReleaseItemGroupBearerRelRes = 2038,
  id_TE_RABFailedToReleaseListGroupBearerRelRes = 2039,
  id_TE_RABReleasedListGroupBearerRelInd = 2040,
  id_TrunkingUserIndication = 2041,
  id_PLMNIdentity = 2042,
  id_TargetE_UTRAN_CGI = 2043,
  id_TE_RABItem = 2044,
  id_TargeteNB_List = 2045,
  id_TargeteNB_Item = 2046,
  id_SourceeNB_List = 2047,
  id_NeedResponse = 2048,
  id_GroupConfigurationContainer = 2049,
  id_GroupConfigurationContainerItem = 2050,
  id_AddModGroupCallConfigurationItem = 2051,
  id_ReleaseGroupCallConfigurationItem = 2052,
  id_AMROverPDCPCapablityIndicator = 2053,
  id_SourceeNB_Item = 2054,
  id_AMROverPDCPIndicator = 2055
} ProtocolIE_ID_enum;

typedef enum _HandoverType_enum {
  intralte     =   0,
  ltetoutran   =   1,
  ltetogeran   =   2,
  utrantolte   =   3,
  gerantolte   =   4
} HandoverType_enum;

typedef enum _SRVCCHOIndication_enum {
  pSandCS      =   0,
  cSonly       =   1
} SRVCCHOIndication_enum;

/*--- End of included file: packet-s1ap-val.h ---*/
#line 66 "./asn1/s1ap/packet-s1ap-template.c"

/* Initialize the protocol and registered fields */
static int proto_s1ap = -1;

static int hf_s1ap_transportLayerAddressIPv4 = -1;
static int hf_s1ap_transportLayerAddressIPv6 = -1;
static int hf_s1ap_E_UTRAN_Trace_ID_TraceID = -1;
static int hf_s1ap_E_UTRAN_Trace_ID_TraceRecordingSessionReference = -1;
static int hf_s1ap_interfacesToTrace_S1_MME = -1;
static int hf_s1ap_interfacesToTrace_X2 = -1;
static int hf_s1ap_interfacesToTrace_Uu = -1;
static int hf_s1ap_interfacesToTrace_F1_C = -1;
static int hf_s1ap_interfacesToTrace_E1 = -1;
static int hf_s1ap_interfacesToTrace_Reserved = -1;
static int hf_s1ap_encryptionAlgorithms_EEA1 = -1;
static int hf_s1ap_encryptionAlgorithms_EEA2 = -1;
static int hf_s1ap_encryptionAlgorithms_EEA3 = -1;
static int hf_s1ap_encryptionAlgorithms_Reserved = -1;
static int hf_s1ap_integrityProtectionAlgorithms_EIA1 = -1;
static int hf_s1ap_integrityProtectionAlgorithms_EIA2 = -1;
static int hf_s1ap_integrityProtectionAlgorithms_EIA3 = -1;
static int hf_s1ap_integrityProtectionAlgorithms_Reserved = -1;
static int hf_s1ap_SerialNumber_gs = -1;
static int hf_s1ap_SerialNumber_msg_code = -1;
static int hf_s1ap_SerialNumber_upd_nb = -1;
static int hf_s1ap_WarningType_value = -1;
static int hf_s1ap_WarningType_emergency_user_alert = -1;
static int hf_s1ap_WarningType_popup = -1;
static int hf_s1ap_WarningMessageContents_nb_pages = -1;
static int hf_s1ap_WarningMessageContents_decoded_page = -1;
static int hf_s1ap_measurementsToActivate_M1 = -1;
static int hf_s1ap_measurementsToActivate_M2 = -1;
static int hf_s1ap_measurementsToActivate_M3 = -1;
static int hf_s1ap_measurementsToActivate_M4 = -1;
static int hf_s1ap_measurementsToActivate_M5 = -1;
static int hf_s1ap_measurementsToActivate_LoggingM1FromEventTriggered = -1;
static int hf_s1ap_measurementsToActivate_M6 = -1;
static int hf_s1ap_measurementsToActivate_M7 = -1;
static int hf_s1ap_MDT_Location_Info_GNSS = -1;
static int hf_s1ap_MDT_Location_Info_E_CID = -1;
static int hf_s1ap_MDT_Location_Info_Reserved = -1;
static int hf_s1ap_NRencryptionAlgorithms_NEA1 = -1;
static int hf_s1ap_NRencryptionAlgorithms_NEA2 = -1;
static int hf_s1ap_NRencryptionAlgorithms_NEA3 = -1;
static int hf_s1ap_NRencryptionAlgorithms_Reserved = -1;
static int hf_s1ap_NRintegrityProtectionAlgorithms_NIA1 = -1;
static int hf_s1ap_NRintegrityProtectionAlgorithms_NIA2 = -1;
static int hf_s1ap_NRintegrityProtectionAlgorithms_NIA3 = -1;
static int hf_s1ap_NRintegrityProtectionAlgorithms_Reserved = -1;
static int hf_s1ap_UE_Application_Layer_Measurement_Capability_QoE_Measurement_for_streaming_service = -1;
static int hf_s1ap_UE_Application_Layer_Measurement_Capability_QoE_Measurement_for_MTSI_service = -1;
static int hf_s1ap_UE_Application_Layer_Measurement_Capability_Reserved = -1;

/*--- Included file: packet-s1ap-hf.c ---*/
#line 1 "./asn1/s1ap/packet-s1ap-hf.c"
static int hf_s1ap_AddModGroupCallConfigurationItem_PDU = -1;  /* AddModGroupCallConfigurationItem */
static int hf_s1ap_AMROverPDCPIndicator_PDU = -1;  /* AMROverPDCPIndicator */
static int hf_s1ap_AMROverPDCPCapablityIndicator_PDU = -1;  /* AMROverPDCPCapablityIndicator */
static int hf_s1ap_Bearers_SubjectToStatusTransfer_Item_PDU = -1;  /* Bearers_SubjectToStatusTransfer_Item */
static int hf_s1ap_BroadcastCancelledAreaList_PDU = -1;  /* BroadcastCancelledAreaList */
static int hf_s1ap_BroadcastCompletedAreaList_PDU = -1;  /* BroadcastCompletedAreaList */
static int hf_s1ap_Cause_PDU = -1;                /* Cause */
static int hf_s1ap_CallPriority_PDU = -1;         /* CallPriority */
static int hf_s1ap_CallSequence_PDU = -1;         /* CallSequence */
static int hf_s1ap_CellAccessMode_PDU = -1;       /* CellAccessMode */
static int hf_s1ap_Cdma2000PDU_PDU = -1;          /* Cdma2000PDU */
static int hf_s1ap_Cdma2000RATType_PDU = -1;      /* Cdma2000RATType */
static int hf_s1ap_Cdma2000SectorID_PDU = -1;     /* Cdma2000SectorID */
static int hf_s1ap_Cdma2000HOStatus_PDU = -1;     /* Cdma2000HOStatus */
static int hf_s1ap_Cdma2000HORequiredIndication_PDU = -1;  /* Cdma2000HORequiredIndication */
static int hf_s1ap_Cdma2000OneXSRVCCInfo_PDU = -1;  /* Cdma2000OneXSRVCCInfo */
static int hf_s1ap_Cdma2000OneXRAND_PDU = -1;     /* Cdma2000OneXRAND */
static int hf_s1ap_CNDomain_PDU = -1;             /* CNDomain */
static int hf_s1ap_ConcurrentWarningMessageIndicator_PDU = -1;  /* ConcurrentWarningMessageIndicator */
static int hf_s1ap_CSFallbackIndicator_PDU = -1;  /* CSFallbackIndicator */
static int hf_s1ap_CSG_Id_PDU = -1;               /* CSG_Id */
static int hf_s1ap_CSG_IdList_PDU = -1;           /* CSG_IdList */
static int hf_s1ap_CSGMembershipStatus_PDU = -1;  /* CSGMembershipStatus */
static int hf_s1ap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_s1ap_DataCodingScheme_PDU = -1;     /* DataCodingScheme */
static int hf_s1ap_Direct_Forwarding_Path_Availability_PDU = -1;  /* Direct_Forwarding_Path_Availability */
static int hf_s1ap_Data_Forwarding_Not_Possible_PDU = -1;  /* Data_Forwarding_Not_Possible */
static int hf_s1ap_s1ap_Global_ENB_ID_PDU = -1;   /* Global_ENB_ID */
static int hf_s1ap_s1ap_ENB_StatusTransfer_TransparentContainer_PDU = -1;  /* ENB_StatusTransfer_TransparentContainer */
static int hf_s1ap_ENB_UE_S1AP_ID_PDU = -1;       /* ENB_UE_S1AP_ID */
static int hf_s1ap_ENBname_PDU = -1;              /* ENBname */
static int hf_s1ap_E_RABInformationListItem_PDU = -1;  /* E_RABInformationListItem */
static int hf_s1ap_E_RABList_PDU = -1;            /* E_RABList */
static int hf_s1ap_E_RABItem_PDU = -1;            /* E_RABItem */
static int hf_s1ap_s1ap_EUTRAN_CGI_PDU = -1;      /* EUTRAN_CGI */
static int hf_s1ap_EUTRANRoundTripDelayEstimationInfo_PDU = -1;  /* EUTRANRoundTripDelayEstimationInfo */
static int hf_s1ap_ExtendedRepetitionPeriod_PDU = -1;  /* ExtendedRepetitionPeriod */
static int hf_s1ap_Group_S1AP_IDs_PDU = -1;       /* Group_S1AP_IDs */
static int hf_s1ap_GroupIdentity_PDU = -1;        /* GroupIdentity */
static int hf_s1ap_TAIListItemGroupServiceArea_PDU = -1;  /* TAIListItemGroupServiceArea */
static int hf_s1ap_CellListItemGroupServiceArea_PDU = -1;  /* CellListItemGroupServiceArea */
static int hf_s1ap_GroupConfigurationContainer_PDU = -1;  /* GroupConfigurationContainer */
static int hf_s1ap_GroupConfigurationContainerItem_PDU = -1;  /* GroupConfigurationContainerItem */
static int hf_s1ap_GroupAggregateMaximumBitrate_PDU = -1;  /* GroupAggregateMaximumBitrate */
static int hf_s1ap_MME_Group_S1AP_ID_PDU = -1;    /* MME_Group_S1AP_ID */
static int hf_s1ap_ReleaseGroupCallConfigurationItem_PDU = -1;  /* ReleaseGroupCallConfigurationItem */
static int hf_s1ap_GUMMEI_PDU = -1;               /* GUMMEI */
static int hf_s1ap_s1ap_HandoverRestrictionList_PDU = -1;  /* HandoverRestrictionList */
static int hf_s1ap_HandoverType_PDU = -1;         /* HandoverType */
static int hf_s1ap_LAI_PDU = -1;                  /* LAI */
static int hf_s1ap_s1ap_LastVisitedEUTRANCellInformation_PDU = -1;  /* LastVisitedEUTRANCellInformation */
static int hf_s1ap_s1ap_LastVisitedGERANCellInformation_PDU = -1;  /* LastVisitedGERANCellInformation */
static int hf_s1ap_LPPa_PDU_PDU = -1;             /* LPPa_PDU */
static int hf_s1ap_MessageIdentifier_PDU = -1;    /* MessageIdentifier */
static int hf_s1ap_MMEname_PDU = -1;              /* MMEname */
static int hf_s1ap_MME_UE_S1AP_ID_PDU = -1;       /* MME_UE_S1AP_ID */
static int hf_s1ap_MSClassmark2_PDU = -1;         /* MSClassmark2 */
static int hf_s1ap_MSClassmark3_PDU = -1;         /* MSClassmark3 */
static int hf_s1ap_NAS_PDU_PDU = -1;              /* NAS_PDU */
static int hf_s1ap_NASSecurityParametersfromE_UTRAN_PDU = -1;  /* NASSecurityParametersfromE_UTRAN */
static int hf_s1ap_NASSecurityParameterstoE_UTRAN_PDU = -1;  /* NASSecurityParameterstoE_UTRAN */
static int hf_s1ap_NumberofBroadcastRequest_PDU = -1;  /* NumberofBroadcastRequest */
static int hf_s1ap_OverloadResponse_PDU = -1;     /* OverloadResponse */
static int hf_s1ap_PagingDRX_PDU = -1;            /* PagingDRX */
static int hf_s1ap_PS_ServiceNotAvailable_PDU = -1;  /* PS_ServiceNotAvailable */
static int hf_s1ap_NAS_PDUType_PDU = -1;          /* NAS_PDUType */
static int hf_s1ap_NeedResponse_PDU = -1;         /* NeedResponse */
static int hf_s1ap_RelativeMMECapacity_PDU = -1;  /* RelativeMMECapacity */
static int hf_s1ap_RequestType_PDU = -1;          /* RequestType */
static int hf_s1ap_RepetitionPeriod_PDU = -1;     /* RepetitionPeriod */
static int hf_s1ap_RRC_Establishment_Cause_PDU = -1;  /* RRC_Establishment_Cause */
static int hf_s1ap_Routing_ID_PDU = -1;           /* Routing_ID */
static int hf_s1ap_SecurityKey_PDU = -1;          /* SecurityKey */
static int hf_s1ap_SecurityContext_PDU = -1;      /* SecurityContext */
static int hf_s1ap_SerialNumber_PDU = -1;         /* SerialNumber */
static int hf_s1ap_SONConfigurationTransfer_PDU = -1;  /* SONConfigurationTransfer */
static int hf_s1ap_Source_ToTarget_TransparentContainer_PDU = -1;  /* Source_ToTarget_TransparentContainer */
static int hf_s1ap_SRVCCOperationPossible_PDU = -1;  /* SRVCCOperationPossible */
static int hf_s1ap_SRVCCHOIndication_PDU = -1;    /* SRVCCHOIndication */
static int hf_s1ap_s1ap_SourceeNB_ToTargeteNB_TransparentContainer_PDU = -1;  /* SourceeNB_ToTargeteNB_TransparentContainer */
static int hf_s1ap_SourceeNB_List_PDU = -1;       /* SourceeNB_List */
static int hf_s1ap_SourceeNB_Item_PDU = -1;       /* SourceeNB_Item */
static int hf_s1ap_ServedGUMMEIs_PDU = -1;        /* ServedGUMMEIs */
static int hf_s1ap_ServedPLMNs_PDU = -1;          /* ServedPLMNs */
static int hf_s1ap_SubscriberProfileIDforRFP_PDU = -1;  /* SubscriberProfileIDforRFP */
static int hf_s1ap_SupportedTAs_PDU = -1;         /* SupportedTAs */
static int hf_s1ap_S_TMSI_PDU = -1;               /* S_TMSI */
static int hf_s1ap_TAI_PDU = -1;                  /* TAI */
static int hf_s1ap_TargetID_PDU = -1;             /* TargetID */
static int hf_s1ap_TrunkingUserIndication_PDU = -1;  /* TrunkingUserIndication */
static int hf_s1ap_TE_RABItem_PDU = -1;           /* TE_RABItem */
static int hf_s1ap_TargeteNB_List_PDU = -1;       /* TargeteNB_List */
static int hf_s1ap_TargeteNB_Item_PDU = -1;       /* TargeteNB_Item */
static int hf_s1ap_s1ap_TargeteNB_ToSourceeNB_TransparentContainer_PDU = -1;  /* TargeteNB_ToSourceeNB_TransparentContainer */
static int hf_s1ap_Target_ToSource_TransparentContainer_PDU = -1;  /* Target_ToSource_TransparentContainer */
static int hf_s1ap_TimeToWait_PDU = -1;           /* TimeToWait */
static int hf_s1ap_TransportLayerAddress_PDU = -1;  /* TransportLayerAddress */
static int hf_s1ap_TraceActivation_PDU = -1;      /* TraceActivation */
static int hf_s1ap_E_UTRAN_Trace_ID_PDU = -1;     /* E_UTRAN_Trace_ID */
static int hf_s1ap_UEAggregateMaximumBitrate_PDU = -1;  /* UEAggregateMaximumBitrate */
static int hf_s1ap_UE_S1AP_IDs_PDU = -1;          /* UE_S1AP_IDs */
static int hf_s1ap_UE_associatedLogicalS1_ConnectionItem_PDU = -1;  /* UE_associatedLogicalS1_ConnectionItem */
static int hf_s1ap_UEIdentityIndexValue_PDU = -1;  /* UEIdentityIndexValue */
static int hf_s1ap_s1ap_UE_HistoryInformation_PDU = -1;  /* UE_HistoryInformation */
static int hf_s1ap_UEPagingID_PDU = -1;           /* UEPagingID */
static int hf_s1ap_UERadioCapability_PDU = -1;    /* UERadioCapability */
static int hf_s1ap_UESecurityCapabilities_PDU = -1;  /* UESecurityCapabilities */
static int hf_s1ap_WarningAreaList_PDU = -1;      /* WarningAreaList */
static int hf_s1ap_WarningType_PDU = -1;          /* WarningType */
static int hf_s1ap_WarningSecurityInfo_PDU = -1;  /* WarningSecurityInfo */
static int hf_s1ap_WarningMessageContents_PDU = -1;  /* WarningMessageContents */
static int hf_s1ap_HandoverRequired_PDU = -1;     /* HandoverRequired */
static int hf_s1ap_HandoverCommand_PDU = -1;      /* HandoverCommand */
static int hf_s1ap_E_RABSubjecttoDataForwardingList_PDU = -1;  /* E_RABSubjecttoDataForwardingList */
static int hf_s1ap_E_RABDataForwardingItem_PDU = -1;  /* E_RABDataForwardingItem */
static int hf_s1ap_HandoverPreparationFailure_PDU = -1;  /* HandoverPreparationFailure */
static int hf_s1ap_HandoverRequest_PDU = -1;      /* HandoverRequest */
static int hf_s1ap_E_RABToBeSetupListHOReq_PDU = -1;  /* E_RABToBeSetupListHOReq */
static int hf_s1ap_E_RABToBeSetupItemHOReq_PDU = -1;  /* E_RABToBeSetupItemHOReq */
static int hf_s1ap_HandoverRequestAcknowledge_PDU = -1;  /* HandoverRequestAcknowledge */
static int hf_s1ap_E_RABAdmittedList_PDU = -1;    /* E_RABAdmittedList */
static int hf_s1ap_E_RABAdmittedItem_PDU = -1;    /* E_RABAdmittedItem */
static int hf_s1ap_E_RABFailedtoSetupListHOReqAck_PDU = -1;  /* E_RABFailedtoSetupListHOReqAck */
static int hf_s1ap_E_RABFailedToSetupItemHOReqAck_PDU = -1;  /* E_RABFailedToSetupItemHOReqAck */
static int hf_s1ap_HandoverFailure_PDU = -1;      /* HandoverFailure */
static int hf_s1ap_HandoverNotify_PDU = -1;       /* HandoverNotify */
static int hf_s1ap_PathSwitchRequest_PDU = -1;    /* PathSwitchRequest */
static int hf_s1ap_E_RABToBeSwitchedDLList_PDU = -1;  /* E_RABToBeSwitchedDLList */
static int hf_s1ap_E_RABToBeSwitchedDLItem_PDU = -1;  /* E_RABToBeSwitchedDLItem */
static int hf_s1ap_PathSwitchRequestAcknowledge_PDU = -1;  /* PathSwitchRequestAcknowledge */
static int hf_s1ap_E_RABToBeSwitchedULList_PDU = -1;  /* E_RABToBeSwitchedULList */
static int hf_s1ap_E_RABToBeSwitchedULItem_PDU = -1;  /* E_RABToBeSwitchedULItem */
static int hf_s1ap_PathSwitchRequestFailure_PDU = -1;  /* PathSwitchRequestFailure */
static int hf_s1ap_HandoverCancel_PDU = -1;       /* HandoverCancel */
static int hf_s1ap_HandoverCancelAcknowledge_PDU = -1;  /* HandoverCancelAcknowledge */
static int hf_s1ap_E_RABSetupRequest_PDU = -1;    /* E_RABSetupRequest */
static int hf_s1ap_E_RABToBeSetupListBearerSUReq_PDU = -1;  /* E_RABToBeSetupListBearerSUReq */
static int hf_s1ap_E_RABToBeSetupItemBearerSUReq_PDU = -1;  /* E_RABToBeSetupItemBearerSUReq */
static int hf_s1ap_E_RABSetupResponse_PDU = -1;   /* E_RABSetupResponse */
static int hf_s1ap_E_RABSetupListBearerSURes_PDU = -1;  /* E_RABSetupListBearerSURes */
static int hf_s1ap_E_RABSetupItemBearerSURes_PDU = -1;  /* E_RABSetupItemBearerSURes */
static int hf_s1ap_E_RABModifyRequest_PDU = -1;   /* E_RABModifyRequest */
static int hf_s1ap_E_RABToBeModifiedListBearerModReq_PDU = -1;  /* E_RABToBeModifiedListBearerModReq */
static int hf_s1ap_E_RABToBeModifiedItemBearerModReq_PDU = -1;  /* E_RABToBeModifiedItemBearerModReq */
static int hf_s1ap_E_RABModifyResponse_PDU = -1;  /* E_RABModifyResponse */
static int hf_s1ap_E_RABModifyListBearerModRes_PDU = -1;  /* E_RABModifyListBearerModRes */
static int hf_s1ap_E_RABModifyItemBearerModRes_PDU = -1;  /* E_RABModifyItemBearerModRes */
static int hf_s1ap_E_RABReleaseCommand_PDU = -1;  /* E_RABReleaseCommand */
static int hf_s1ap_E_RABReleaseResponse_PDU = -1;  /* E_RABReleaseResponse */
static int hf_s1ap_E_RABReleaseListBearerRelComp_PDU = -1;  /* E_RABReleaseListBearerRelComp */
static int hf_s1ap_E_RABReleaseItemBearerRelComp_PDU = -1;  /* E_RABReleaseItemBearerRelComp */
static int hf_s1ap_E_RABReleaseIndication_PDU = -1;  /* E_RABReleaseIndication */
static int hf_s1ap_InitialContextSetupRequest_PDU = -1;  /* InitialContextSetupRequest */
static int hf_s1ap_E_RABToBeSetupListCtxtSUReq_PDU = -1;  /* E_RABToBeSetupListCtxtSUReq */
static int hf_s1ap_E_RABToBeSetupItemCtxtSUReq_PDU = -1;  /* E_RABToBeSetupItemCtxtSUReq */
static int hf_s1ap_InitialContextSetupResponse_PDU = -1;  /* InitialContextSetupResponse */
static int hf_s1ap_E_RABSetupListCtxtSURes_PDU = -1;  /* E_RABSetupListCtxtSURes */
static int hf_s1ap_E_RABSetupItemCtxtSURes_PDU = -1;  /* E_RABSetupItemCtxtSURes */
static int hf_s1ap_InitialContextSetupFailure_PDU = -1;  /* InitialContextSetupFailure */
static int hf_s1ap_Paging_PDU = -1;               /* Paging */
static int hf_s1ap_TAIList_PDU = -1;              /* TAIList */
static int hf_s1ap_TAIItem_PDU = -1;              /* TAIItem */
static int hf_s1ap_UEContextReleaseRequest_PDU = -1;  /* UEContextReleaseRequest */
static int hf_s1ap_UEContextReleaseCommand_PDU = -1;  /* UEContextReleaseCommand */
static int hf_s1ap_UEContextReleaseComplete_PDU = -1;  /* UEContextReleaseComplete */
static int hf_s1ap_UEContextModificationRequest_PDU = -1;  /* UEContextModificationRequest */
static int hf_s1ap_UEContextModificationResponse_PDU = -1;  /* UEContextModificationResponse */
static int hf_s1ap_UEContextModificationFailure_PDU = -1;  /* UEContextModificationFailure */
static int hf_s1ap_DownlinkNASTransport_PDU = -1;  /* DownlinkNASTransport */
static int hf_s1ap_InitialUEMessage_PDU = -1;     /* InitialUEMessage */
static int hf_s1ap_UplinkNASTransport_PDU = -1;   /* UplinkNASTransport */
static int hf_s1ap_NASNonDeliveryIndication_PDU = -1;  /* NASNonDeliveryIndication */
static int hf_s1ap_Reset_PDU = -1;                /* Reset */
static int hf_s1ap_ResetType_PDU = -1;            /* ResetType */
static int hf_s1ap_ResetAcknowledge_PDU = -1;     /* ResetAcknowledge */
static int hf_s1ap_UE_associatedLogicalS1_ConnectionListResAck_PDU = -1;  /* UE_associatedLogicalS1_ConnectionListResAck */
static int hf_s1ap_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_s1ap_S1SetupRequest_PDU = -1;       /* S1SetupRequest */
static int hf_s1ap_S1SetupResponse_PDU = -1;      /* S1SetupResponse */
static int hf_s1ap_S1SetupFailure_PDU = -1;       /* S1SetupFailure */
static int hf_s1ap_ENBConfigurationUpdate_PDU = -1;  /* ENBConfigurationUpdate */
static int hf_s1ap_ENBConfigurationUpdateAcknowledge_PDU = -1;  /* ENBConfigurationUpdateAcknowledge */
static int hf_s1ap_ENBConfigurationUpdateFailure_PDU = -1;  /* ENBConfigurationUpdateFailure */
static int hf_s1ap_MMEConfigurationUpdate_PDU = -1;  /* MMEConfigurationUpdate */
static int hf_s1ap_MMEConfigurationUpdateAcknowledge_PDU = -1;  /* MMEConfigurationUpdateAcknowledge */
static int hf_s1ap_MMEConfigurationUpdateFailure_PDU = -1;  /* MMEConfigurationUpdateFailure */
static int hf_s1ap_UECapabilityInfoIndication_PDU = -1;  /* UECapabilityInfoIndication */
static int hf_s1ap_ENBStatusTransfer_PDU = -1;    /* ENBStatusTransfer */
static int hf_s1ap_MMEStatusTransfer_PDU = -1;    /* MMEStatusTransfer */
static int hf_s1ap_TraceStart_PDU = -1;           /* TraceStart */
static int hf_s1ap_TraceFailureIndication_PDU = -1;  /* TraceFailureIndication */
static int hf_s1ap_DeactivateTrace_PDU = -1;      /* DeactivateTrace */
static int hf_s1ap_CellTrafficTrace_PDU = -1;     /* CellTrafficTrace */
static int hf_s1ap_LocationReportingControl_PDU = -1;  /* LocationReportingControl */
static int hf_s1ap_LocationReportingFailureIndication_PDU = -1;  /* LocationReportingFailureIndication */
static int hf_s1ap_LocationReport_PDU = -1;       /* LocationReport */
static int hf_s1ap_OverloadStart_PDU = -1;        /* OverloadStart */
static int hf_s1ap_OverloadStop_PDU = -1;         /* OverloadStop */
static int hf_s1ap_WriteReplaceWarningRequest_PDU = -1;  /* WriteReplaceWarningRequest */
static int hf_s1ap_WriteReplaceWarningResponse_PDU = -1;  /* WriteReplaceWarningResponse */
static int hf_s1ap_ENBDirectInformationTransfer_PDU = -1;  /* ENBDirectInformationTransfer */
static int hf_s1ap_Inter_SystemInformationTransferType_PDU = -1;  /* Inter_SystemInformationTransferType */
static int hf_s1ap_MMEDirectInformationTransfer_PDU = -1;  /* MMEDirectInformationTransfer */
static int hf_s1ap_ENBConfigurationTransfer_PDU = -1;  /* ENBConfigurationTransfer */
static int hf_s1ap_MMEConfigurationTransfer_PDU = -1;  /* MMEConfigurationTransfer */
static int hf_s1ap_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_s1ap_KillRequest_PDU = -1;          /* KillRequest */
static int hf_s1ap_KillResponse_PDU = -1;         /* KillResponse */
static int hf_s1ap_DownlinkUEAssociatedLPPaTransport_PDU = -1;  /* DownlinkUEAssociatedLPPaTransport */
static int hf_s1ap_UplinkUEAssociatedLPPaTransport_PDU = -1;  /* UplinkUEAssociatedLPPaTransport */
static int hf_s1ap_DownlinkNonUEAssociatedLPPaTransport_PDU = -1;  /* DownlinkNonUEAssociatedLPPaTransport */
static int hf_s1ap_UplinkNonUEAssociatedLPPaTransport_PDU = -1;  /* UplinkNonUEAssociatedLPPaTransport */
static int hf_s1ap_GroupCallContextSetupRequest_PDU = -1;  /* GroupCallContextSetupRequest */
static int hf_s1ap_TE_RABToBeSetupListGroupCtxtSUReq_PDU = -1;  /* TE_RABToBeSetupListGroupCtxtSUReq */
static int hf_s1ap_TE_RABToBeSetupItemGroupCtxtSUReq_PDU = -1;  /* TE_RABToBeSetupItemGroupCtxtSUReq */
static int hf_s1ap_GroupCallContextSetupResponse_PDU = -1;  /* GroupCallContextSetupResponse */
static int hf_s1ap_TE_RABSetupListGroupCtxtSURes_PDU = -1;  /* TE_RABSetupListGroupCtxtSURes */
static int hf_s1ap_TE_RABSetupItemGroupCtxtSURes_PDU = -1;  /* TE_RABSetupItemGroupCtxtSURes */
static int hf_s1ap_GroupCallContextSetupFailure_PDU = -1;  /* GroupCallContextSetupFailure */
static int hf_s1ap_GroupCallContextModificationRequest_PDU = -1;  /* GroupCallContextModificationRequest */
static int hf_s1ap_GroupCallContextModificationResponse_PDU = -1;  /* GroupCallContextModificationResponse */
static int hf_s1ap_GroupCallContextReleaseCommand_PDU = -1;  /* GroupCallContextReleaseCommand */
static int hf_s1ap_GroupCallContextReleaseComplete_PDU = -1;  /* GroupCallContextReleaseComplete */
static int hf_s1ap_GroupCallContextReleaseIndication_PDU = -1;  /* GroupCallContextReleaseIndication */
static int hf_s1ap_InstantGroupCallConfigNotify_PDU = -1;  /* InstantGroupCallConfigNotify */
static int hf_s1ap_TrunkingIndividualPaging_PDU = -1;  /* TrunkingIndividualPaging */
static int hf_s1ap_ListOfTargetTAIsTrunkingIndividualPaging_PDU = -1;  /* ListOfTargetTAIsTrunkingIndividualPaging */
static int hf_s1ap_ListOfTargetTAIsItemTrunkingIndividualPaging_PDU = -1;  /* ListOfTargetTAIsItemTrunkingIndividualPaging */
static int hf_s1ap_GroupDownlinkNASTransport_PDU = -1;  /* GroupDownlinkNASTransport */
static int hf_s1ap_TrunkingErrorIndication_PDU = -1;  /* TrunkingErrorIndication */
static int hf_s1ap_GroupReset_PDU = -1;           /* GroupReset */
static int hf_s1ap_GroupResetType_PDU = -1;       /* GroupResetType */
static int hf_s1ap_Group_associatedLogicalS1_ConnectionItemGroupReset_PDU = -1;  /* Group_associatedLogicalS1_ConnectionItemGroupReset */
static int hf_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck_PDU = -1;  /* Group_associatedLogicalS1_ConnectionListGroupResetAck */
static int hf_s1ap_Group_associatedLogicalS1_ConnectionItemGroupResetAck_PDU = -1;  /* Group_associatedLogicalS1_ConnectionItemGroupResetAck */
static int hf_s1ap_GroupTE_RABSetupRequest_PDU = -1;  /* GroupTE_RABSetupRequest */
static int hf_s1ap_TE_RABToBeSetupListGroupBearerSUReq_PDU = -1;  /* TE_RABToBeSetupListGroupBearerSUReq */
static int hf_s1ap_TE_RABToBeSetupItemGroupBearerSUReq_PDU = -1;  /* TE_RABToBeSetupItemGroupBearerSUReq */
static int hf_s1ap_GroupTE_RABSetupResponse_PDU = -1;  /* GroupTE_RABSetupResponse */
static int hf_s1ap_TE_RABSetupListGroupBearerSURes_PDU = -1;  /* TE_RABSetupListGroupBearerSURes */
static int hf_s1ap_TE_RABSetupItemGroupBearerSURes_PDU = -1;  /* TE_RABSetupItemGroupBearerSURes */
static int hf_s1ap_GroupTE_RABModifyRequest_PDU = -1;  /* GroupTE_RABModifyRequest */
static int hf_s1ap_TE_RABToBeModifiedListGroupBearerModReq_PDU = -1;  /* TE_RABToBeModifiedListGroupBearerModReq */
static int hf_s1ap_TE_RABToBeModifiedItemGroupBearerModReq_PDU = -1;  /* TE_RABToBeModifiedItemGroupBearerModReq */
static int hf_s1ap_GroupTE_RABModifyResponse_PDU = -1;  /* GroupTE_RABModifyResponse */
static int hf_s1ap_TE_RABModifyListGroupBearerModRes_PDU = -1;  /* TE_RABModifyListGroupBearerModRes */
static int hf_s1ap_TE_RABModifyItemGroupBearerModRes_PDU = -1;  /* TE_RABModifyItemGroupBearerModRes */
static int hf_s1ap_GroupTE_RABReleaseCommand_PDU = -1;  /* GroupTE_RABReleaseCommand */
static int hf_s1ap_GroupTE_RABReleaseResponse_PDU = -1;  /* GroupTE_RABReleaseResponse */
static int hf_s1ap_TE_RABReleaseListGroupBearerRelRes_PDU = -1;  /* TE_RABReleaseListGroupBearerRelRes */
static int hf_s1ap_TE_RABReleaseItemGroupBearerRelRes_PDU = -1;  /* TE_RABReleaseItemGroupBearerRelRes */
static int hf_s1ap_GroupTE_RABReleaseIndication_PDU = -1;  /* GroupTE_RABReleaseIndication */
static int hf_s1ap_TrunkingMessageTransport_PDU = -1;  /* TrunkingMessageTransport */
static int hf_s1ap_TrunkingServingCellUpdateIndication_PDU = -1;  /* TrunkingServingCellUpdateIndication */
static int hf_s1ap_MMEGroupCallConfigurationTransfer_PDU = -1;  /* MMEGroupCallConfigurationTransfer */
static int hf_s1ap_S1AP_PDU_PDU = -1;             /* S1AP_PDU */
static int hf_s1ap_local = -1;                    /* INTEGER_0_65535 */
static int hf_s1ap_global = -1;                   /* T_global */
static int hf_s1ap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_s1ap_id = -1;                       /* ProtocolIE_ID */
static int hf_s1ap_criticality = -1;              /* Criticality */
static int hf_s1ap_ie_field_value = -1;           /* T_ie_field_value */
static int hf_s1ap_ProtocolIE_ContainerList_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_s1ap_ext_id = -1;                   /* ProtocolExtensionID */
static int hf_s1ap_extensionValue = -1;           /* T_extensionValue */
static int hf_s1ap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_s1ap_private_id = -1;               /* PrivateIE_ID */
static int hf_s1ap_value = -1;                    /* T_value */
static int hf_s1ap_priorityLevel = -1;            /* PriorityLevel */
static int hf_s1ap_pre_emptionCapability = -1;    /* Pre_emptionCapability */
static int hf_s1ap_pre_emptionVulnerability = -1;  /* Pre_emptionVulnerability */
static int hf_s1ap_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_s1ap_AddModGroupCallConfigurationList_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_eCGI = -1;                     /* EUTRAN_CGI */
static int hf_s1ap_groupRRC_Container = -1;       /* RRC_Container */
static int hf_s1ap_Bearers_SubjectToStatusTransferList_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_e_RAB_ID = -1;                 /* E_RAB_ID */
static int hf_s1ap_uL_COUNTvalue = -1;            /* COUNTvalue */
static int hf_s1ap_dL_COUNTvalue = -1;            /* COUNTvalue */
static int hf_s1ap_receiveStatusofULPDCPSDUs = -1;  /* ReceiveStatusofULPDCPSDUs */
static int hf_s1ap_BPLMNs_item = -1;              /* PLMNidentity */
static int hf_s1ap_cellID_Cancelled = -1;         /* CellID_Cancelled */
static int hf_s1ap_tAI_Cancelled = -1;            /* TAI_Cancelled */
static int hf_s1ap_emergencyAreaID_Cancelled = -1;  /* EmergencyAreaID_Cancelled */
static int hf_s1ap_cellID_Broadcast = -1;         /* CellID_Broadcast */
static int hf_s1ap_tAI_Broadcast = -1;            /* TAI_Broadcast */
static int hf_s1ap_emergencyAreaID_Broadcast = -1;  /* EmergencyAreaID_Broadcast */
static int hf_s1ap_CancelledCellinEAI_item = -1;  /* CancelledCellinEAI_Item */
static int hf_s1ap_numberOfBroadcasts = -1;       /* NumberOfBroadcasts */
static int hf_s1ap_CancelledCellinTAI_item = -1;  /* CancelledCellinTAI_Item */
static int hf_s1ap_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_s1ap_transport = -1;                /* CauseTransport */
static int hf_s1ap_nas = -1;                      /* CauseNas */
static int hf_s1ap_protocol = -1;                 /* CauseProtocol */
static int hf_s1ap_misc = -1;                     /* CauseMisc */
static int hf_s1ap_CellID_Broadcast_item = -1;    /* CellID_Broadcast_Item */
static int hf_s1ap_CellID_Cancelled_item = -1;    /* CellID_Cancelled_Item */
static int hf_s1ap_cdma2000OneXMEID = -1;         /* Cdma2000OneXMEID */
static int hf_s1ap_cdma2000OneXMSI = -1;          /* Cdma2000OneXMSI */
static int hf_s1ap_cdma2000OneXPilot = -1;        /* Cdma2000OneXPilot */
static int hf_s1ap_cell_Size = -1;                /* Cell_Size */
static int hf_s1ap_pLMNidentity = -1;             /* PLMNidentity */
static int hf_s1ap_lAC = -1;                      /* LAC */
static int hf_s1ap_cI = -1;                       /* CI */
static int hf_s1ap_rAC = -1;                      /* RAC */
static int hf_s1ap_CSG_IdList_item = -1;          /* CSG_IdList_Item */
static int hf_s1ap_cSG_Id = -1;                   /* CSG_Id */
static int hf_s1ap_pDCP_SN = -1;                  /* PDCP_SN */
static int hf_s1ap_hFN = -1;                      /* HFN */
static int hf_s1ap_procedureCode = -1;            /* ProcedureCode */
static int hf_s1ap_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_s1ap_procedureCriticality = -1;     /* Criticality */
static int hf_s1ap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_s1ap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_Item */
static int hf_s1ap_iECriticality = -1;            /* Criticality */
static int hf_s1ap_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_s1ap_typeOfError = -1;              /* TypeOfError */
static int hf_s1ap_ECGIList_item = -1;            /* EUTRAN_CGI */
static int hf_s1ap_EmergencyAreaIDList_item = -1;  /* EmergencyAreaID */
static int hf_s1ap_EmergencyAreaID_Broadcast_item = -1;  /* EmergencyAreaID_Broadcast_Item */
static int hf_s1ap_emergencyAreaID = -1;          /* EmergencyAreaID */
static int hf_s1ap_completedCellinEAI = -1;       /* CompletedCellinEAI */
static int hf_s1ap_EmergencyAreaID_Cancelled_item = -1;  /* EmergencyAreaID_Cancelled_Item */
static int hf_s1ap_cancelledCellinEAI = -1;       /* CancelledCellinEAI */
static int hf_s1ap_CompletedCellinEAI_item = -1;  /* CompletedCellinEAI_Item */
static int hf_s1ap_macroENB_ID = -1;              /* BIT_STRING_SIZE_20 */
static int hf_s1ap_homeENB_ID = -1;               /* BIT_STRING_SIZE_28 */
static int hf_s1ap_lAI = -1;                      /* LAI */
static int hf_s1ap_eNB_ID = -1;                   /* ENB_ID */
static int hf_s1ap_bearers_SubjectToStatusTransferList = -1;  /* Bearers_SubjectToStatusTransferList */
static int hf_s1ap_ENBX2TLAs_item = -1;           /* TransportLayerAddress */
static int hf_s1ap_EPLMNs_item = -1;              /* PLMNidentity */
static int hf_s1ap_E_RABInformationList_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_dL_Forwarding = -1;            /* DL_Forwarding */
static int hf_s1ap_E_RABList_item = -1;           /* ProtocolIE_SingleContainer */
static int hf_s1ap_cause = -1;                    /* Cause */
static int hf_s1ap_qCI = -1;                      /* QCI */
static int hf_s1ap_allocationRetentionPriority = -1;  /* AllocationAndRetentionPriority */
static int hf_s1ap_gbrQosInformation = -1;        /* GBR_QosInformation */
static int hf_s1ap_cell_ID = -1;                  /* CellIdentity */
static int hf_s1ap_ForbiddenTAs_item = -1;        /* ForbiddenTAs_Item */
static int hf_s1ap_pLMN_Identity = -1;            /* PLMNidentity */
static int hf_s1ap_forbiddenTACs = -1;            /* ForbiddenTACs */
static int hf_s1ap_ForbiddenTACs_item = -1;       /* TAC */
static int hf_s1ap_ForbiddenLAs_item = -1;        /* ForbiddenLAs_Item */
static int hf_s1ap_forbiddenLACs = -1;            /* ForbiddenLACs */
static int hf_s1ap_ForbiddenLACs_item = -1;       /* LAC */
static int hf_s1ap_e_RAB_MaximumBitrateDL = -1;   /* BitRate */
static int hf_s1ap_e_RAB_MaximumBitrateUL = -1;   /* BitRate */
static int hf_s1ap_e_RAB_GuaranteedBitrateDL = -1;  /* BitRate */
static int hf_s1ap_e_RAB_GuaranteedBitrateUL = -1;  /* BitRate */
static int hf_s1ap_group_S1AP_ID_pair = -1;       /* Group_S1AP_ID_pair */
static int hf_s1ap_mME_Group_S1AP_ID = -1;        /* MME_Group_S1AP_ID */
static int hf_s1ap_eNB_Group_S1AP_ID = -1;        /* ENB_Group_S1AP_ID */
static int hf_s1ap_tAIList = -1;                  /* TAIListGroupServiceArea */
static int hf_s1ap_cellList = -1;                 /* CellListGroupServiceArea */
static int hf_s1ap_TAIListGroupServiceArea_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_tAI = -1;                      /* TAI */
static int hf_s1ap_CellListGroupServiceArea_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_groupCallcipheringAlgorithm = -1;  /* GroupCallcipheringAlgorithm */
static int hf_s1ap_groupCallintegrityProtAlgorithm = -1;  /* GroupCallintegrityProtAlgorithm */
static int hf_s1ap_groupCallSecurityKey = -1;     /* SecurityKey */
static int hf_s1ap_randGroup = -1;                /* RandGroup */
static int hf_s1ap_securityAlgorithms = -1;       /* GroupCallAlgorithms */
static int hf_s1ap_gkVersion = -1;                /* GkVersion */
static int hf_s1ap_groupConfigurationContainerList = -1;  /* GroupConfigurationContainerList */
static int hf_s1ap_GroupConfigurationContainerList_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_groupIdentity = -1;            /* GroupIdentity */
static int hf_s1ap_addModGroupCallConfigurationList = -1;  /* AddModGroupCallConfigurationList */
static int hf_s1ap_releaseGroupCallConfigurationList = -1;  /* ReleaseGroupCallConfigurationList */
static int hf_s1ap_groupaggregateMaximumBitRate = -1;  /* BitRate */
static int hf_s1ap_te_RAB_MaximumBitrate = -1;    /* BitRate */
static int hf_s1ap_te_RAB_GuaranteedBitrate = -1;  /* BitRate */
static int hf_s1ap_ReleaseGroupCallConfigurationList_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_ecgi = -1;                     /* EUTRAN_CGI */
static int hf_s1ap_mME_Group_ID = -1;             /* MME_Group_ID */
static int hf_s1ap_mME_Code = -1;                 /* MME_Code */
static int hf_s1ap_servingPLMN = -1;              /* PLMNidentity */
static int hf_s1ap_equivalentPLMNs = -1;          /* EPLMNs */
static int hf_s1ap_forbiddenTAs = -1;             /* ForbiddenTAs */
static int hf_s1ap_forbiddenLAs = -1;             /* ForbiddenLAs */
static int hf_s1ap_forbiddenInterRATs = -1;       /* ForbiddenInterRATs */
static int hf_s1ap_e_UTRAN_Cell = -1;             /* LastVisitedEUTRANCellInformation */
static int hf_s1ap_uTRAN_Cell = -1;               /* LastVisitedUTRANCellInformation */
static int hf_s1ap_gERAN_Cell = -1;               /* LastVisitedGERANCellInformation */
static int hf_s1ap_global_Cell_ID = -1;           /* EUTRAN_CGI */
static int hf_s1ap_cellType = -1;                 /* CellType */
static int hf_s1ap_time_UE_StayedInCell = -1;     /* Time_UE_StayedInCell */
static int hf_s1ap_undefined = -1;                /* NULL */
static int hf_s1ap_overloadAction = -1;           /* OverloadAction */
static int hf_s1ap_eventType = -1;                /* EventType */
static int hf_s1ap_reportArea = -1;               /* ReportArea */
static int hf_s1ap_rIMInformation = -1;           /* RIMInformation */
static int hf_s1ap_rIMRoutingAddress = -1;        /* RIMRoutingAddress */
static int hf_s1ap_gERAN_Cell_ID = -1;            /* GERAN_Cell_ID */
static int hf_s1ap_targetRNC_ID = -1;             /* TargetRNC_ID */
static int hf_s1ap_nextHopChainingCount = -1;     /* INTEGER_0_7 */
static int hf_s1ap_nextHopParameter = -1;         /* SecurityKey */
static int hf_s1ap_sONInformationRequest = -1;    /* SONInformationRequest */
static int hf_s1ap_sONInformationReply = -1;      /* SONInformationReply */
static int hf_s1ap_x2TNLConfigurationInfo = -1;   /* X2TNLConfigurationInfo */
static int hf_s1ap_targeteNB_ID = -1;             /* TargeteNB_ID */
static int hf_s1ap_sourceeNB_ID = -1;             /* SourceeNB_ID */
static int hf_s1ap_sONInformation = -1;           /* SONInformation */
static int hf_s1ap_global_ENB_ID = -1;            /* Global_ENB_ID */
static int hf_s1ap_selected_TAI = -1;             /* TAI */
static int hf_s1ap_rRC_Container = -1;            /* RRC_Container */
static int hf_s1ap_e_RABInformationList = -1;     /* E_RABInformationList */
static int hf_s1ap_targetCell_ID = -1;            /* EUTRAN_CGI */
static int hf_s1ap_subscriberProfileIDforRFP = -1;  /* SubscriberProfileIDforRFP */
static int hf_s1ap_uE_HistoryInformation = -1;    /* UE_HistoryInformation */
static int hf_s1ap_SourceeNB_List_item = -1;      /* ProtocolIE_SingleContainer */
static int hf_s1ap_needResponse = -1;             /* NeedResponse */
static int hf_s1ap_groupConfigurationContainer = -1;  /* GroupConfigurationContainer */
static int hf_s1ap_ServedGUMMEIs_item = -1;       /* ServedGUMMEIsItem */
static int hf_s1ap_servedPLMNs = -1;              /* ServedPLMNs */
static int hf_s1ap_servedGroupIDs = -1;           /* ServedGroupIDs */
static int hf_s1ap_servedMMECs = -1;              /* ServedMMECs */
static int hf_s1ap_ServedGroupIDs_item = -1;      /* MME_Group_ID */
static int hf_s1ap_ServedMMECs_item = -1;         /* MME_Code */
static int hf_s1ap_ServedPLMNs_item = -1;         /* PLMNidentity */
static int hf_s1ap_SupportedTAs_item = -1;        /* SupportedTAs_Item */
static int hf_s1ap_tAC = -1;                      /* TAC */
static int hf_s1ap_broadcastPLMNs = -1;           /* BPLMNs */
static int hf_s1ap_stratumLevel = -1;             /* StratumLevel */
static int hf_s1ap_synchronizationStatus = -1;    /* SynchronizationStatus */
static int hf_s1ap_mMEC = -1;                     /* MME_Code */
static int hf_s1ap_m_TMSI = -1;                   /* M_TMSI */
static int hf_s1ap_TAIListforWarning_item = -1;   /* TAI */
static int hf_s1ap_TAI_Broadcast_item = -1;       /* TAI_Broadcast_Item */
static int hf_s1ap_completedCellinTAI = -1;       /* CompletedCellinTAI */
static int hf_s1ap_TAI_Cancelled_item = -1;       /* TAI_Cancelled_Item */
static int hf_s1ap_cancelledCellinTAI = -1;       /* CancelledCellinTAI */
static int hf_s1ap_CompletedCellinTAI_item = -1;  /* CompletedCellinTAI_Item */
static int hf_s1ap_cGI = -1;                      /* CGI */
static int hf_s1ap_TE_RABList_item = -1;          /* ProtocolIE_SingleContainer */
static int hf_s1ap_tE_RAB_ID = -1;                /* TE_RAB_ID */
static int hf_s1ap_groupGbrQosInformation = -1;   /* Group_GBR_QosInformation */
static int hf_s1ap_TargeteNB_List_item = -1;      /* ProtocolIE_SingleContainer */
static int hf_s1ap_rNC_ID = -1;                   /* RNC_ID */
static int hf_s1ap_extendedRNC_ID = -1;           /* ExtendedRNC_ID */
static int hf_s1ap_e_UTRAN_Trace_ID = -1;         /* E_UTRAN_Trace_ID */
static int hf_s1ap_interfacesToTrace = -1;        /* InterfacesToTrace */
static int hf_s1ap_traceDepth = -1;               /* TraceDepth */
static int hf_s1ap_traceCollectionEntityIPAddress = -1;  /* TransportLayerAddress */
static int hf_s1ap_uEaggregateMaximumBitRateDL = -1;  /* BitRate */
static int hf_s1ap_uEaggregateMaximumBitRateUL = -1;  /* BitRate */
static int hf_s1ap_uE_S1AP_ID_pair = -1;          /* UE_S1AP_ID_pair */
static int hf_s1ap_mME_UE_S1AP_ID = -1;           /* MME_UE_S1AP_ID */
static int hf_s1ap_eNB_UE_S1AP_ID = -1;           /* ENB_UE_S1AP_ID */
static int hf_s1ap_UE_HistoryInformation_item = -1;  /* LastVisitedCell_Item */
static int hf_s1ap_s_TMSI = -1;                   /* S_TMSI */
static int hf_s1ap_iMSI = -1;                     /* IMSI */
static int hf_s1ap_encryptionAlgorithms = -1;     /* EncryptionAlgorithms */
static int hf_s1ap_integrityProtectionAlgorithms = -1;  /* IntegrityProtectionAlgorithms */
static int hf_s1ap_cellIDList = -1;               /* ECGIList */
static int hf_s1ap_trackingAreaListforWarning = -1;  /* TAIListforWarning */
static int hf_s1ap_emergencyAreaIDList = -1;      /* EmergencyAreaIDList */
static int hf_s1ap_eNBX2TransportLayerAddresses = -1;  /* ENBX2TLAs */
static int hf_s1ap_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_s1ap_dL_transportLayerAddress = -1;  /* TransportLayerAddress */
static int hf_s1ap_dL_gTP_TEID = -1;              /* GTP_TEID */
static int hf_s1ap_uL_TransportLayerAddress = -1;  /* TransportLayerAddress */
static int hf_s1ap_uL_GTP_TEID = -1;              /* GTP_TEID */
static int hf_s1ap_transportLayerAddress = -1;    /* TransportLayerAddress */
static int hf_s1ap_gTP_TEID = -1;                 /* GTP_TEID */
static int hf_s1ap_e_RABlevelQosParameters = -1;  /* E_RABLevelQoSParameters */
static int hf_s1ap_E_RABToBeSetupListBearerSUReq_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_e_RABlevelQoSParameters = -1;  /* E_RABLevelQoSParameters */
static int hf_s1ap_nAS_PDU = -1;                  /* NAS_PDU */
static int hf_s1ap_E_RABSetupListBearerSURes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_E_RABToBeModifiedListBearerModReq_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_e_RABLevelQoSParameters = -1;  /* E_RABLevelQoSParameters */
static int hf_s1ap_E_RABModifyListBearerModRes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_E_RABReleaseListBearerRelComp_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_E_RABToBeSetupListCtxtSUReq_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_E_RABSetupListCtxtSURes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_TAIList_item = -1;             /* ProtocolIE_SingleContainer */
static int hf_s1ap_s1_Interface = -1;             /* ResetAll */
static int hf_s1ap_partOfS1_Interface = -1;       /* UE_associatedLogicalS1_ConnectionListRes */
static int hf_s1ap_UE_associatedLogicalS1_ConnectionListRes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_UE_associatedLogicalS1_ConnectionListResAck_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_rIMTransfer = -1;              /* RIMTransfer */
static int hf_s1ap_privateIEs = -1;               /* PrivateIE_Container */
static int hf_s1ap_TE_RABToBeSetupListGroupCtxtSUReq_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_tE_RABlevelQosParameters = -1;  /* TE_RABLevelQoSParameters */
static int hf_s1ap_transportType = -1;            /* TransportTypeGroupCtxtSUReq */
static int hf_s1ap_unicast = -1;                  /* UnicastTransportTypeGroupCtxtSUReq */
static int hf_s1ap_multicast = -1;                /* MulticastTransportTypeGroupCtxtSUReq */
static int hf_s1ap_multiAddress = -1;             /* TransportLayerAddress */
static int hf_s1ap_sourceAddress = -1;            /* TransportLayerAddress */
static int hf_s1ap_TE_RABSetupListGroupCtxtSURes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_transportType_01 = -1;         /* TransportTypeGroupCtxtSURes */
static int hf_s1ap_unicast_01 = -1;               /* UnicastTransportTypeGroupCtxtSURes */
static int hf_s1ap_multicast_01 = -1;             /* NULL */
static int hf_s1ap_ListOfTargetTAIsTrunkingIndividualPaging_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_s1_TInterface = -1;            /* GroupResetAll */
static int hf_s1ap_partOfS1_TInterface = -1;      /* PartOfS1_TInterfaceGroupReset */
static int hf_s1ap_group_associatedLogicalS1_Connection = -1;  /* Group_associatedLogicalS1_ConnectionListGroupReset */
static int hf_s1ap_Group_associatedLogicalS1_ConnectionListGroupReset_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_TE_RABToBeSetupListGroupBearerSUReq_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_tE_RABlevelQoSParameters = -1;  /* TE_RABLevelQoSParameters */
static int hf_s1ap_transportType_02 = -1;         /* TransportTypeGroupBearerSUReq */
static int hf_s1ap_unicast_02 = -1;               /* UnicastTransportTypeGroupBearerSUReq */
static int hf_s1ap_multicast_02 = -1;             /* MulticastTransportTypeGroupBearerSUReq */
static int hf_s1ap_TE_RABSetupListGroupBearerSURes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_transportType_03 = -1;         /* TransportTypeGroupBearerSURes */
static int hf_s1ap_unicast_03 = -1;               /* UnicastTransportTypeGroupBearerSURes */
static int hf_s1ap_TE_RABToBeModifiedListGroupBearerModReq_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_tE_RABLevelQoSParameters = -1;  /* TE_RABLevelQoSParameters */
static int hf_s1ap_TE_RABModifyListGroupBearerModRes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_TE_RABReleaseListGroupBearerRelRes_item = -1;  /* ProtocolIE_SingleContainer */
static int hf_s1ap_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_s1ap_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_s1ap_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_s1ap_initiatingMessagevalue = -1;   /* InitiatingMessage_value */
static int hf_s1ap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_s1ap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-s1ap-hf.c ---*/
#line 119 "./asn1/s1ap/packet-s1ap-template.c"

/* Initialize the subtree pointers */
static int ett_s1ap = -1;
static int ett_s1ap_TransportLayerAddress = -1;
static int ett_s1ap_ToTargetTransparentContainer = -1;
static int ett_s1ap_ToSourceTransparentContainer = -1;
static int ett_s1ap_RRCContainer = -1;
static int ett_s1ap_UERadioCapability = -1;
static int ett_s1ap_RIMInformation = -1;
static int ett_s1ap_Cdma2000PDU = -1;
static int ett_s1ap_Cdma2000SectorID = -1;
static int ett_s1ap_UERadioPagingInformation = -1;
static int ett_s1ap_UE_HistoryInformationFromTheUE = -1;
static int ett_s1ap_CELevel = -1;
static int ett_s1ap_UE_RLF_Report_Container = -1;
static int ett_s1ap_UE_RLF_Report_Container_for_extended_bands = -1;
static int ett_s1ap_S1_Message = -1;
static int ett_s1ap_E_UTRAN_Trace_ID = -1;
static int ett_s1ap_InterfacesToTrace = -1;
static int ett_s1ap_EncryptionAlgorithms = -1;
static int ett_s1ap_IntegrityProtectionAlgorithms = -1;
static int ett_s1ap_LastVisitedNGRANCellInformation = -1;
static int ett_s1ap_LastVisitedUTRANCellInformation = -1;
static int ett_s1ap_SerialNumber = -1;
static int ett_s1ap_WarningType = -1;
static int ett_s1ap_DataCodingScheme = -1;
static int ett_s1ap_WarningMessageContents = -1;
static int ett_s1ap_MSClassmark = -1;
static int ett_s1ap_MeasurementsToActivate = -1;
static int ett_s1ap_MDT_Location_Info = -1;
static int ett_s1ap_IMSI = -1;
static int ett_s1ap_NASSecurityParameters = -1;
static int ett_s1ap_NRencryptionAlgorithms = -1;
static int ett_s1ap_NRintegrityProtectionAlgorithms = -1;
static int ett_s1ap_UE_Application_Layer_Measurement_Capability = -1;
static int ett_s1ap_sMTC = -1;
static int ett_s1ap_threshRS_Index_r15 = -1;
static int ett_s1ap_sSBToMeasure = -1;
static int ett_s1ap_sSRSSIMeasurement = -1;
static int ett_s1ap_quantityConfigNR_R15 = -1;
static int ett_s1ap_blackCellsToAddModList = -1;
static int ett_s1ap_NB_IoT_RLF_Report_Container = -1;
static int ett_s1ap_MDT_ConfigurationNR = -1;
static int ett_s1ap_IntersystemSONConfigurationTransfer = -1;

/*--- Included file: packet-s1ap-ett.c ---*/
#line 1 "./asn1/s1ap/packet-s1ap-ett.c"
static gint ett_s1ap_PrivateIE_ID = -1;
static gint ett_s1ap_ProtocolIE_Container = -1;
static gint ett_s1ap_ProtocolIE_Field = -1;
static gint ett_s1ap_ProtocolIE_ContainerList = -1;
static gint ett_s1ap_ProtocolExtensionContainer = -1;
static gint ett_s1ap_ProtocolExtensionField = -1;
static gint ett_s1ap_PrivateIE_Container = -1;
static gint ett_s1ap_PrivateIE_Field = -1;
static gint ett_s1ap_AllocationAndRetentionPriority = -1;
static gint ett_s1ap_AddModGroupCallConfigurationList = -1;
static gint ett_s1ap_AddModGroupCallConfigurationItem = -1;
static gint ett_s1ap_Bearers_SubjectToStatusTransferList = -1;
static gint ett_s1ap_Bearers_SubjectToStatusTransfer_Item = -1;
static gint ett_s1ap_BPLMNs = -1;
static gint ett_s1ap_BroadcastCancelledAreaList = -1;
static gint ett_s1ap_BroadcastCompletedAreaList = -1;
static gint ett_s1ap_CancelledCellinEAI = -1;
static gint ett_s1ap_CancelledCellinEAI_Item = -1;
static gint ett_s1ap_CancelledCellinTAI = -1;
static gint ett_s1ap_CancelledCellinTAI_Item = -1;
static gint ett_s1ap_Cause = -1;
static gint ett_s1ap_CellID_Broadcast = -1;
static gint ett_s1ap_CellID_Broadcast_Item = -1;
static gint ett_s1ap_CellID_Cancelled = -1;
static gint ett_s1ap_CellID_Cancelled_Item = -1;
static gint ett_s1ap_Cdma2000OneXSRVCCInfo = -1;
static gint ett_s1ap_CellType = -1;
static gint ett_s1ap_CGI = -1;
static gint ett_s1ap_CSG_IdList = -1;
static gint ett_s1ap_CSG_IdList_Item = -1;
static gint ett_s1ap_COUNTvalue = -1;
static gint ett_s1ap_CriticalityDiagnostics = -1;
static gint ett_s1ap_CriticalityDiagnostics_IE_List = -1;
static gint ett_s1ap_CriticalityDiagnostics_IE_Item = -1;
static gint ett_s1ap_ECGIList = -1;
static gint ett_s1ap_EmergencyAreaIDList = -1;
static gint ett_s1ap_EmergencyAreaID_Broadcast = -1;
static gint ett_s1ap_EmergencyAreaID_Broadcast_Item = -1;
static gint ett_s1ap_EmergencyAreaID_Cancelled = -1;
static gint ett_s1ap_EmergencyAreaID_Cancelled_Item = -1;
static gint ett_s1ap_CompletedCellinEAI = -1;
static gint ett_s1ap_CompletedCellinEAI_Item = -1;
static gint ett_s1ap_ENB_ID = -1;
static gint ett_s1ap_GERAN_Cell_ID = -1;
static gint ett_s1ap_Global_ENB_ID = -1;
static gint ett_s1ap_ENB_StatusTransfer_TransparentContainer = -1;
static gint ett_s1ap_ENBX2TLAs = -1;
static gint ett_s1ap_EPLMNs = -1;
static gint ett_s1ap_E_RABInformationList = -1;
static gint ett_s1ap_E_RABInformationListItem = -1;
static gint ett_s1ap_E_RABList = -1;
static gint ett_s1ap_E_RABItem = -1;
static gint ett_s1ap_E_RABLevelQoSParameters = -1;
static gint ett_s1ap_EUTRAN_CGI = -1;
static gint ett_s1ap_ForbiddenTAs = -1;
static gint ett_s1ap_ForbiddenTAs_Item = -1;
static gint ett_s1ap_ForbiddenTACs = -1;
static gint ett_s1ap_ForbiddenLAs = -1;
static gint ett_s1ap_ForbiddenLAs_Item = -1;
static gint ett_s1ap_ForbiddenLACs = -1;
static gint ett_s1ap_GBR_QosInformation = -1;
static gint ett_s1ap_Group_S1AP_IDs = -1;
static gint ett_s1ap_Group_S1AP_ID_pair = -1;
static gint ett_s1ap_GroupServiceArea = -1;
static gint ett_s1ap_TAIListGroupServiceArea = -1;
static gint ett_s1ap_TAIListItemGroupServiceArea = -1;
static gint ett_s1ap_CellListGroupServiceArea = -1;
static gint ett_s1ap_CellListItemGroupServiceArea = -1;
static gint ett_s1ap_GroupCallAlgorithms = -1;
static gint ett_s1ap_GroupSecurityInformation = -1;
static gint ett_s1ap_GroupConfigurationContainer = -1;
static gint ett_s1ap_GroupConfigurationContainerList = -1;
static gint ett_s1ap_GroupConfigurationContainerItem = -1;
static gint ett_s1ap_GroupAggregateMaximumBitrate = -1;
static gint ett_s1ap_Group_GBR_QosInformation = -1;
static gint ett_s1ap_ReleaseGroupCallConfigurationList = -1;
static gint ett_s1ap_ReleaseGroupCallConfigurationItem = -1;
static gint ett_s1ap_GUMMEI = -1;
static gint ett_s1ap_HandoverRestrictionList = -1;
static gint ett_s1ap_LAI = -1;
static gint ett_s1ap_LastVisitedCell_Item = -1;
static gint ett_s1ap_LastVisitedEUTRANCellInformation = -1;
static gint ett_s1ap_LastVisitedGERANCellInformation = -1;
static gint ett_s1ap_OverloadResponse = -1;
static gint ett_s1ap_RequestType = -1;
static gint ett_s1ap_RIMTransfer = -1;
static gint ett_s1ap_RIMRoutingAddress = -1;
static gint ett_s1ap_SecurityContext = -1;
static gint ett_s1ap_SONInformation = -1;
static gint ett_s1ap_SONInformationReply = -1;
static gint ett_s1ap_SONConfigurationTransfer = -1;
static gint ett_s1ap_SourceeNB_ID = -1;
static gint ett_s1ap_SourceeNB_ToTargeteNB_TransparentContainer = -1;
static gint ett_s1ap_SourceeNB_List = -1;
static gint ett_s1ap_SourceeNB_Item = -1;
static gint ett_s1ap_ServedGUMMEIs = -1;
static gint ett_s1ap_ServedGUMMEIsItem = -1;
static gint ett_s1ap_ServedGroupIDs = -1;
static gint ett_s1ap_ServedMMECs = -1;
static gint ett_s1ap_ServedPLMNs = -1;
static gint ett_s1ap_SupportedTAs = -1;
static gint ett_s1ap_SupportedTAs_Item = -1;
static gint ett_s1ap_TimeSynchronizationInfo = -1;
static gint ett_s1ap_S_TMSI = -1;
static gint ett_s1ap_TAIListforWarning = -1;
static gint ett_s1ap_TAI = -1;
static gint ett_s1ap_TAI_Broadcast = -1;
static gint ett_s1ap_TAI_Broadcast_Item = -1;
static gint ett_s1ap_TAI_Cancelled = -1;
static gint ett_s1ap_TAI_Cancelled_Item = -1;
static gint ett_s1ap_CompletedCellinTAI = -1;
static gint ett_s1ap_CompletedCellinTAI_Item = -1;
static gint ett_s1ap_TargetID = -1;
static gint ett_s1ap_TargeteNB_ID = -1;
static gint ett_s1ap_TE_RABList = -1;
static gint ett_s1ap_TE_RABItem = -1;
static gint ett_s1ap_TE_RABLevelQoSParameters = -1;
static gint ett_s1ap_TargeteNB_List = -1;
static gint ett_s1ap_TargeteNB_Item = -1;
static gint ett_s1ap_TargetRNC_ID = -1;
static gint ett_s1ap_TargeteNB_ToSourceeNB_TransparentContainer = -1;
static gint ett_s1ap_TraceActivation = -1;
static gint ett_s1ap_UEAggregateMaximumBitrate = -1;
static gint ett_s1ap_UE_S1AP_IDs = -1;
static gint ett_s1ap_UE_S1AP_ID_pair = -1;
static gint ett_s1ap_UE_associatedLogicalS1_ConnectionItem = -1;
static gint ett_s1ap_UE_HistoryInformation = -1;
static gint ett_s1ap_UEPagingID = -1;
static gint ett_s1ap_UESecurityCapabilities = -1;
static gint ett_s1ap_WarningAreaList = -1;
static gint ett_s1ap_X2TNLConfigurationInfo = -1;
static gint ett_s1ap_HandoverRequired = -1;
static gint ett_s1ap_HandoverCommand = -1;
static gint ett_s1ap_E_RABDataForwardingItem = -1;
static gint ett_s1ap_HandoverPreparationFailure = -1;
static gint ett_s1ap_HandoverRequest = -1;
static gint ett_s1ap_E_RABToBeSetupItemHOReq = -1;
static gint ett_s1ap_HandoverRequestAcknowledge = -1;
static gint ett_s1ap_E_RABAdmittedItem = -1;
static gint ett_s1ap_E_RABFailedToSetupItemHOReqAck = -1;
static gint ett_s1ap_HandoverFailure = -1;
static gint ett_s1ap_HandoverNotify = -1;
static gint ett_s1ap_PathSwitchRequest = -1;
static gint ett_s1ap_E_RABToBeSwitchedDLItem = -1;
static gint ett_s1ap_PathSwitchRequestAcknowledge = -1;
static gint ett_s1ap_E_RABToBeSwitchedULItem = -1;
static gint ett_s1ap_PathSwitchRequestFailure = -1;
static gint ett_s1ap_HandoverCancel = -1;
static gint ett_s1ap_HandoverCancelAcknowledge = -1;
static gint ett_s1ap_E_RABSetupRequest = -1;
static gint ett_s1ap_E_RABToBeSetupListBearerSUReq = -1;
static gint ett_s1ap_E_RABToBeSetupItemBearerSUReq = -1;
static gint ett_s1ap_E_RABSetupResponse = -1;
static gint ett_s1ap_E_RABSetupListBearerSURes = -1;
static gint ett_s1ap_E_RABSetupItemBearerSURes = -1;
static gint ett_s1ap_E_RABModifyRequest = -1;
static gint ett_s1ap_E_RABToBeModifiedListBearerModReq = -1;
static gint ett_s1ap_E_RABToBeModifiedItemBearerModReq = -1;
static gint ett_s1ap_E_RABModifyResponse = -1;
static gint ett_s1ap_E_RABModifyListBearerModRes = -1;
static gint ett_s1ap_E_RABModifyItemBearerModRes = -1;
static gint ett_s1ap_E_RABReleaseCommand = -1;
static gint ett_s1ap_E_RABReleaseResponse = -1;
static gint ett_s1ap_E_RABReleaseListBearerRelComp = -1;
static gint ett_s1ap_E_RABReleaseItemBearerRelComp = -1;
static gint ett_s1ap_E_RABReleaseIndication = -1;
static gint ett_s1ap_InitialContextSetupRequest = -1;
static gint ett_s1ap_E_RABToBeSetupListCtxtSUReq = -1;
static gint ett_s1ap_E_RABToBeSetupItemCtxtSUReq = -1;
static gint ett_s1ap_InitialContextSetupResponse = -1;
static gint ett_s1ap_E_RABSetupListCtxtSURes = -1;
static gint ett_s1ap_E_RABSetupItemCtxtSURes = -1;
static gint ett_s1ap_InitialContextSetupFailure = -1;
static gint ett_s1ap_Paging = -1;
static gint ett_s1ap_TAIList = -1;
static gint ett_s1ap_TAIItem = -1;
static gint ett_s1ap_UEContextReleaseRequest = -1;
static gint ett_s1ap_UEContextReleaseCommand = -1;
static gint ett_s1ap_UEContextReleaseComplete = -1;
static gint ett_s1ap_UEContextModificationRequest = -1;
static gint ett_s1ap_UEContextModificationResponse = -1;
static gint ett_s1ap_UEContextModificationFailure = -1;
static gint ett_s1ap_DownlinkNASTransport = -1;
static gint ett_s1ap_InitialUEMessage = -1;
static gint ett_s1ap_UplinkNASTransport = -1;
static gint ett_s1ap_NASNonDeliveryIndication = -1;
static gint ett_s1ap_Reset = -1;
static gint ett_s1ap_ResetType = -1;
static gint ett_s1ap_UE_associatedLogicalS1_ConnectionListRes = -1;
static gint ett_s1ap_ResetAcknowledge = -1;
static gint ett_s1ap_UE_associatedLogicalS1_ConnectionListResAck = -1;
static gint ett_s1ap_ErrorIndication = -1;
static gint ett_s1ap_S1SetupRequest = -1;
static gint ett_s1ap_S1SetupResponse = -1;
static gint ett_s1ap_S1SetupFailure = -1;
static gint ett_s1ap_ENBConfigurationUpdate = -1;
static gint ett_s1ap_ENBConfigurationUpdateAcknowledge = -1;
static gint ett_s1ap_ENBConfigurationUpdateFailure = -1;
static gint ett_s1ap_MMEConfigurationUpdate = -1;
static gint ett_s1ap_MMEConfigurationUpdateAcknowledge = -1;
static gint ett_s1ap_MMEConfigurationUpdateFailure = -1;
static gint ett_s1ap_DownlinkS1cdma2000tunneling = -1;
static gint ett_s1ap_UplinkS1cdma2000tunneling = -1;
static gint ett_s1ap_UECapabilityInfoIndication = -1;
static gint ett_s1ap_ENBStatusTransfer = -1;
static gint ett_s1ap_MMEStatusTransfer = -1;
static gint ett_s1ap_TraceStart = -1;
static gint ett_s1ap_TraceFailureIndication = -1;
static gint ett_s1ap_DeactivateTrace = -1;
static gint ett_s1ap_CellTrafficTrace = -1;
static gint ett_s1ap_LocationReportingControl = -1;
static gint ett_s1ap_LocationReportingFailureIndication = -1;
static gint ett_s1ap_LocationReport = -1;
static gint ett_s1ap_OverloadStart = -1;
static gint ett_s1ap_OverloadStop = -1;
static gint ett_s1ap_WriteReplaceWarningRequest = -1;
static gint ett_s1ap_WriteReplaceWarningResponse = -1;
static gint ett_s1ap_ENBDirectInformationTransfer = -1;
static gint ett_s1ap_Inter_SystemInformationTransferType = -1;
static gint ett_s1ap_MMEDirectInformationTransfer = -1;
static gint ett_s1ap_ENBConfigurationTransfer = -1;
static gint ett_s1ap_MMEConfigurationTransfer = -1;
static gint ett_s1ap_PrivateMessage = -1;
static gint ett_s1ap_KillRequest = -1;
static gint ett_s1ap_KillResponse = -1;
static gint ett_s1ap_DownlinkUEAssociatedLPPaTransport = -1;
static gint ett_s1ap_UplinkUEAssociatedLPPaTransport = -1;
static gint ett_s1ap_DownlinkNonUEAssociatedLPPaTransport = -1;
static gint ett_s1ap_UplinkNonUEAssociatedLPPaTransport = -1;
static gint ett_s1ap_GroupCallContextSetupRequest = -1;
static gint ett_s1ap_TE_RABToBeSetupListGroupCtxtSUReq = -1;
static gint ett_s1ap_TE_RABToBeSetupItemGroupCtxtSUReq = -1;
static gint ett_s1ap_TransportTypeGroupCtxtSUReq = -1;
static gint ett_s1ap_UnicastTransportTypeGroupCtxtSUReq = -1;
static gint ett_s1ap_MulticastTransportTypeGroupCtxtSUReq = -1;
static gint ett_s1ap_GroupCallContextSetupResponse = -1;
static gint ett_s1ap_TE_RABSetupListGroupCtxtSURes = -1;
static gint ett_s1ap_TE_RABSetupItemGroupCtxtSURes = -1;
static gint ett_s1ap_TransportTypeGroupCtxtSURes = -1;
static gint ett_s1ap_UnicastTransportTypeGroupCtxtSURes = -1;
static gint ett_s1ap_GroupCallContextSetupFailure = -1;
static gint ett_s1ap_GroupCallContextModificationRequest = -1;
static gint ett_s1ap_GroupCallContextModificationResponse = -1;
static gint ett_s1ap_GroupCallContextReleaseCommand = -1;
static gint ett_s1ap_GroupCallContextReleaseComplete = -1;
static gint ett_s1ap_GroupCallContextReleaseIndication = -1;
static gint ett_s1ap_InstantGroupCallConfigNotify = -1;
static gint ett_s1ap_GroupCallContextExpansionRequest = -1;
static gint ett_s1ap_GroupCallContextExpansionAccept = -1;
static gint ett_s1ap_GroupCallContextExpansionReject = -1;
static gint ett_s1ap_TrunkingIndividualPaging = -1;
static gint ett_s1ap_ListOfTargetTAIsTrunkingIndividualPaging = -1;
static gint ett_s1ap_ListOfTargetTAIsItemTrunkingIndividualPaging = -1;
static gint ett_s1ap_GroupDownlinkNASTransport = -1;
static gint ett_s1ap_TrunkingErrorIndication = -1;
static gint ett_s1ap_GroupReset = -1;
static gint ett_s1ap_GroupResetType = -1;
static gint ett_s1ap_PartOfS1_TInterfaceGroupReset = -1;
static gint ett_s1ap_Group_associatedLogicalS1_ConnectionListGroupReset = -1;
static gint ett_s1ap_Group_associatedLogicalS1_ConnectionItemGroupReset = -1;
static gint ett_s1ap_GroupResetAcknowledge = -1;
static gint ett_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck = -1;
static gint ett_s1ap_Group_associatedLogicalS1_ConnectionItemGroupResetAck = -1;
static gint ett_s1ap_GroupTE_RABSetupRequest = -1;
static gint ett_s1ap_TE_RABToBeSetupListGroupBearerSUReq = -1;
static gint ett_s1ap_TE_RABToBeSetupItemGroupBearerSUReq = -1;
static gint ett_s1ap_TransportTypeGroupBearerSUReq = -1;
static gint ett_s1ap_UnicastTransportTypeGroupBearerSUReq = -1;
static gint ett_s1ap_MulticastTransportTypeGroupBearerSUReq = -1;
static gint ett_s1ap_GroupTE_RABSetupResponse = -1;
static gint ett_s1ap_TE_RABSetupListGroupBearerSURes = -1;
static gint ett_s1ap_TE_RABSetupItemGroupBearerSURes = -1;
static gint ett_s1ap_TransportTypeGroupBearerSURes = -1;
static gint ett_s1ap_UnicastTransportTypeGroupBearerSURes = -1;
static gint ett_s1ap_GroupTE_RABModifyRequest = -1;
static gint ett_s1ap_TE_RABToBeModifiedListGroupBearerModReq = -1;
static gint ett_s1ap_TE_RABToBeModifiedItemGroupBearerModReq = -1;
static gint ett_s1ap_GroupTE_RABModifyResponse = -1;
static gint ett_s1ap_TE_RABModifyListGroupBearerModRes = -1;
static gint ett_s1ap_TE_RABModifyItemGroupBearerModRes = -1;
static gint ett_s1ap_GroupTE_RABReleaseCommand = -1;
static gint ett_s1ap_GroupTE_RABReleaseResponse = -1;
static gint ett_s1ap_TE_RABReleaseListGroupBearerRelRes = -1;
static gint ett_s1ap_TE_RABReleaseItemGroupBearerRelRes = -1;
static gint ett_s1ap_GroupTE_RABReleaseIndication = -1;
static gint ett_s1ap_TrunkingMessageTransport = -1;
static gint ett_s1ap_TrunkingServingCellUpdateIndication = -1;
static gint ett_s1ap_ENBGroupCallConfigurationTransfer = -1;
static gint ett_s1ap_MMEGroupCallConfigurationTransfer = -1;
static gint ett_s1ap_S1AP_PDU = -1;
static gint ett_s1ap_InitiatingMessage = -1;
static gint ett_s1ap_SuccessfulOutcome = -1;
static gint ett_s1ap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-s1ap-ett.c ---*/
#line 164 "./asn1/s1ap/packet-s1ap-template.c"

static expert_field ei_s1ap_number_pages_le15 = EI_INIT;

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

struct s1ap_conv_info {
  wmem_map_t *nbiot_ta;
  wmem_tree_t *nbiot_enb_ue_s1ap_id;
};

struct s1ap_supported_ta {
  guint16 tac;
  wmem_array_t *plmn;
};

struct s1ap_tai {
  guint32 plmn;
  guint16 tac;
};

struct s1ap_private_data {
  struct s1ap_conv_info *s1ap_conv;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  guint32 handover_type_value;
  guint32 message_type;
  guint8 data_coding_scheme;
  struct s1ap_supported_ta *supported_ta;
  const char *obj_id;
  struct s1ap_tai *tai;
  guint16 enb_ue_s1ap_id;
  gboolean srvcc_ho_cs_only;
  guint8 transparent_container_type;
};

enum {
  S1AP_LTE_CONTAINER_AUTOMATIC,
  S1AP_LTE_CONTAINER_LEGACY,
  S1AP_LTE_CONTAINER_NBIOT
};

static const enum_val_t s1ap_lte_container_vals[] = {
  {"automatic", "Automatic", S1AP_LTE_CONTAINER_AUTOMATIC},
  {"legacy", "Legacy LTE", S1AP_LTE_CONTAINER_LEGACY},
  {"nb-iot","NB-IoT", S1AP_LTE_CONTAINER_NBIOT},
  {NULL, NULL, -1}
};

enum {
  SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = 1,
  TARGET_TO_SOURCE_TRANSPARENT_CONTAINER
};

/* Global variables */
static guint gbl_s1apSctpPort=SCTP_PORT_S1AP;
static gboolean g_s1ap_dissect_container = TRUE;
static gint g_s1ap_dissect_lte_container_as = S1AP_LTE_CONTAINER_AUTOMATIC;

static dissector_handle_t s1ap_handle;

/* Dissector tables */
static dissector_table_t s1ap_ies_dissector_table;
static dissector_table_t s1ap_ies_p1_dissector_table;
static dissector_table_t s1ap_ies_p2_dissector_table;
static dissector_table_t s1ap_extension_dissector_table;
static dissector_table_t s1ap_proc_imsg_dissector_table;
static dissector_table_t s1ap_proc_sout_dissector_table;
static dissector_table_t s1ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
*/
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static int dissect_InitialUEMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data);
#if 0
static int dissect_SourceRNC_ToTargetRNC_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_TargetRNC_ToSourceRNC_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SourceBSS_ToTargetBSS_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_TargetBSS_ToSourceBSS_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
#endif

static void
s1ap_Threshold_RSRP_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", (gint32)v-140, v);
}

static void
s1ap_Threshold_RSRQ_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-20, v);
}

static const true_false_string s1ap_tfs_interfacesToTrace = {
  "Should be traced",
  "Should not be traced"
};

static void
s1ap_Time_UE_StayedInCell_EnhancedGranularity_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fs", ((float)v)/10);
}

const value_string s1ap_serialNumber_gs_vals[] = {
  { 0, "Display mode immediate, cell wide"},
  { 1, "Display mode normal, PLMN wide"},
  { 2, "Display mode normal, tracking area wide"},
  { 3, "Display mode normal, cell wide"},
  { 0, NULL},
};

const value_string s1ap_warningType_vals[] = {
  { 0, "Earthquake"},
  { 1, "Tsunami"},
  { 2, "Earthquake and Tsunami"},
  { 3, "Test"},
  { 4, "Other"},
  { 0, NULL},
};

void
dissect_s1ap_warningMessageContents(tvbuff_t *warning_msg_tvb, proto_tree *tree, packet_info *pinfo, guint8 dcs, int hf_nb_pages, int hf_decoded_page)
{
  guint32 offset;
  guint8 nb_of_pages, length, *str;
  proto_item *ti;
  tvbuff_t *cb_data_page_tvb, *cb_data_tvb;
  int i;

  nb_of_pages = tvb_get_guint8(warning_msg_tvb, 0);
  ti = proto_tree_add_uint(tree, hf_nb_pages, warning_msg_tvb, 0, 1, nb_of_pages);
  if (nb_of_pages > 15) {
    expert_add_info_format(pinfo, ti, &ei_s1ap_number_pages_le15,
                           "Number of pages should be <=15 (found %u)", nb_of_pages);
    nb_of_pages = 15;
  }
  for (i = 0, offset = 1; i < nb_of_pages; i++) {
    length = tvb_get_guint8(warning_msg_tvb, offset+82);
    cb_data_page_tvb = tvb_new_subset_length(warning_msg_tvb, offset, length);
    cb_data_tvb = dissect_cbs_data(dcs, cb_data_page_tvb, tree, pinfo, 0);
    if (cb_data_tvb) {
      str = tvb_get_string_enc(wmem_packet_scope(), cb_data_tvb, 0, tvb_reported_length(cb_data_tvb), ENC_UTF_8|ENC_NA);
      proto_tree_add_string_format(tree, hf_decoded_page, warning_msg_tvb, offset, 83,
                                   str, "Decoded Page %u: %s", i+1, str);
    }
    offset += 83;
  }
}

static void
s1ap_EUTRANRoundTripDelayEstimationInfo_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%uTs (%u)", 16*v, v);
}

static const true_false_string s1ap_tfs_activate_do_not_activate = {
  "Activate",
  "Do not activate"
};

static void
s1ap_Packet_LossRate_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f %% (%u)", (float)v/10, v);
}

static void
s1ap_threshold_nr_rsrp_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", (gint32)v-156, v);
}

static void
s1ap_threshold_nr_rsrq_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-43, v);
}

static void
s1ap_threshold_nr_sinr_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-23, v);
}

static struct s1ap_private_data*
s1ap_get_private_data(packet_info *pinfo)
{
  struct s1ap_private_data *s1ap_data = (struct s1ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_s1ap, 0);
  if (!s1ap_data) {
    s1ap_data = wmem_new0(pinfo->pool, struct s1ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_s1ap, 0, s1ap_data);
  }
  return s1ap_data;
}

static gboolean
s1ap_is_nbiot_ue(packet_info *pinfo)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  if (s1ap_data->s1ap_conv) {
    wmem_tree_key_t tree_key[3];
    guint32 *id;
    guint32 enb_ue_s1ap_id = s1ap_data->enb_ue_s1ap_id;

    tree_key[0].length = 1;
    tree_key[0].key = &enb_ue_s1ap_id;
    tree_key[1].length = 1;
    tree_key[1].key = &pinfo->num;
    tree_key[2].length = 0;
    tree_key[2].key = NULL;
    id = (guint32*)wmem_tree_lookup32_array_le(s1ap_data->s1ap_conv->nbiot_enb_ue_s1ap_id, tree_key);
    if (id && (*id == enb_ue_s1ap_id)) {
      return TRUE;
    }
  }
  return FALSE;
}


/*--- Included file: packet-s1ap-fn.c ---*/
#line 1 "./asn1/s1ap/packet-s1ap-fn.c"

static const value_string s1ap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_s1ap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_s1ap_T_global(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 222 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &s1ap_data->obj_id);




  return offset;
}


static const value_string s1ap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_s1ap_local          , ASN1_NO_EXTENSIONS     , dissect_s1ap_INTEGER_0_65535 },
  {   1, &hf_s1ap_global         , ASN1_NO_EXTENSIONS     , dissect_s1ap_T_global },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 218 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  s1ap_data->obj_id = NULL;


  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string s1ap_ProcedureCode_vals[] = {
  { id_HandoverPreparation, "id-HandoverPreparation" },
  { id_HandoverResourceAllocation, "id-HandoverResourceAllocation" },
  { id_HandoverNotification, "id-HandoverNotification" },
  { id_PathSwitchRequest, "id-PathSwitchRequest" },
  { id_HandoverCancel, "id-HandoverCancel" },
  { id_E_RABSetup, "id-E-RABSetup" },
  { id_E_RABModify, "id-E-RABModify" },
  { id_E_RABRelease, "id-E-RABRelease" },
  { id_E_RABReleaseIndication, "id-E-RABReleaseIndication" },
  { id_InitialContextSetup, "id-InitialContextSetup" },
  { id_Paging, "id-Paging" },
  { id_downlinkNASTransport, "id-downlinkNASTransport" },
  { id_initialUEMessage, "id-initialUEMessage" },
  { id_uplinkNASTransport, "id-uplinkNASTransport" },
  { id_Reset, "id-Reset" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_NASNonDeliveryIndication, "id-NASNonDeliveryIndication" },
  { id_S1Setup, "id-S1Setup" },
  { id_UEContextReleaseRequest, "id-UEContextReleaseRequest" },
  { id_DownlinkS1cdma2000tunneling, "id-DownlinkS1cdma2000tunneling" },
  { id_UplinkS1cdma2000tunneling, "id-UplinkS1cdma2000tunneling" },
  { id_UEContextModification, "id-UEContextModification" },
  { id_UECapabilityInfoIndication, "id-UECapabilityInfoIndication" },
  { id_UEContextRelease, "id-UEContextRelease" },
  { id_eNBStatusTransfer, "id-eNBStatusTransfer" },
  { id_MMEStatusTransfer, "id-MMEStatusTransfer" },
  { id_DeactivateTrace, "id-DeactivateTrace" },
  { id_TraceStart, "id-TraceStart" },
  { id_TraceFailureIndication, "id-TraceFailureIndication" },
  { id_ENBConfigurationUpdate, "id-ENBConfigurationUpdate" },
  { id_MMEConfigurationUpdate, "id-MMEConfigurationUpdate" },
  { id_LocationReportingControl, "id-LocationReportingControl" },
  { id_LocationReportingFailureIndication, "id-LocationReportingFailureIndication" },
  { id_LocationReport, "id-LocationReport" },
  { id_OverloadStart, "id-OverloadStart" },
  { id_OverloadStop, "id-OverloadStop" },
  { id_WriteReplaceWarning, "id-WriteReplaceWarning" },
  { id_eNBDirectInformationTransfer, "id-eNBDirectInformationTransfer" },
  { id_MMEDirectInformationTransfer, "id-MMEDirectInformationTransfer" },
  { id_PrivateMessage, "id-PrivateMessage" },
  { id_eNBConfigurationTransfer, "id-eNBConfigurationTransfer" },
  { id_MMEConfigurationTransfer, "id-MMEConfigurationTransfer" },
  { id_CellTrafficTrace, "id-CellTrafficTrace" },
  { id_Kill, "id-Kill" },
  { id_downlinkUEAssociatedLPPaTransport, "id-downlinkUEAssociatedLPPaTransport" },
  { id_uplinkUEAssociatedLPPaTransport, "id-uplinkUEAssociatedLPPaTransport" },
  { id_downlinkNonUEAssociatedLPPaTransport, "id-downlinkNonUEAssociatedLPPaTransport" },
  { id_uplinkNonUEAssociatedLPPaTransport, "id-uplinkNonUEAssociatedLPPaTransport" },
  { id_GroupCallContextSetup, "id-GroupCallContextSetup" },
  { id_GroupCallContextModification, "id-GroupCallContextModification" },
  { id_GroupCallContextRelease, "id-GroupCallContextRelease" },
  { id_GroupTE_RABSetup, "id-GroupTE-RABSetup" },
  { id_GroupTE_RABModify, "id-GroupTE-RABModify" },
  { id_GroupTE_RABRelease, "id-GroupTE-RABRelease" },
  { id_GroupTE_RABReleaseIndication, "id-GroupTE-RABReleaseIndication" },
  { id_GroupCallContextReleaseIndication, "id-GroupCallContextReleaseIndication" },
  { id_InstantGroupCallConfigNotify, "id-InstantGroupCallConfigNotify" },
  { id_GroupCallContextExpansion, "id-GroupCallContextExpansion" },
  { id_TrunkingIndividualPaging, "id-TrunkingIndividualPaging" },
  { id_GroupDownlinkNASTransport, "id-GroupDownlinkNASTransport" },
  { id_TrunkingErrorIndication, "id-TrunkingErrorIndication" },
  { id_GroupReset, "id-GroupReset" },
  { id_TrunkingMessageTransport, "id-TrunkingMessageTransport" },
  { id_TrunkingServingCellUpdateIndication, "id-TrunkingServingCellUpdateIndication" },
  { id_eNBGroupCallConfigurationTransfer, "id-eNBGroupCallConfigurationTransfer" },
  { id_MMEGroupCallConfigurationTransfer, "id-MMEGroupCallConfigurationTransfer" },
  { 0, NULL }
};

static value_string_ext s1ap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(s1ap_ProcedureCode_vals);


static int
dissect_s1ap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 136 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &s1ap_data->procedure_code, FALSE);



  return offset;
}



static int
dissect_s1ap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 130 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &s1ap_data->protocol_extension_id, FALSE);




  return offset;
}


static const value_string s1ap_ProtocolIE_ID_vals[] = {
  { id_MME_UE_S1AP_ID, "id-MME-UE-S1AP-ID" },
  { id_HandoverType, "id-HandoverType" },
  { id_Cause, "id-Cause" },
  { id_SourceID, "id-SourceID" },
  { id_TargetID, "id-TargetID" },
  { id_eNB_UE_S1AP_ID, "id-eNB-UE-S1AP-ID" },
  { id_E_RABSubjecttoDataForwardingList, "id-E-RABSubjecttoDataForwardingList" },
  { id_E_RABtoReleaseListHOCmd, "id-E-RABtoReleaseListHOCmd" },
  { id_E_RABDataForwardingItem, "id-E-RABDataForwardingItem" },
  { id_E_RABReleaseItemBearerRelComp, "id-E-RABReleaseItemBearerRelComp" },
  { id_E_RABToBeSetupListBearerSUReq, "id-E-RABToBeSetupListBearerSUReq" },
  { id_E_RABToBeSetupItemBearerSUReq, "id-E-RABToBeSetupItemBearerSUReq" },
  { id_E_RABAdmittedList, "id-E-RABAdmittedList" },
  { id_E_RABFailedToSetupListHOReqAck, "id-E-RABFailedToSetupListHOReqAck" },
  { id_E_RABAdmittedItem, "id-E-RABAdmittedItem" },
  { id_E_RABFailedtoSetupItemHOReqAck, "id-E-RABFailedtoSetupItemHOReqAck" },
  { id_E_RABToBeSwitchedDLList, "id-E-RABToBeSwitchedDLList" },
  { id_E_RABToBeSwitchedDLItem, "id-E-RABToBeSwitchedDLItem" },
  { id_E_RABToBeSetupListCtxtSUReq, "id-E-RABToBeSetupListCtxtSUReq" },
  { id_TraceActivation, "id-TraceActivation" },
  { id_NAS_PDU, "id-NAS-PDU" },
  { id_E_RABToBeSetupItemHOReq, "id-E-RABToBeSetupItemHOReq" },
  { id_E_RABSetupListBearerSURes, "id-E-RABSetupListBearerSURes" },
  { id_E_RABFailedToSetupListBearerSURes, "id-E-RABFailedToSetupListBearerSURes" },
  { id_E_RABToBeModifiedListBearerModReq, "id-E-RABToBeModifiedListBearerModReq" },
  { id_E_RABModifyListBearerModRes, "id-E-RABModifyListBearerModRes" },
  { id_E_RABFailedToModifyList, "id-E-RABFailedToModifyList" },
  { id_E_RABToBeReleasedList, "id-E-RABToBeReleasedList" },
  { id_E_RABFailedToReleaseList, "id-E-RABFailedToReleaseList" },
  { id_E_RABItem, "id-E-RABItem" },
  { id_E_RABToBeModifiedItemBearerModReq, "id-E-RABToBeModifiedItemBearerModReq" },
  { id_E_RABModifyItemBearerModRes, "id-E-RABModifyItemBearerModRes" },
  { id_E_RABReleaseItem, "id-E-RABReleaseItem" },
  { id_E_RABSetupItemBearerSURes, "id-E-RABSetupItemBearerSURes" },
  { id_SecurityContext, "id-SecurityContext" },
  { id_HandoverRestrictionList, "id-HandoverRestrictionList" },
  { id_UEPagingID, "id-UEPagingID" },
  { id_pagingDRX, "id-pagingDRX" },
  { id_TAIList, "id-TAIList" },
  { id_TAIItem, "id-TAIItem" },
  { id_E_RABFailedToSetupListCtxtSURes, "id-E-RABFailedToSetupListCtxtSURes" },
  { id_E_RABReleaseItemHOCmd, "id-E-RABReleaseItemHOCmd" },
  { id_E_RABSetupItemCtxtSURes, "id-E-RABSetupItemCtxtSURes" },
  { id_E_RABSetupListCtxtSURes, "id-E-RABSetupListCtxtSURes" },
  { id_E_RABToBeSetupItemCtxtSUReq, "id-E-RABToBeSetupItemCtxtSUReq" },
  { id_E_RABToBeSetupListHOReq, "id-E-RABToBeSetupListHOReq" },
  { id_GERANtoLTEHOInformationRes, "id-GERANtoLTEHOInformationRes" },
  { id_UTRANtoLTEHOInformationRes, "id-UTRANtoLTEHOInformationRes" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_Global_ENB_ID, "id-Global-ENB-ID" },
  { id_eNBname, "id-eNBname" },
  { id_MMEname, "id-MMEname" },
  { id_ServedPLMNs, "id-ServedPLMNs" },
  { id_SupportedTAs, "id-SupportedTAs" },
  { id_TimeToWait, "id-TimeToWait" },
  { id_uEaggregateMaximumBitrate, "id-uEaggregateMaximumBitrate" },
  { id_TAI, "id-TAI" },
  { id_E_RABReleaseListBearerRelComp, "id-E-RABReleaseListBearerRelComp" },
  { id_cdma2000PDU, "id-cdma2000PDU" },
  { id_cdma2000RATType, "id-cdma2000RATType" },
  { id_cdma2000SectorID, "id-cdma2000SectorID" },
  { id_SecurityKey, "id-SecurityKey" },
  { id_UERadioCapability, "id-UERadioCapability" },
  { id_GUMMEI_ID, "id-GUMMEI-ID" },
  { id_E_RABInformationListItem, "id-E-RABInformationListItem" },
  { id_Direct_Forwarding_Path_Availability, "id-Direct-Forwarding-Path-Availability" },
  { id_UEIdentityIndexValue, "id-UEIdentityIndexValue" },
  { id_cdma2000HOStatus, "id-cdma2000HOStatus" },
  { id_cdma2000HORequiredIndication, "id-cdma2000HORequiredIndication" },
  { id_E_UTRAN_Trace_ID, "id-E-UTRAN-Trace-ID" },
  { id_RelativeMMECapacity, "id-RelativeMMECapacity" },
  { id_SourceMME_UE_S1AP_ID, "id-SourceMME-UE-S1AP-ID" },
  { id_Bearers_SubjectToStatusTransfer_Item, "id-Bearers-SubjectToStatusTransfer-Item" },
  { id_eNB_StatusTransfer_TransparentContainer, "id-eNB-StatusTransfer-TransparentContainer" },
  { id_UE_associatedLogicalS1_ConnectionItem, "id-UE-associatedLogicalS1-ConnectionItem" },
  { id_ResetType, "id-ResetType" },
  { id_UE_associatedLogicalS1_ConnectionListResAck, "id-UE-associatedLogicalS1-ConnectionListResAck" },
  { id_E_RABToBeSwitchedULItem, "id-E-RABToBeSwitchedULItem" },
  { id_E_RABToBeSwitchedULList, "id-E-RABToBeSwitchedULList" },
  { id_S_TMSI, "id-S-TMSI" },
  { id_cdma2000OneXRAND, "id-cdma2000OneXRAND" },
  { id_RequestType, "id-RequestType" },
  { id_UE_S1AP_IDs, "id-UE-S1AP-IDs" },
  { id_EUTRAN_CGI, "id-EUTRAN-CGI" },
  { id_OverloadResponse, "id-OverloadResponse" },
  { id_cdma2000OneXSRVCCInfo, "id-cdma2000OneXSRVCCInfo" },
  { id_E_RABFailedToBeReleasedList, "id-E-RABFailedToBeReleasedList" },
  { id_Source_ToTarget_TransparentContainer, "id-Source-ToTarget-TransparentContainer" },
  { id_ServedGUMMEIs, "id-ServedGUMMEIs" },
  { id_SubscriberProfileIDforRFP, "id-SubscriberProfileIDforRFP" },
  { id_UESecurityCapabilities, "id-UESecurityCapabilities" },
  { id_CSFallbackIndicator, "id-CSFallbackIndicator" },
  { id_CNDomain, "id-CNDomain" },
  { id_E_RABReleasedList, "id-E-RABReleasedList" },
  { id_MessageIdentifier, "id-MessageIdentifier" },
  { id_SerialNumber, "id-SerialNumber" },
  { id_WarningAreaList, "id-WarningAreaList" },
  { id_RepetitionPeriod, "id-RepetitionPeriod" },
  { id_NumberofBroadcastRequest, "id-NumberofBroadcastRequest" },
  { id_WarningType, "id-WarningType" },
  { id_WarningSecurityInfo, "id-WarningSecurityInfo" },
  { id_DataCodingScheme, "id-DataCodingScheme" },
  { id_WarningMessageContents, "id-WarningMessageContents" },
  { id_BroadcastCompletedAreaList, "id-BroadcastCompletedAreaList" },
  { id_Inter_SystemInformationTransferTypeEDT, "id-Inter-SystemInformationTransferTypeEDT" },
  { id_Inter_SystemInformationTransferTypeMDT, "id-Inter-SystemInformationTransferTypeMDT" },
  { id_Target_ToSource_TransparentContainer, "id-Target-ToSource-TransparentContainer" },
  { id_SRVCCOperationPossible, "id-SRVCCOperationPossible" },
  { id_SRVCCHOIndication, "id-SRVCCHOIndication" },
  { id_NAS_DownlinkCount, "id-NAS-DownlinkCount" },
  { id_CSG_Id, "id-CSG-Id" },
  { id_CSG_IdList, "id-CSG-IdList" },
  { id_SONConfigurationTransferECT, "id-SONConfigurationTransferECT" },
  { id_SONConfigurationTransferMCT, "id-SONConfigurationTransferMCT" },
  { id_TraceCollectionEntityIPAddress, "id-TraceCollectionEntityIPAddress" },
  { id_MSClassmark2, "id-MSClassmark2" },
  { id_MSClassmark3, "id-MSClassmark3" },
  { id_RRC_Establishment_Cause, "id-RRC-Establishment-Cause" },
  { id_NASSecurityParametersfromE_UTRAN, "id-NASSecurityParametersfromE-UTRAN" },
  { id_NASSecurityParameterstoE_UTRAN, "id-NASSecurityParameterstoE-UTRAN" },
  { id_DefaultPagingDRX, "id-DefaultPagingDRX" },
  { id_Source_ToTarget_TransparentContainer_Secondary, "id-Source-ToTarget-TransparentContainer-Secondary" },
  { id_Target_ToSource_TransparentContainer_Secondary, "id-Target-ToSource-TransparentContainer-Secondary" },
  { id_EUTRANRoundTripDelayEstimationInfo, "id-EUTRANRoundTripDelayEstimationInfo" },
  { id_BroadcastCancelledAreaList, "id-BroadcastCancelledAreaList" },
  { id_ConcurrentWarningMessageIndicator, "id-ConcurrentWarningMessageIndicator" },
  { id_Data_Forwarding_Not_Possible, "id-Data-Forwarding-Not-Possible" },
  { id_ExtendedRepetitionPeriod, "id-ExtendedRepetitionPeriod" },
  { id_CellAccessMode, "id-CellAccessMode" },
  { id_CSGMembershipStatus, "id-CSGMembershipStatus" },
  { id_LPPa_PDU, "id-LPPa-PDU" },
  { id_Routing_ID, "id-Routing-ID" },
  { id_Time_Synchronization_Info, "id-Time-Synchronization-Info" },
  { id_PS_ServiceNotAvailable, "id-PS-ServiceNotAvailable" },
  { id_RegisteredLAI, "id-RegisteredLAI" },
  { id_GroupIdentity, "id-GroupIdentity" },
  { id_MME_Group_S1AP_ID, "id-MME-Group-S1AP-ID" },
  { id_CallPriority, "id-CallPriority" },
  { id_CallSequence, "id-CallSequence" },
  { id_GroupAggregateMaximumBitrate, "id-GroupAggregateMaximumBitrate" },
  { id_TE_RABToBeSetupListGroupCtxtSUReq, "id-TE-RABToBeSetupListGroupCtxtSUReq" },
  { id_TE_RABToBeSetupItemGroupCtxtSUReq, "id-TE-RABToBeSetupItemGroupCtxtSUReq" },
  { id_GroupCallAreaGroupCtxtSUReq, "id-GroupCallAreaGroupCtxtSUReq" },
  { id_GroupCallSecurityInformation, "id-GroupCallSecurityInformation" },
  { id_eNB_Group_S1AP_ID, "id-eNB-Group-S1AP-ID" },
  { id_TE_RABSetupListGroupCtxtSURes, "id-TE-RABSetupListGroupCtxtSURes" },
  { id_TE_RABSetupItemGroupCtxtSURes, "id-TE-RABSetupItemGroupCtxtSURes" },
  { id_TE_RABFailedToSetupListGroupCtxtSURes, "id-TE-RABFailedToSetupListGroupCtxtSURes" },
  { id_GroupCallAreaGroupCtxtModReq, "id-GroupCallAreaGroupCtxtModReq" },
  { id_TAIListItemGroupServiceArea, "id-TAIListItemGroupServiceArea" },
  { id_CellListItemGroupServiceArea, "id-CellListItemGroupServiceArea" },
  { id_Group_S1AP_IDs, "id-Group-S1AP-IDs" },
  { id_ListOfTargetTAIsTrunkingIndividualPaging, "id-ListOfTargetTAIsTrunkingIndividualPaging" },
  { id_ListOfTargetTAIsItemTrunkingIndividualPaging, "id-ListOfTargetTAIsItemTrunkingIndividualPaging" },
  { id_NAS_PDUType, "id-NAS-PDUType" },
  { id_GroupResetType, "id-GroupResetType" },
  { id_Group_associatedLogicalS1_ConnectionItemGroupReset, "id-Group-associatedLogicalS1-ConnectionItemGroupReset" },
  { id_Group_associatedLogicalS1_ConnectionListGroupResetAck, "id-Group-associatedLogicalS1-ConnectionListGroupResetAck" },
  { id_Group_associatedLogicalS1_ConnectionItemGroupResetAck, "id-Group-associatedLogicalS1-ConnectionItemGroupResetAck" },
  { id_TE_RABToBeSetupListGroupBearerSUReq, "id-TE-RABToBeSetupListGroupBearerSUReq" },
  { id_TE_RABToBeSetupItemGroupBearerSUReq, "id-TE-RABToBeSetupItemGroupBearerSUReq" },
  { id_MessageServiceArea, "id-MessageServiceArea" },
  { id_TE_RABSetupListGroupBearerSURes, "id-TE-RABSetupListGroupBearerSURes" },
  { id_TE_RABSetupItemGroupBearerSURes, "id-TE-RABSetupItemGroupBearerSURes" },
  { id_TE_RABFailedToSetupListGroupBearerSURes, "id-TE-RABFailedToSetupListGroupBearerSURes" },
  { id_TE_RABToBeModifiedListGroupBearerModReq, "id-TE-RABToBeModifiedListGroupBearerModReq" },
  { id_TE_RABToBeModifiedItemGroupBearerModReq, "id-TE-RABToBeModifiedItemGroupBearerModReq" },
  { id_TE_RABModifyListGroupBearerModRes, "id-TE-RABModifyListGroupBearerModRes" },
  { id_TE_RABModifyItemGroupBearerModRes, "id-TE-RABModifyItemGroupBearerModRes" },
  { id_TE_RABFailedToModifyListGroupBearerModRes, "id-TE-RABFailedToModifyListGroupBearerModRes" },
  { id_TE_RABToBeReleasedListGroupBearerRelCmd, "id-TE-RABToBeReleasedListGroupBearerRelCmd" },
  { id_TE_RABToBeReleasedItemGroupBearerRelCmd, "id-TE-RABToBeReleasedItemGroupBearerRelCmd" },
  { id_TE_RABReleaseListGroupBearerRelRes, "id-TE-RABReleaseListGroupBearerRelRes" },
  { id_TE_RABReleaseItemGroupBearerRelRes, "id-TE-RABReleaseItemGroupBearerRelRes" },
  { id_TE_RABFailedToReleaseListGroupBearerRelRes, "id-TE-RABFailedToReleaseListGroupBearerRelRes" },
  { id_TE_RABReleasedListGroupBearerRelInd, "id-TE-RABReleasedListGroupBearerRelInd" },
  { id_TrunkingUserIndication, "id-TrunkingUserIndication" },
  { id_PLMNIdentity, "id-PLMNIdentity" },
  { id_TargetE_UTRAN_CGI, "id-TargetE-UTRAN-CGI" },
  { id_TE_RABItem, "id-TE-RABItem" },
  { id_TargeteNB_List, "id-TargeteNB-List" },
  { id_TargeteNB_Item, "id-TargeteNB-Item" },
  { id_SourceeNB_List, "id-SourceeNB-List" },
  { id_NeedResponse, "id-NeedResponse" },
  { id_GroupConfigurationContainer, "id-GroupConfigurationContainer" },
  { id_GroupConfigurationContainerItem, "id-GroupConfigurationContainerItem" },
  { id_AddModGroupCallConfigurationItem, "id-AddModGroupCallConfigurationItem" },
  { id_ReleaseGroupCallConfigurationItem, "id-ReleaseGroupCallConfigurationItem" },
  { id_AMROverPDCPCapablityIndicator, "id-AMROverPDCPCapablityIndicator" },
  { id_SourceeNB_Item, "id-SourceeNB-Item" },
  { id_AMROverPDCPIndicator, "id-AMROverPDCPIndicator" },
  { 0, NULL }
};

static value_string_ext s1ap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(s1ap_ProtocolIE_ID_vals);


static int
dissect_s1ap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 112 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &s1ap_data->protocol_ie_id, FALSE);




#line 116 "./asn1/s1ap/s1ap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s",
                           val_to_str_ext(s1ap_data->protocol_ie_id, &s1ap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }

  return offset;
}


static const value_string s1ap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessfull-outcome" },
  { 0, NULL }
};


static int
dissect_s1ap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_s1ap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_ID },
  { &hf_s1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_Criticality },
  { &hf_s1ap_ie_field_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_s1ap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Field },
};

static int
dissect_s1ap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_s1ap_ProtocolIE_SingleContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s1ap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ProtocolIE_ContainerList_sequence_of[1] = {
  { &hf_s1ap_ProtocolIE_ContainerList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_ProtocolIE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 163 "./asn1/s1ap/s1ap.cnf"
  static const asn1_par_def_t ProtocolIE_ContainerList_pars[] = {
    { "lowerBound", ASN1_PAR_INTEGER },
    { "upperBound", ASN1_PAR_INTEGER },
    { NULL, (asn1_par_type)0 }
  };
  asn1_stack_frame_check(actx, "ProtocolIE-ContainerList", ProtocolIE_ContainerList_pars);

  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ProtocolIE_ContainerList, ProtocolIE_ContainerList_sequence_of,
                                                  asn1_param_get_integer(actx,"lowerBound"), asn1_param_get_integer(actx,"upperBound"), FALSE);

  return offset;
}



static int
dissect_s1ap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_s1ap_ext_id         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolExtensionID },
  { &hf_s1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_Criticality },
  { &hf_s1ap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_s1ap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolExtensionField },
};

static int
dissect_s1ap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_s1ap_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 226 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  if (s1ap_data->obj_id) {
    offset = call_per_oid_callback(s1ap_data->obj_id, tvb, actx->pinfo, tree, offset, actx, hf_index);
  } else {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  }





  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_s1ap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_PrivateIE_ID },
  { &hf_s1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_Criticality },
  { &hf_s1ap_value          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_s1ap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_PrivateIE_Field },
};

static int
dissect_s1ap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}


static const value_string s1ap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_s1ap_PriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const value_string s1ap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_s1ap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string s1ap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_s1ap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationAndRetentionPriority_sequence[] = {
  { &hf_s1ap_priorityLevel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PriorityLevel },
  { &hf_s1ap_pre_emptionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Pre_emptionCapability },
  { &hf_s1ap_pre_emptionVulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Pre_emptionVulnerability },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_AllocationAndRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_AllocationAndRetentionPriority, AllocationAndRetentionPriority_sequence);

  return offset;
}


static const per_sequence_t AddModGroupCallConfigurationList_sequence_of[1] = {
  { &hf_s1ap_AddModGroupCallConfigurationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_AddModGroupCallConfigurationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_AddModGroupCallConfigurationList, AddModGroupCallConfigurationList_sequence_of,
                                                  0, maxnoofCellsineNB, FALSE);

  return offset;
}




static int
dissect_s1ap_PLMNidentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 239 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);
  if(tvb_reported_length(tvb)==0)
    return offset;

  if (!parameter_tvb)
    return offset;
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, tree, 0, E212_NONE, FALSE);
  if (s1ap_data->supported_ta) {
    guint32 plmn = tvb_get_ntoh24(parameter_tvb, 0);
    wmem_array_append_one(s1ap_data->supported_ta->plmn, plmn);
  } else if (s1ap_data->tai) {
    s1ap_data->tai->plmn = tvb_get_ntoh24(parameter_tvb, 0);
  }


  return offset;
}



static int
dissect_s1ap_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2672 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *cell_id_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     28, 28, FALSE, NULL, 0, &cell_id_tvb, NULL);

  if (cell_id_tvb) {
    guint32 cell_id = tvb_get_bits32(cell_id_tvb, 0, 28, ENC_BIG_ENDIAN);
    actx->created_item = proto_tree_add_uint(tree, hf_index, cell_id_tvb, 0, 4, cell_id);
  }


  return offset;
}


static const per_sequence_t EUTRAN_CGI_sequence[] = {
  { &hf_s1ap_pLMNidentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
  { &hf_s1ap_cell_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_CellIdentity },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_EUTRAN_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_EUTRAN_CGI, EUTRAN_CGI_sequence);

  return offset;
}



static int
dissect_s1ap_RRC_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 520 "./asn1/s1ap/s1ap.cnf"


  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  if (g_s1ap_dissect_container) {
    struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
    subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_RRCContainer);

    switch(s1ap_data->transparent_container_type){
      case SOURCE_TO_TARGET_TRANSPARENT_CONTAINER:
        /* 9.2.1.7 Source eNB to Target eNB Transparent Container */
        if ((s1ap_is_nbiot_ue(actx->pinfo) && (g_s1ap_dissect_lte_container_as == S1AP_LTE_CONTAINER_AUTOMATIC)) ||
            (g_s1ap_dissect_lte_container_as == S1AP_LTE_CONTAINER_NBIOT)) {
          TRY {
            dissect_lte_rrc_HandoverPreparationInformation_NB_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
          }
          CATCH_BOUNDS_ERRORS {
            show_exception(parameter_tvb, actx->pinfo, subtree, EXCEPT_CODE, GET_MESSAGE);
          }
          ENDTRY;
        } else {
          TRY {
            dissect_lte_rrc_HandoverPreparationInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
          }
          CATCH_BOUNDS_ERRORS {
            show_exception(parameter_tvb, actx->pinfo, subtree, EXCEPT_CODE, GET_MESSAGE);
          }
          ENDTRY;
        }
        break;
      case TARGET_TO_SOURCE_TRANSPARENT_CONTAINER:
        /* 9.2.1.8 Target eNB to Source eNB Transparent Container */
          TRY {
            dissect_lte_rrc_HandoverCommand_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
          }
          CATCH_BOUNDS_ERRORS {
            show_exception(parameter_tvb, actx->pinfo, subtree, EXCEPT_CODE, GET_MESSAGE);
          }
          ENDTRY;
        break;
      default:
        break;
    }
  }



  return offset;
}


static const per_sequence_t AddModGroupCallConfigurationItem_sequence[] = {
  { &hf_s1ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_groupRRC_Container, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_RRC_Container },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_AddModGroupCallConfigurationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_AddModGroupCallConfigurationItem, AddModGroupCallConfigurationItem_sequence);

  return offset;
}


static const value_string s1ap_AMROverPDCPIndicator_vals[] = {
  {   0, "used" },
  { 0, NULL }
};


static int
dissect_s1ap_AMROverPDCPIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_AMROverPDCPCapablityIndicator_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_s1ap_AMROverPDCPCapablityIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Bearers_SubjectToStatusTransferList_sequence_of[1] = {
  { &hf_s1ap_Bearers_SubjectToStatusTransferList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_Bearers_SubjectToStatusTransferList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_Bearers_SubjectToStatusTransferList, Bearers_SubjectToStatusTransferList_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}



static int
dissect_s1ap_E_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}



static int
dissect_s1ap_PDCP_SN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_s1ap_HFN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, FALSE);

  return offset;
}


static const per_sequence_t COUNTvalue_sequence[] = {
  { &hf_s1ap_pDCP_SN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PDCP_SN },
  { &hf_s1ap_hFN            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_HFN },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_COUNTvalue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_COUNTvalue, COUNTvalue_sequence);

  return offset;
}



static int
dissect_s1ap_ReceiveStatusofULPDCPSDUs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4096, 4096, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Bearers_SubjectToStatusTransfer_Item_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_uL_COUNTvalue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_COUNTvalue },
  { &hf_s1ap_dL_COUNTvalue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_COUNTvalue },
  { &hf_s1ap_receiveStatusofULPDCPSDUs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ReceiveStatusofULPDCPSDUs },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_Bearers_SubjectToStatusTransfer_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_Bearers_SubjectToStatusTransfer_Item, Bearers_SubjectToStatusTransfer_Item_sequence);

  return offset;
}



static int
dissect_s1ap_BitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, G_GUINT64_CONSTANT(10000000000), NULL, FALSE);

  return offset;
}


static const per_sequence_t BPLMNs_sequence_of[1] = {
  { &hf_s1ap_BPLMNs_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
};

static int
dissect_s1ap_BPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_BPLMNs, BPLMNs_sequence_of,
                                                  1, maxnoofBPLMNs, FALSE);

  return offset;
}



static int
dissect_s1ap_NumberOfBroadcasts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CellID_Cancelled_Item_sequence[] = {
  { &hf_s1ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_NumberOfBroadcasts },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CellID_Cancelled_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CellID_Cancelled_Item, CellID_Cancelled_Item_sequence);

  return offset;
}


static const per_sequence_t CellID_Cancelled_sequence_of[1] = {
  { &hf_s1ap_CellID_Cancelled_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_CellID_Cancelled_Item },
};

static int
dissect_s1ap_CellID_Cancelled(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_CellID_Cancelled, CellID_Cancelled_sequence_of,
                                                  1, maxnoofCellID, FALSE);

  return offset;
}



static int
dissect_s1ap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1246 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
    if (s1ap_data->supported_ta) {
      s1ap_data->supported_ta->tac = tvb_get_ntohs(parameter_tvb, 0);
    } else if (s1ap_data->tai) {
      s1ap_data->tai->tac = tvb_get_ntohs(parameter_tvb, 0);
    }
  }



  return offset;
}


static const per_sequence_t TAI_sequence[] = {
  { &hf_s1ap_pLMNidentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
  { &hf_s1ap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TAC },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1373 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);

  s1ap_data->tai = wmem_new0(wmem_packet_scope(), struct s1ap_tai);
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TAI, TAI_sequence);

  if (!PINFO_FD_VISITED(actx->pinfo) && s1ap_data->s1ap_conv &&
      (s1ap_data->message_type == INITIATING_MESSAGE) &&
      (s1ap_data->procedure_code == id_initialUEMessage)) {
    guint64 key = (s1ap_data->tai->plmn << 16) | s1ap_data->tai->tac;

    if (wmem_map_lookup(s1ap_data->s1ap_conv->nbiot_ta, &key)) {
      wmem_tree_key_t tree_key[3];
      guint32 *id = wmem_new(wmem_file_scope(), guint32);

      *id = s1ap_data->enb_ue_s1ap_id;
      tree_key[0].length = 1;
      tree_key[0].key = id;
      tree_key[1].length = 1;
      tree_key[1].key = &actx->pinfo->num;
      tree_key[2].length = 0;
      tree_key[2].key = NULL;
      wmem_tree_insert32_array(s1ap_data->s1ap_conv->nbiot_enb_ue_s1ap_id, tree_key, id);
    }
  }



  return offset;
}


static const per_sequence_t CancelledCellinTAI_Item_sequence[] = {
  { &hf_s1ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_NumberOfBroadcasts },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CancelledCellinTAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CancelledCellinTAI_Item, CancelledCellinTAI_Item_sequence);

  return offset;
}


static const per_sequence_t CancelledCellinTAI_sequence_of[1] = {
  { &hf_s1ap_CancelledCellinTAI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_CancelledCellinTAI_Item },
};

static int
dissect_s1ap_CancelledCellinTAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_CancelledCellinTAI, CancelledCellinTAI_sequence_of,
                                                  1, maxnoofCellinTAI, FALSE);

  return offset;
}


static const per_sequence_t TAI_Cancelled_Item_sequence[] = {
  { &hf_s1ap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI },
  { &hf_s1ap_cancelledCellinTAI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_CancelledCellinTAI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TAI_Cancelled_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TAI_Cancelled_Item, TAI_Cancelled_Item_sequence);

  return offset;
}


static const per_sequence_t TAI_Cancelled_sequence_of[1] = {
  { &hf_s1ap_TAI_Cancelled_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI_Cancelled_Item },
};

static int
dissect_s1ap_TAI_Cancelled(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TAI_Cancelled, TAI_Cancelled_sequence_of,
                                                  1, maxnoofTAIforWarning, FALSE);

  return offset;
}



static int
dissect_s1ap_EmergencyAreaID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t CancelledCellinEAI_Item_sequence[] = {
  { &hf_s1ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_numberOfBroadcasts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_NumberOfBroadcasts },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CancelledCellinEAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CancelledCellinEAI_Item, CancelledCellinEAI_Item_sequence);

  return offset;
}


static const per_sequence_t CancelledCellinEAI_sequence_of[1] = {
  { &hf_s1ap_CancelledCellinEAI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_CancelledCellinEAI_Item },
};

static int
dissect_s1ap_CancelledCellinEAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_CancelledCellinEAI, CancelledCellinEAI_sequence_of,
                                                  1, maxnoofCellinEAI, FALSE);

  return offset;
}


static const per_sequence_t EmergencyAreaID_Cancelled_Item_sequence[] = {
  { &hf_s1ap_emergencyAreaID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EmergencyAreaID },
  { &hf_s1ap_cancelledCellinEAI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_CancelledCellinEAI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_EmergencyAreaID_Cancelled_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_EmergencyAreaID_Cancelled_Item, EmergencyAreaID_Cancelled_Item_sequence);

  return offset;
}


static const per_sequence_t EmergencyAreaID_Cancelled_sequence_of[1] = {
  { &hf_s1ap_EmergencyAreaID_Cancelled_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_EmergencyAreaID_Cancelled_Item },
};

static int
dissect_s1ap_EmergencyAreaID_Cancelled(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_EmergencyAreaID_Cancelled, EmergencyAreaID_Cancelled_sequence_of,
                                                  1, maxnoofEmergencyAreaID, FALSE);

  return offset;
}


static const value_string s1ap_BroadcastCancelledAreaList_vals[] = {
  {   0, "cellID-Cancelled" },
  {   1, "tAI-Cancelled" },
  {   2, "emergencyAreaID-Cancelled" },
  { 0, NULL }
};

static const per_choice_t BroadcastCancelledAreaList_choice[] = {
  {   0, &hf_s1ap_cellID_Cancelled, ASN1_EXTENSION_ROOT    , dissect_s1ap_CellID_Cancelled },
  {   1, &hf_s1ap_tAI_Cancelled  , ASN1_EXTENSION_ROOT    , dissect_s1ap_TAI_Cancelled },
  {   2, &hf_s1ap_emergencyAreaID_Cancelled, ASN1_EXTENSION_ROOT    , dissect_s1ap_EmergencyAreaID_Cancelled },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_BroadcastCancelledAreaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_BroadcastCancelledAreaList, BroadcastCancelledAreaList_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellID_Broadcast_Item_sequence[] = {
  { &hf_s1ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CellID_Broadcast_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CellID_Broadcast_Item, CellID_Broadcast_Item_sequence);

  return offset;
}


static const per_sequence_t CellID_Broadcast_sequence_of[1] = {
  { &hf_s1ap_CellID_Broadcast_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_CellID_Broadcast_Item },
};

static int
dissect_s1ap_CellID_Broadcast(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_CellID_Broadcast, CellID_Broadcast_sequence_of,
                                                  1, maxnoofCellID, FALSE);

  return offset;
}


static const per_sequence_t CompletedCellinTAI_Item_sequence[] = {
  { &hf_s1ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CompletedCellinTAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CompletedCellinTAI_Item, CompletedCellinTAI_Item_sequence);

  return offset;
}


static const per_sequence_t CompletedCellinTAI_sequence_of[1] = {
  { &hf_s1ap_CompletedCellinTAI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_CompletedCellinTAI_Item },
};

static int
dissect_s1ap_CompletedCellinTAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_CompletedCellinTAI, CompletedCellinTAI_sequence_of,
                                                  1, maxnoofCellinTAI, FALSE);

  return offset;
}


static const per_sequence_t TAI_Broadcast_Item_sequence[] = {
  { &hf_s1ap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI },
  { &hf_s1ap_completedCellinTAI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_CompletedCellinTAI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TAI_Broadcast_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TAI_Broadcast_Item, TAI_Broadcast_Item_sequence);

  return offset;
}


static const per_sequence_t TAI_Broadcast_sequence_of[1] = {
  { &hf_s1ap_TAI_Broadcast_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI_Broadcast_Item },
};

static int
dissect_s1ap_TAI_Broadcast(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TAI_Broadcast, TAI_Broadcast_sequence_of,
                                                  1, maxnoofTAIforWarning, FALSE);

  return offset;
}


static const per_sequence_t CompletedCellinEAI_Item_sequence[] = {
  { &hf_s1ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CompletedCellinEAI_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CompletedCellinEAI_Item, CompletedCellinEAI_Item_sequence);

  return offset;
}


static const per_sequence_t CompletedCellinEAI_sequence_of[1] = {
  { &hf_s1ap_CompletedCellinEAI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_CompletedCellinEAI_Item },
};

static int
dissect_s1ap_CompletedCellinEAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_CompletedCellinEAI, CompletedCellinEAI_sequence_of,
                                                  1, maxnoofCellinEAI, FALSE);

  return offset;
}


static const per_sequence_t EmergencyAreaID_Broadcast_Item_sequence[] = {
  { &hf_s1ap_emergencyAreaID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EmergencyAreaID },
  { &hf_s1ap_completedCellinEAI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_CompletedCellinEAI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_EmergencyAreaID_Broadcast_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_EmergencyAreaID_Broadcast_Item, EmergencyAreaID_Broadcast_Item_sequence);

  return offset;
}


static const per_sequence_t EmergencyAreaID_Broadcast_sequence_of[1] = {
  { &hf_s1ap_EmergencyAreaID_Broadcast_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_EmergencyAreaID_Broadcast_Item },
};

static int
dissect_s1ap_EmergencyAreaID_Broadcast(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_EmergencyAreaID_Broadcast, EmergencyAreaID_Broadcast_sequence_of,
                                                  1, maxnoofEmergencyAreaID, FALSE);

  return offset;
}


static const value_string s1ap_BroadcastCompletedAreaList_vals[] = {
  {   0, "cellID-Broadcast" },
  {   1, "tAI-Broadcast" },
  {   2, "emergencyAreaID-Broadcast" },
  { 0, NULL }
};

static const per_choice_t BroadcastCompletedAreaList_choice[] = {
  {   0, &hf_s1ap_cellID_Broadcast, ASN1_EXTENSION_ROOT    , dissect_s1ap_CellID_Broadcast },
  {   1, &hf_s1ap_tAI_Broadcast  , ASN1_EXTENSION_ROOT    , dissect_s1ap_TAI_Broadcast },
  {   2, &hf_s1ap_emergencyAreaID_Broadcast, ASN1_EXTENSION_ROOT    , dissect_s1ap_EmergencyAreaID_Broadcast },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_BroadcastCompletedAreaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_BroadcastCompletedAreaList, BroadcastCompletedAreaList_choice,
                                 NULL);

  return offset;
}


const value_string s1ap_CauseRadioNetwork_vals[] = {
  {   0, "unspecified" },
  {   1, "tx2relocoverall-expiry" },
  {   2, "successful-handover" },
  {   3, "release-due-to-eutran-generated-reason" },
  {   4, "handover-cancelled" },
  {   5, "partial-handover" },
  {   6, "ho-failure-in-target-EPC-eNB-or-target-system" },
  {   7, "ho-target-not-allowed" },
  {   8, "tS1relocoverall-expiry" },
  {   9, "tS1relocprep-expiry" },
  {  10, "cell-not-available" },
  {  11, "unknown-targetID" },
  {  12, "no-radio-resources-available-in-target-cell" },
  {  13, "unknown-mme-ue-s1ap-id" },
  {  14, "unknown-enb-ue-s1ap-id" },
  {  15, "unknown-pair-ue-s1ap-id" },
  {  16, "handover-desirable-for-radio-reason" },
  {  17, "time-critical-handover" },
  {  18, "resource-optimisation-handover" },
  {  19, "reduce-load-in-serving-cell" },
  {  20, "user-inactivity" },
  {  21, "radio-connection-with-ue-lost" },
  {  22, "load-balancing-tau-required" },
  {  23, "cs-fallback-triggered" },
  {  24, "ue-not-available-for-ps-service" },
  {  25, "radio-resources-not-available" },
  {  26, "failure-in-radio-interface-procedure" },
  {  27, "invalid-qos-combination" },
  {  28, "interrat-redirection" },
  {  29, "interaction-with-other-procedure" },
  {  30, "unknown-E-RAB-ID" },
  {  31, "multiple-E-RAB-ID-instances" },
  {  32, "encryption-and-or-integrity-protection-algorithms-not-supported" },
  {  33, "s1-intra-system-handover-triggered" },
  {  34, "s1-inter-system-handover-triggered" },
  {  35, "x2-handover-triggered" },
  {  36, "redirection-towards-1xRTT" },
  {  37, "not-supported-QCI-value" },
  {  38, "invalid-CSG-Id" },
  {  39, "spare30" },
  {  40, "spare29" },
  {  41, "spare28" },
  {  42, "spare27" },
  {  43, "spare26" },
  {  44, "spare25" },
  {  45, "spare24" },
  {  46, "spare23" },
  {  47, "spare22" },
  {  48, "spare21" },
  {  49, "spare20" },
  {  50, "spare19" },
  {  51, "spare18" },
  {  52, "spare17" },
  {  53, "spare16" },
  {  54, "spare15" },
  {  55, "spare14" },
  {  56, "spare13" },
  {  57, "spare12" },
  {  58, "spare11" },
  {  59, "spare10" },
  {  60, "spare9" },
  {  61, "spare8" },
  {  62, "spare7" },
  {  63, "spare6" },
  {  64, "spare5" },
  {  65, "spare4" },
  {  66, "spare3" },
  {  67, "spare2" },
  {  68, "spare1" },
  {  69, "unknown-or-already-allocated-mme-group-s1ap-id" },
  {  70, "unknown-or-already-allocated-enb-group-s1ap-id" },
  {  71, "unknown-or-inconsistent-pair-of-group-s1ap-id" },
  {  72, "unknown-TE-RAB-ID" },
  {  73, "multiple-TE-RAB-ID-instances" },
  {  74, "service-area-not-allowed" },
  { 0, NULL }
};

static value_string_ext s1ap_CauseRadioNetwork_vals_ext = VALUE_STRING_EXT_INIT(s1ap_CauseRadioNetwork_vals);


static int
dissect_s1ap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2643 "./asn1/s1ap/s1ap.cnf"
  guint32 value;
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     36, &value, TRUE, 39, NULL);

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " [RadioNetwork-cause=%s]", val_to_str_const(value, s1ap_CauseRadioNetwork_vals, "Unknown"));



  return offset;
}


const value_string s1ap_CauseTransport_vals[] = {
  {   0, "transport-resource-unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_s1ap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2648 "./asn1/s1ap/s1ap.cnf"
  guint32 value;
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, &value, TRUE, 0, NULL);

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " [Transport-cause=%s]", val_to_str_const(value, s1ap_CauseTransport_vals, "Unknown"));



  return offset;
}


const value_string s1ap_CauseNas_vals[] = {
  {   0, "normal-release" },
  {   1, "authentication-failure" },
  {   2, "detach" },
  {   3, "unspecified" },
  {   4, "csg-subscription-expiry" },
  { 0, NULL }
};


static int
dissect_s1ap_CauseNas(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2653 "./asn1/s1ap/s1ap.cnf"
  guint32 value;
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, &value, TRUE, 1, NULL);

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " [NAS-cause=%s]", val_to_str_const(value, s1ap_CauseNas_vals, "Unknown"));



  return offset;
}


const value_string s1ap_CauseProtocol_vals[] = {
  {   0, "transfer-syntax-error" },
  {   1, "abstract-syntax-error-reject" },
  {   2, "abstract-syntax-error-ignore-and-notify" },
  {   3, "message-not-compatible-with-receiver-state" },
  {   4, "semantic-error" },
  {   5, "abstract-syntax-error-falsely-constructed-message" },
  {   6, "unspecified" },
  { 0, NULL }
};


static int
dissect_s1ap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2658 "./asn1/s1ap/s1ap.cnf"
  guint32 value;
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, &value, TRUE, 0, NULL);

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " [Protocol-cause=%s]", val_to_str_const(value, s1ap_CauseProtocol_vals, "Unknown"));



  return offset;
}


const value_string s1ap_CauseMisc_vals[] = {
  {   0, "control-processing-overload" },
  {   1, "not-enough-user-plane-processing-resources" },
  {   2, "hardware-failure" },
  {   3, "om-intervention" },
  {   4, "unspecified" },
  {   5, "unknown-PLMN" },
  { 0, NULL }
};


static int
dissect_s1ap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2663 "./asn1/s1ap/s1ap.cnf"
  guint32 value;
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, &value, TRUE, 0, NULL);

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " [Misc-cause=%s]", val_to_str_const(value, s1ap_CauseMisc_vals, "Unknown"));



  return offset;
}


const value_string s1ap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "nas" },
  {   3, "protocol" },
  {   4, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_s1ap_radioNetwork   , ASN1_EXTENSION_ROOT    , dissect_s1ap_CauseRadioNetwork },
  {   1, &hf_s1ap_transport      , ASN1_EXTENSION_ROOT    , dissect_s1ap_CauseTransport },
  {   2, &hf_s1ap_nas            , ASN1_EXTENSION_ROOT    , dissect_s1ap_CauseNas },
  {   3, &hf_s1ap_protocol       , ASN1_EXTENSION_ROOT    , dissect_s1ap_CauseProtocol },
  {   4, &hf_s1ap_misc           , ASN1_EXTENSION_ROOT    , dissect_s1ap_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_Cause, Cause_choice,
                                 NULL);

  return offset;
}



static int
dissect_s1ap_CallPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_s1ap_CallSequence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string s1ap_CellAccessMode_vals[] = {
  {   0, "hybrid" },
  { 0, NULL }
};


static int
dissect_s1ap_CellAccessMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_Cdma2000PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 670 "./asn1/s1ap/s1ap.cnf"

  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

if (gcsna_handle) {
        subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_Cdma2000PDU);
        call_dissector(gcsna_handle, parameter_tvb, actx->pinfo, subtree);
}




  return offset;
}


static const value_string s1ap_Cdma2000RATType_vals[] = {
  {   0, "hRPD" },
  {   1, "onexRTT" },
  { 0, NULL }
};


static int
dissect_s1ap_Cdma2000RATType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_Cdma2000SectorID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 685 "./asn1/s1ap/s1ap.cnf"
/* 9.2.1.25
 * This IE is set to CDMA2000 Reference Cell ID
 * corresponding to the HRPD/1xRTT sector under
 * the HRPD AN/1xBS to which the eNB has initiated the UE
 * to handover to. The CDMA2000 Reference Cell
 * ID is statically configured in the eNB.
 */
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_Cdma2000SectorID);
  dissect_a21_ie_common(parameter_tvb, actx->pinfo, NULL/* Top tree not needed */, subtree, 0,  0 /* message_type not needed */);



  return offset;
}


static const value_string s1ap_Cdma2000HOStatus_vals[] = {
  {   0, "hOSuccess" },
  {   1, "hOFailure" },
  { 0, NULL }
};


static int
dissect_s1ap_Cdma2000HOStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_Cdma2000HORequiredIndication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_s1ap_Cdma2000HORequiredIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_Cdma2000OneXMEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_s1ap_Cdma2000OneXMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_s1ap_Cdma2000OneXPilot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t Cdma2000OneXSRVCCInfo_sequence[] = {
  { &hf_s1ap_cdma2000OneXMEID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Cdma2000OneXMEID },
  { &hf_s1ap_cdma2000OneXMSI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Cdma2000OneXMSI },
  { &hf_s1ap_cdma2000OneXPilot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Cdma2000OneXPilot },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_Cdma2000OneXSRVCCInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_Cdma2000OneXSRVCCInfo, Cdma2000OneXSRVCCInfo_sequence);

  return offset;
}



static int
dissect_s1ap_Cdma2000OneXRAND(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string s1ap_Cell_Size_vals[] = {
  {   0, "verysmall" },
  {   1, "small" },
  {   2, "medium" },
  {   3, "large" },
  { 0, NULL }
};


static int
dissect_s1ap_Cell_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CellType_sequence[] = {
  { &hf_s1ap_cell_Size      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Cell_Size },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CellType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CellType, CellType_sequence);

  return offset;
}



static int
dissect_s1ap_LAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1261 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_s1ap_CI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_s1ap_RAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1270 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       1, 1, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t CGI_sequence[] = {
  { &hf_s1ap_pLMNidentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
  { &hf_s1ap_lAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_LAC },
  { &hf_s1ap_cI             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_CI },
  { &hf_s1ap_rAC            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_RAC },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CGI, CGI_sequence);

  return offset;
}


static const value_string s1ap_CNDomain_vals[] = {
  {   0, "ps" },
  {   1, "cs" },
  { 0, NULL }
};


static int
dissect_s1ap_CNDomain(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string s1ap_ConcurrentWarningMessageIndicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_s1ap_ConcurrentWarningMessageIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string s1ap_CSFallbackIndicator_vals[] = {
  {   0, "cs-fallback-required" },
  {   1, "cs-fallback-high-priority" },
  { 0, NULL }
};


static int
dissect_s1ap_CSFallbackIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}



static int
dissect_s1ap_CSG_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     27, 27, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t CSG_IdList_Item_sequence[] = {
  { &hf_s1ap_cSG_Id         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_CSG_Id },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CSG_IdList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CSG_IdList_Item, CSG_IdList_Item_sequence);

  return offset;
}


static const per_sequence_t CSG_IdList_sequence_of[1] = {
  { &hf_s1ap_CSG_IdList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_CSG_IdList_Item },
};

static int
dissect_s1ap_CSG_IdList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_CSG_IdList, CSG_IdList_sequence_of,
                                                  1, maxNrOfCSGs, FALSE);

  return offset;
}


static const value_string s1ap_CSGMembershipStatus_vals[] = {
  {   0, "member" },
  {   1, "not-member" },
  { 0, NULL }
};


static int
dissect_s1ap_CSGMembershipStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string s1ap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_s1ap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_Item_sequence[] = {
  { &hf_s1ap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Criticality },
  { &hf_s1ap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_ID },
  { &hf_s1ap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TypeOfError },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CriticalityDiagnostics_IE_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CriticalityDiagnostics_IE_Item, CriticalityDiagnostics_IE_Item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_s1ap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_CriticalityDiagnostics_IE_Item },
};

static int
dissect_s1ap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_s1ap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProcedureCode },
  { &hf_s1ap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_TriggeringMessage },
  { &hf_s1ap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_Criticality },
  { &hf_s1ap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_CriticalityDiagnostics_IE_List },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_s1ap_DataCodingScheme(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1081 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_DataCodingScheme);
    s1ap_data->data_coding_scheme = dissect_cbs_data_coding_scheme(parameter_tvb, actx->pinfo, subtree, 0);
  }



  return offset;
}


static const value_string s1ap_DL_Forwarding_vals[] = {
  {   0, "dL-Forwarding-proposed" },
  { 0, NULL }
};


static int
dissect_s1ap_DL_Forwarding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_Direct_Forwarding_Path_Availability_vals[] = {
  {   0, "directPathAvailable" },
  { 0, NULL }
};


static int
dissect_s1ap_Direct_Forwarding_Path_Availability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_Data_Forwarding_Not_Possible_vals[] = {
  {   0, "data-Forwarding-not-Possible" },
  { 0, NULL }
};


static int
dissect_s1ap_Data_Forwarding_Not_Possible(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_ENB_Group_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ECGIList_sequence_of[1] = {
  { &hf_s1ap_ECGIList_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
};

static int
dissect_s1ap_ECGIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ECGIList, ECGIList_sequence_of,
                                                  1, maxnoofCellID, FALSE);

  return offset;
}


static const per_sequence_t EmergencyAreaIDList_sequence_of[1] = {
  { &hf_s1ap_EmergencyAreaIDList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_EmergencyAreaID },
};

static int
dissect_s1ap_EmergencyAreaIDList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_EmergencyAreaIDList, EmergencyAreaIDList_sequence_of,
                                                  1, maxnoofEmergencyAreaID, FALSE);

  return offset;
}



static int
dissect_s1ap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_s1ap_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string s1ap_ENB_ID_vals[] = {
  {   0, "macroENB-ID" },
  {   1, "homeENB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_s1ap_macroENB_ID    , ASN1_EXTENSION_ROOT    , dissect_s1ap_BIT_STRING_SIZE_20 },
  {   1, &hf_s1ap_homeENB_ID     , ASN1_EXTENSION_ROOT    , dissect_s1ap_BIT_STRING_SIZE_28 },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LAI_sequence[] = {
  { &hf_s1ap_pLMNidentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
  { &hf_s1ap_lAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_LAC },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_LAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_LAI, LAI_sequence);

  return offset;
}


static const per_sequence_t GERAN_Cell_ID_sequence[] = {
  { &hf_s1ap_lAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_LAI },
  { &hf_s1ap_rAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_RAC },
  { &hf_s1ap_cI             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_CI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GERAN_Cell_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GERAN_Cell_ID, GERAN_Cell_ID_sequence);

  return offset;
}


static const per_sequence_t Global_ENB_ID_sequence[] = {
  { &hf_s1ap_pLMNidentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
  { &hf_s1ap_eNB_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ENB_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

int
dissect_s1ap_Global_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_Global_ENB_ID, Global_ENB_ID_sequence);

  return offset;
}


static const per_sequence_t ENB_StatusTransfer_TransparentContainer_sequence[] = {
  { &hf_s1ap_bearers_SubjectToStatusTransferList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Bearers_SubjectToStatusTransferList },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ENB_StatusTransfer_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ENB_StatusTransfer_TransparentContainer, ENB_StatusTransfer_TransparentContainer_sequence);

  return offset;
}



static int
dissect_s1ap_ENB_UE_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1352 "./asn1/s1ap/s1ap.cnf"
  guint32 enb_ue_s1ap_id;
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, &enb_ue_s1ap_id, FALSE);

  if (hf_index == hf_s1ap_eNB_UE_S1AP_ID) {
    proto_item *item;
    item = proto_tree_add_uint(tree, hf_s1ap_ENB_UE_S1AP_ID_PDU, tvb, offset, 0 , enb_ue_s1ap_id );
    proto_item_set_hidden(item);
  }

  s1ap_data->enb_ue_s1ap_id = (guint16)enb_ue_s1ap_id;



  return offset;
}



static int
dissect_s1ap_ENBname(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 259 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  int length;
  gboolean is_ascii;

  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);


  if (!parameter_tvb)
    return offset;

  length = tvb_reported_length(parameter_tvb);

  is_ascii = tvb_ascii_isprint(parameter_tvb, 0, length);
  if (is_ascii)
     proto_item_append_text(actx->created_item," (%s)",tvb_format_text(parameter_tvb, 0, length));



  return offset;
}



static int
dissect_s1ap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 312 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  proto_tree *subtree;
  gint tvb_len;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, TRUE, NULL, 0, &parameter_tvb, NULL);

  if (!parameter_tvb)
    return offset;

  /* Get the length */
  tvb_len = tvb_reported_length(parameter_tvb);
  subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_TransportLayerAddress);
  if (tvb_len==4) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_s1ap_transportLayerAddressIPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
  } else if (tvb_len==16) {
    /* IPv6 */
     proto_tree_add_item(subtree, hf_s1ap_transportLayerAddressIPv6, parameter_tvb, 0, 16, ENC_NA);
  } else if (tvb_len==20) {
    /* IPv4 */
     proto_tree_add_item(subtree, hf_s1ap_transportLayerAddressIPv4, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
    /* IPv6 */
     proto_tree_add_item(subtree, hf_s1ap_transportLayerAddressIPv6, parameter_tvb, 4, 16, ENC_NA);
  }



  return offset;
}


static const per_sequence_t ENBX2TLAs_sequence_of[1] = {
  { &hf_s1ap_ENBX2TLAs_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
};

static int
dissect_s1ap_ENBX2TLAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ENBX2TLAs, ENBX2TLAs_sequence_of,
                                                  1, maxnoofeNBX2TLAs, FALSE);

  return offset;
}



static int
dissect_s1ap_EncryptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 966 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, NULL, 0, &parameter_tvb, NULL);

  if(parameter_tvb){
    static int * const fields[] = {
      &hf_s1ap_encryptionAlgorithms_EEA1,
      &hf_s1ap_encryptionAlgorithms_EEA2,
      &hf_s1ap_encryptionAlgorithms_EEA3,
      &hf_s1ap_encryptionAlgorithms_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_EncryptionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t EPLMNs_sequence_of[1] = {
  { &hf_s1ap_EPLMNs_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
};

static int
dissect_s1ap_EPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_EPLMNs, EPLMNs_sequence_of,
                                                  1, maxnoofEPLMNs, FALSE);

  return offset;
}


static const value_string s1ap_EventType_vals[] = {
  {   0, "direct" },
  {   1, "change-of-serve-cell" },
  {   2, "stop-change-of-serve-cell" },
  { 0, NULL }
};


static int
dissect_s1ap_EventType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t E_RABInformationList_sequence_of[1] = {
  { &hf_s1ap_E_RABInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_E_RABInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_E_RABInformationList, E_RABInformationList_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t E_RABInformationListItem_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_dL_Forwarding  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_DL_Forwarding },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABInformationListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABInformationListItem, E_RABInformationListItem_sequence);

  return offset;
}


static const per_sequence_t E_RABList_sequence_of[1] = {
  { &hf_s1ap_E_RABList_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_E_RABList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_E_RABList, E_RABList_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t E_RABItem_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Cause },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABItem, E_RABItem_sequence);

  return offset;
}



static int
dissect_s1ap_QCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GBR_QosInformation_sequence[] = {
  { &hf_s1ap_e_RAB_MaximumBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BitRate },
  { &hf_s1ap_e_RAB_MaximumBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BitRate },
  { &hf_s1ap_e_RAB_GuaranteedBitrateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BitRate },
  { &hf_s1ap_e_RAB_GuaranteedBitrateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BitRate },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GBR_QosInformation, GBR_QosInformation_sequence);

  return offset;
}


static const per_sequence_t E_RABLevelQoSParameters_sequence[] = {
  { &hf_s1ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_QCI },
  { &hf_s1ap_allocationRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_AllocationAndRetentionPriority },
  { &hf_s1ap_gbrQosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_GBR_QosInformation },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABLevelQoSParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABLevelQoSParameters, E_RABLevelQoSParameters_sequence);

  return offset;
}



static int
dissect_s1ap_EUTRANRoundTripDelayEstimationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, FALSE);

  return offset;
}



static int
dissect_s1ap_ExtendedRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            4096U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_s1ap_ExtendedRepetitionPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            4096U, 131071U, NULL, FALSE);

  return offset;
}


static const value_string s1ap_ForbiddenInterRATs_vals[] = {
  {   0, "all" },
  {   1, "geran" },
  {   2, "utran" },
  {   3, "cdma2000" },
  {   4, "geranandutran" },
  {   5, "cdma2000andutran" },
  { 0, NULL }
};


static int
dissect_s1ap_ForbiddenInterRATs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 2, NULL);

  return offset;
}


static const per_sequence_t ForbiddenTACs_sequence_of[1] = {
  { &hf_s1ap_ForbiddenTACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_TAC },
};

static int
dissect_s1ap_ForbiddenTACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ForbiddenTACs, ForbiddenTACs_sequence_of,
                                                  1, maxnoofForbTACs, FALSE);

  return offset;
}


static const per_sequence_t ForbiddenTAs_Item_sequence[] = {
  { &hf_s1ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
  { &hf_s1ap_forbiddenTACs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ForbiddenTACs },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ForbiddenTAs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ForbiddenTAs_Item, ForbiddenTAs_Item_sequence);

  return offset;
}


static const per_sequence_t ForbiddenTAs_sequence_of[1] = {
  { &hf_s1ap_ForbiddenTAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ForbiddenTAs_Item },
};

static int
dissect_s1ap_ForbiddenTAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ForbiddenTAs, ForbiddenTAs_sequence_of,
                                                  1, maxnoofEPLMNsPlusOne, FALSE);

  return offset;
}


static const per_sequence_t ForbiddenLACs_sequence_of[1] = {
  { &hf_s1ap_ForbiddenLACs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_LAC },
};

static int
dissect_s1ap_ForbiddenLACs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ForbiddenLACs, ForbiddenLACs_sequence_of,
                                                  1, maxnoofForbLACs, FALSE);

  return offset;
}


static const per_sequence_t ForbiddenLAs_Item_sequence[] = {
  { &hf_s1ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
  { &hf_s1ap_forbiddenLACs  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ForbiddenLACs },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ForbiddenLAs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ForbiddenLAs_Item, ForbiddenLAs_Item_sequence);

  return offset;
}


static const per_sequence_t ForbiddenLAs_sequence_of[1] = {
  { &hf_s1ap_ForbiddenLAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ForbiddenLAs_Item },
};

static int
dissect_s1ap_ForbiddenLAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ForbiddenLAs, ForbiddenLAs_sequence_of,
                                                  1, maxnoofEPLMNsPlusOne, FALSE);

  return offset;
}



static int
dissect_s1ap_MME_Group_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Group_S1AP_ID_pair_sequence[] = {
  { &hf_s1ap_mME_Group_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_MME_Group_S1AP_ID },
  { &hf_s1ap_eNB_Group_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ENB_Group_S1AP_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_Group_S1AP_ID_pair(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_Group_S1AP_ID_pair, Group_S1AP_ID_pair_sequence);

  return offset;
}


static const value_string s1ap_Group_S1AP_IDs_vals[] = {
  {   0, "group-S1AP-ID-pair" },
  {   1, "mME-Group-S1AP-ID" },
  { 0, NULL }
};

static const per_choice_t Group_S1AP_IDs_choice[] = {
  {   0, &hf_s1ap_group_S1AP_ID_pair, ASN1_EXTENSION_ROOT    , dissect_s1ap_Group_S1AP_ID_pair },
  {   1, &hf_s1ap_mME_Group_S1AP_ID, ASN1_EXTENSION_ROOT    , dissect_s1ap_MME_Group_S1AP_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_Group_S1AP_IDs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_Group_S1AP_IDs, Group_S1AP_IDs_choice,
                                 NULL);

  return offset;
}



static int
dissect_s1ap_GroupIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     44, 44, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t TAIListGroupServiceArea_sequence_of[1] = {
  { &hf_s1ap_TAIListGroupServiceArea_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TAIListGroupServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TAIListGroupServiceArea, TAIListGroupServiceArea_sequence_of,
                                                  1, maxnoofTAIs, FALSE);

  return offset;
}


static const per_sequence_t CellListGroupServiceArea_sequence_of[1] = {
  { &hf_s1ap_CellListGroupServiceArea_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_CellListGroupServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_CellListGroupServiceArea, CellListGroupServiceArea_sequence_of,
                                                  1, maxnoofCellID, FALSE);

  return offset;
}


static const per_sequence_t GroupServiceArea_sequence[] = {
  { &hf_s1ap_tAIList        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_TAIListGroupServiceArea },
  { &hf_s1ap_cellList       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_CellListGroupServiceArea },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupServiceArea, GroupServiceArea_sequence);

  return offset;
}


static const per_sequence_t TAIListItemGroupServiceArea_sequence[] = {
  { &hf_s1ap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TAIListItemGroupServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TAIListItemGroupServiceArea, TAIListItemGroupServiceArea_sequence);

  return offset;
}


static const per_sequence_t CellListItemGroupServiceArea_sequence[] = {
  { &hf_s1ap_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CellListItemGroupServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CellListItemGroupServiceArea, CellListItemGroupServiceArea_sequence);

  return offset;
}


static const value_string s1ap_GroupCallcipheringAlgorithm_vals[] = {
  {   0, "eea0" },
  {   1, "eea1" },
  {   2, "eea2" },
  {   3, "eea3" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_s1ap_GroupCallcipheringAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_GroupCallintegrityProtAlgorithm_vals[] = {
  {   0, "eia0" },
  {   1, "eia1" },
  {   2, "eia2" },
  {   3, "eia3" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_s1ap_GroupCallintegrityProtAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t GroupCallAlgorithms_sequence[] = {
  { &hf_s1ap_groupCallcipheringAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GroupCallcipheringAlgorithm },
  { &hf_s1ap_groupCallintegrityProtAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GroupCallintegrityProtAlgorithm },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallAlgorithms, GroupCallAlgorithms_sequence);

  return offset;
}



static int
dissect_s1ap_SecurityKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_s1ap_RandGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_s1ap_GkVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GroupSecurityInformation_sequence[] = {
  { &hf_s1ap_groupCallSecurityKey, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_SecurityKey },
  { &hf_s1ap_randGroup      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_RandGroup },
  { &hf_s1ap_securityAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GroupCallAlgorithms },
  { &hf_s1ap_gkVersion      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GkVersion },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupSecurityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupSecurityInformation, GroupSecurityInformation_sequence);

  return offset;
}


static const per_sequence_t GroupConfigurationContainerList_sequence_of[1] = {
  { &hf_s1ap_GroupConfigurationContainerList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_GroupConfigurationContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_GroupConfigurationContainerList, GroupConfigurationContainerList_sequence_of,
                                                  1, maxnoofGroupCall, FALSE);

  return offset;
}


static const per_sequence_t GroupConfigurationContainer_sequence[] = {
  { &hf_s1ap_groupConfigurationContainerList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GroupConfigurationContainerList },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupConfigurationContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupConfigurationContainer, GroupConfigurationContainer_sequence);

  return offset;
}


static const per_sequence_t ReleaseGroupCallConfigurationList_sequence_of[1] = {
  { &hf_s1ap_ReleaseGroupCallConfigurationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_ReleaseGroupCallConfigurationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ReleaseGroupCallConfigurationList, ReleaseGroupCallConfigurationList_sequence_of,
                                                  0, maxnoofCellsineNB, FALSE);

  return offset;
}


static const per_sequence_t GroupConfigurationContainerItem_sequence[] = {
  { &hf_s1ap_groupIdentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GroupIdentity },
  { &hf_s1ap_addModGroupCallConfigurationList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_AddModGroupCallConfigurationList },
  { &hf_s1ap_releaseGroupCallConfigurationList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ReleaseGroupCallConfigurationList },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupConfigurationContainerItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupConfigurationContainerItem, GroupConfigurationContainerItem_sequence);

  return offset;
}


static const per_sequence_t GroupAggregateMaximumBitrate_sequence[] = {
  { &hf_s1ap_groupaggregateMaximumBitRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BitRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupAggregateMaximumBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupAggregateMaximumBitrate, GroupAggregateMaximumBitrate_sequence);

  return offset;
}


static const per_sequence_t Group_GBR_QosInformation_sequence[] = {
  { &hf_s1ap_te_RAB_MaximumBitrate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BitRate },
  { &hf_s1ap_te_RAB_GuaranteedBitrate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BitRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_Group_GBR_QosInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_Group_GBR_QosInformation, Group_GBR_QosInformation_sequence);

  return offset;
}


static const per_sequence_t ReleaseGroupCallConfigurationItem_sequence[] = {
  { &hf_s1ap_ecgi           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ReleaseGroupCallConfigurationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ReleaseGroupCallConfigurationItem, ReleaseGroupCallConfigurationItem_sequence);

  return offset;
}



static int
dissect_s1ap_GTP_TEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_s1ap_MME_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 959 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_s1ap_MME_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 950 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       1, 1, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const per_sequence_t GUMMEI_sequence[] = {
  { &hf_s1ap_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
  { &hf_s1ap_mME_Group_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_MME_Group_ID },
  { &hf_s1ap_mME_Code       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_MME_Code },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GUMMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GUMMEI, GUMMEI_sequence);

  return offset;
}


static const per_sequence_t HandoverRestrictionList_sequence[] = {
  { &hf_s1ap_servingPLMN    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
  { &hf_s1ap_equivalentPLMNs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_EPLMNs },
  { &hf_s1ap_forbiddenTAs   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ForbiddenTAs },
  { &hf_s1ap_forbiddenLAs   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ForbiddenLAs },
  { &hf_s1ap_forbiddenInterRATs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ForbiddenInterRATs },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverRestrictionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverRestrictionList, HandoverRestrictionList_sequence);

  return offset;
}


static const value_string s1ap_HandoverType_vals[] = {
  { intralte, "intralte" },
  { ltetoutran, "ltetoutran" },
  { ltetogeran, "ltetogeran" },
  { utrantolte, "utrantolte" },
  { gerantolte, "gerantolte" },
  { 0, NULL }
};


static int
dissect_s1ap_HandoverType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 362 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, &s1ap_data->handover_type_value, TRUE, 0, NULL);




  return offset;
}



static int
dissect_s1ap_IMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1299 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 8, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_IMSI);
    dissect_e212_imsi(parameter_tvb, actx->pinfo, subtree, 0, tvb_reported_length(parameter_tvb), FALSE);
  }



  return offset;
}



static int
dissect_s1ap_IntegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 981 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, TRUE, NULL, 0, &parameter_tvb, NULL);

  if(parameter_tvb){
    static int * const fields[] = {
      &hf_s1ap_integrityProtectionAlgorithms_EIA1,
      &hf_s1ap_integrityProtectionAlgorithms_EIA2,
      &hf_s1ap_integrityProtectionAlgorithms_EIA3,
      &hf_s1ap_integrityProtectionAlgorithms_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_IntegrityProtectionAlgorithms);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 2, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_s1ap_InterfacesToTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 868 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, 0, &parameter_tvb, NULL);

  if(parameter_tvb){
    static int * const fields[] = {
      &hf_s1ap_interfacesToTrace_S1_MME,
      &hf_s1ap_interfacesToTrace_X2,
      &hf_s1ap_interfacesToTrace_Uu,
      &hf_s1ap_interfacesToTrace_F1_C,
      &hf_s1ap_interfacesToTrace_E1,
      &hf_s1ap_interfacesToTrace_Reserved,
      NULL
    };
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_InterfacesToTrace);
    proto_tree_add_bitmask_list(subtree, parameter_tvb, 0, 1, fields, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_s1ap_Time_UE_StayedInCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LastVisitedEUTRANCellInformation_sequence[] = {
  { &hf_s1ap_global_Cell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_cellType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_CellType },
  { &hf_s1ap_time_UE_StayedInCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Time_UE_StayedInCell },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_LastVisitedEUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_LastVisitedEUTRANCellInformation, LastVisitedEUTRANCellInformation_sequence);

  return offset;
}



static int
dissect_s1ap_LastVisitedUTRANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1030 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  if (g_s1ap_dissect_container) {
    subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_LastVisitedUTRANCellInformation);
    TRY {
      dissect_ranap_LastVisitedUTRANCell_Item_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
    }
    CATCH_BOUNDS_ERRORS {
      show_exception(parameter_tvb, actx->pinfo, subtree, EXCEPT_CODE, GET_MESSAGE);
    }
    ENDTRY;
  }



  return offset;
}



static int
dissect_s1ap_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string s1ap_LastVisitedGERANCellInformation_vals[] = {
  {   0, "undefined" },
  { 0, NULL }
};

static const per_choice_t LastVisitedGERANCellInformation_choice[] = {
  {   0, &hf_s1ap_undefined      , ASN1_EXTENSION_ROOT    , dissect_s1ap_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_LastVisitedGERANCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_LastVisitedGERANCellInformation, LastVisitedGERANCellInformation_choice,
                                 NULL);

  return offset;
}


static const value_string s1ap_LastVisitedCell_Item_vals[] = {
  {   0, "e-UTRAN-Cell" },
  {   1, "uTRAN-Cell" },
  {   2, "gERAN-Cell" },
  { 0, NULL }
};

static const per_choice_t LastVisitedCell_Item_choice[] = {
  {   0, &hf_s1ap_e_UTRAN_Cell   , ASN1_EXTENSION_ROOT    , dissect_s1ap_LastVisitedEUTRANCellInformation },
  {   1, &hf_s1ap_uTRAN_Cell     , ASN1_EXTENSION_ROOT    , dissect_s1ap_LastVisitedUTRANCellInformation },
  {   2, &hf_s1ap_gERAN_Cell     , ASN1_EXTENSION_ROOT    , dissect_s1ap_LastVisitedGERANCellInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_LastVisitedCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_LastVisitedCell_Item, LastVisitedCell_Item_choice,
                                 NULL);

  return offset;
}



static int
dissect_s1ap_LPPa_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 303 "./asn1/s1ap/s1ap.cnf"

  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);


  if ((tvb_reported_length(parameter_tvb)>0)&&(lppa_handle))
    call_dissector(lppa_handle, parameter_tvb, actx->pinfo, tree);



  return offset;
}



static int
dissect_s1ap_MessageIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1051 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, FALSE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_s1ap_MMEname(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 275 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  int length;
  gboolean is_ascii;

  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, TRUE);


  if (!parameter_tvb)
    return offset;

  length = tvb_reported_length(parameter_tvb);

  is_ascii = tvb_ascii_isprint(parameter_tvb, 0, length);
  if (is_ascii)
     proto_item_append_text(actx->created_item," (%s)",tvb_format_text(parameter_tvb, 0, length));



  return offset;
}



static int
dissect_s1ap_MME_UE_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1364 "./asn1/s1ap/s1ap.cnf"
  guint32 mme_ue_s1ap_id;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, &mme_ue_s1ap_id, FALSE);

  if (hf_index == hf_s1ap_mME_UE_S1AP_ID) {
    proto_item *item;
    item = proto_tree_add_uint(tree, hf_s1ap_MME_UE_S1AP_ID_PDU, tvb, offset, 0 , mme_ue_s1ap_id );
    proto_item_set_hidden(item);
  }



  return offset;
}



static int
dissect_s1ap_M_TMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1288 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  proto_item *ti;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       4, 4, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(tree, hf_3gpp_tmsi, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_item_set_hidden(ti);

  }



  return offset;
}



static int
dissect_s1ap_MSClassmark2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1104 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_MSClassmark);
    de_ms_cm_2(parameter_tvb, subtree, actx->pinfo, 0, tvb_reported_length(parameter_tvb), NULL, 0);
  }



  return offset;
}



static int
dissect_s1ap_MSClassmark3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1112 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_MSClassmark);
    de_ms_cm_3(parameter_tvb, subtree, actx->pinfo, 0, tvb_reported_length(parameter_tvb), NULL, 0);
  }



  return offset;
}



static int
dissect_s1ap_NAS_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 294 "./asn1/s1ap/s1ap.cnf"

tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);


  if ((tvb_reported_length(parameter_tvb)>0)&&(nas_eps_handle))
    call_dissector(nas_eps_handle,parameter_tvb,actx->pinfo, tree);



  return offset;
}



static int
dissect_s1ap_NASSecurityParametersfromE_UTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1307 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_NASSecurityParameters);
    de_emm_sec_par_from_eutra(parameter_tvb, subtree, actx->pinfo, 0, tvb_reported_length(parameter_tvb), NULL, 0);
  }



  return offset;
}



static int
dissect_s1ap_NASSecurityParameterstoE_UTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1315 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_NASSecurityParameters);
    de_emm_sec_par_to_eutra(parameter_tvb, subtree, actx->pinfo, 0, tvb_reported_length(parameter_tvb), NULL, 0);
  }



  return offset;
}



static int
dissect_s1ap_NumberofBroadcastRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string s1ap_OverloadAction_vals[] = {
  {   0, "reject-non-emergency-mo-dt" },
  {   1, "reject-all-rrc-cr-signalling" },
  {   2, "permit-emergency-sessions-and-mobile-terminated-services-only" },
  { 0, NULL }
};


static int
dissect_s1ap_OverloadAction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_OverloadResponse_vals[] = {
  {   0, "overloadAction" },
  { 0, NULL }
};

static const per_choice_t OverloadResponse_choice[] = {
  {   0, &hf_s1ap_overloadAction , ASN1_EXTENSION_ROOT    , dissect_s1ap_OverloadAction },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_OverloadResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_OverloadResponse, OverloadResponse_choice,
                                 NULL);

  return offset;
}


static const value_string s1ap_PagingDRX_vals[] = {
  {   0, "v32" },
  {   1, "v64" },
  {   2, "v128" },
  {   3, "v256" },
  { 0, NULL }
};


static int
dissect_s1ap_PagingDRX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_PS_ServiceNotAvailable_vals[] = {
  {   0, "ps-service-not-available" },
  { 0, NULL }
};


static int
dissect_s1ap_PS_ServiceNotAvailable(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_NAS_PDUType_vals[] = {
  {   0, "start-floor-inform-periodic-transfer" },
  {   1, "start-video-source-indication-periodic-transfer" },
  {   2, "stop-video-source-indication-periodic-transfer" },
  {   3, "groupcallsetupindication" },
  { 0, NULL }
};


static int
dissect_s1ap_NAS_PDUType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_NeedResponse_vals[] = {
  {   0, "needed" },
  { 0, NULL }
};


static int
dissect_s1ap_NeedResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_RelativeMMECapacity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string s1ap_ReportArea_vals[] = {
  {   0, "ecgi" },
  { 0, NULL }
};


static int
dissect_s1ap_ReportArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t RequestType_sequence[] = {
  { &hf_s1ap_eventType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EventType },
  { &hf_s1ap_reportArea     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ReportArea },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_RequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_RequestType, RequestType_sequence);

  return offset;
}



static int
dissect_s1ap_RIMInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 654 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_RIMInformation);
  if ((tvb_reported_length(parameter_tvb)>0)&&(bssgp_handle)){
    col_set_fence(actx->pinfo->cinfo, COL_INFO);
    call_dissector(bssgp_handle,parameter_tvb,actx->pinfo, subtree);
  }




  return offset;
}



static int
dissect_s1ap_RNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TargetRNC_ID_sequence[] = {
  { &hf_s1ap_lAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_LAI },
  { &hf_s1ap_rAC            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_RAC },
  { &hf_s1ap_rNC_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_RNC_ID },
  { &hf_s1ap_extendedRNC_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ExtendedRNC_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TargetRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TargetRNC_ID, TargetRNC_ID_sequence);

  return offset;
}


static const value_string s1ap_RIMRoutingAddress_vals[] = {
  {   0, "gERAN-Cell-ID" },
  {   1, "targetRNC-ID" },
  { 0, NULL }
};

static const per_choice_t RIMRoutingAddress_choice[] = {
  {   0, &hf_s1ap_gERAN_Cell_ID  , ASN1_EXTENSION_ROOT    , dissect_s1ap_GERAN_Cell_ID },
  {   1, &hf_s1ap_targetRNC_ID   , ASN1_NOT_EXTENSION_ROOT, dissect_s1ap_TargetRNC_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_RIMRoutingAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_RIMRoutingAddress, RIMRoutingAddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RIMTransfer_sequence[] = {
  { &hf_s1ap_rIMInformation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_RIMInformation },
  { &hf_s1ap_rIMRoutingAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_RIMRoutingAddress },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_RIMTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_RIMTransfer, RIMTransfer_sequence);

  return offset;
}



static int
dissect_s1ap_RepetitionPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const value_string s1ap_RRC_Establishment_Cause_vals[] = {
  {   0, "emergency" },
  {   1, "highPriorityAccess" },
  {   2, "mt-Access" },
  {   3, "mo-Signalling" },
  {   4, "mo-Data" },
  { 0, NULL }
};


static int
dissect_s1ap_RRC_Establishment_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_Routing_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_s1ap_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SecurityContext_sequence[] = {
  { &hf_s1ap_nextHopChainingCount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_INTEGER_0_7 },
  { &hf_s1ap_nextHopParameter, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_SecurityKey },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_SecurityContext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_SecurityContext, SecurityContext_sequence);

  return offset;
}



static int
dissect_s1ap_SerialNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1058 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, &parameter_tvb, NULL);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_SerialNumber);
    proto_tree_add_item(subtree, hf_s1ap_SerialNumber_gs, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_s1ap_SerialNumber_msg_code, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_s1ap_SerialNumber_upd_nb, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}


static const value_string s1ap_SONInformationRequest_vals[] = {
  {   0, "x2TNL-Configuration-Info" },
  {   1, "time-Synchronization-Info" },
  { 0, NULL }
};


static int
dissect_s1ap_SONInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 1, NULL);

  return offset;
}


static const per_sequence_t X2TNLConfigurationInfo_sequence[] = {
  { &hf_s1ap_eNBX2TransportLayerAddresses, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ENBX2TLAs },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_X2TNLConfigurationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_X2TNLConfigurationInfo, X2TNLConfigurationInfo_sequence);

  return offset;
}


static const per_sequence_t SONInformationReply_sequence[] = {
  { &hf_s1ap_x2TNLConfigurationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_X2TNLConfigurationInfo },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_SONInformationReply(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_SONInformationReply, SONInformationReply_sequence);

  return offset;
}


static const value_string s1ap_SONInformation_vals[] = {
  {   0, "sONInformationRequest" },
  {   1, "sONInformationReply" },
  { 0, NULL }
};

static const per_choice_t SONInformation_choice[] = {
  {   0, &hf_s1ap_sONInformationRequest, ASN1_EXTENSION_ROOT    , dissect_s1ap_SONInformationRequest },
  {   1, &hf_s1ap_sONInformationReply, ASN1_EXTENSION_ROOT    , dissect_s1ap_SONInformationReply },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_SONInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_SONInformation, SONInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TargeteNB_ID_sequence[] = {
  { &hf_s1ap_global_ENB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Global_ENB_ID },
  { &hf_s1ap_selected_TAI   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TargeteNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TargeteNB_ID, TargeteNB_ID_sequence);

  return offset;
}


static const per_sequence_t SourceeNB_ID_sequence[] = {
  { &hf_s1ap_global_ENB_ID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_Global_ENB_ID },
  { &hf_s1ap_selected_TAI   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI },
  { &hf_s1ap_iE_Extensions  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_SourceeNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_SourceeNB_ID, SourceeNB_ID_sequence);

  return offset;
}


static const per_sequence_t SONConfigurationTransfer_sequence[] = {
  { &hf_s1ap_targeteNB_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TargeteNB_ID },
  { &hf_s1ap_sourceeNB_ID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_SourceeNB_ID },
  { &hf_s1ap_sONInformation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_SONInformation },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_SONConfigurationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_SONConfigurationTransfer, SONConfigurationTransfer_sequence);

  return offset;
}



static int
dissect_s1ap_Source_ToTarget_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 400 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);


  if ((g_s1ap_dissect_container)&&(parameter_tvb) && (tvb_reported_length(parameter_tvb) > 0)) {
    struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
    /* Don't want elements inside container to write to info column */
    col_set_writable(actx->pinfo->cinfo, COL_INFO, FALSE);
    subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_ToTargetTransparentContainer);

    switch(s1ap_data->handover_type_value){
      /*
      HandoverType ::= ENUMERATED {
      intralte,
      ltetoutran,
      ltetogeran,
      utrantolte,
      gerantolte,
      ...
      } */
      case intralte:
      /* intralte
        Intra E-UTRAN handover Source eNB to Target eNB
        Transparent Container 36.413
      */
      case utrantolte:
      /* utrantolte */
      case gerantolte:
      /* gerantolte */
      break;
      case ltetoutran:
      /* ltetoutran
        Source RNC to Target RNC
        Transparent Container 25.413
      */
      dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      break;
      case ltetogeran:
      /* ltetogeran
        Source BSS to Target BSS
        Transparent Container 48.018
        or
        Old BSS to New BSS information elements
        Transparent Container 48.008
      */
      if (s1ap_data->srvcc_ho_cs_only)
        bssmap_old_bss_to_new_bss_info(parameter_tvb, subtree, actx->pinfo);
      else
        de_bssgp_source_BSS_to_target_BSS_transp_cont(parameter_tvb, subtree, actx->pinfo, 0, tvb_reported_length(parameter_tvb), NULL, 0);
      break;
      default:
      break;
    }
    /* Enable writing of the column again */
    col_set_writable(actx->pinfo->cinfo, COL_INFO, TRUE);
  }



  return offset;
}



static const value_string s1ap_SRVCCOperationPossible_vals[] = {
  {   0, "possible" },
  { 0, NULL }
};


static int
dissect_s1ap_SRVCCOperationPossible(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string s1ap_SRVCCHOIndication_vals[] = {
  { pSandCS, "pSandCS" },
  { cSonly, "cSonly" },
  { 0, NULL }
};


static int
dissect_s1ap_SRVCCHOIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 366 "./asn1/s1ap/s1ap.cnf"
  guint32 srvcc_ho_ind;
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, &srvcc_ho_ind, TRUE, 0, NULL);

  if (srvcc_ho_ind == cSonly)
    s1ap_data->srvcc_ho_cs_only = TRUE;



  return offset;
}



static int
dissect_s1ap_SubscriberProfileIDforRFP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, FALSE);

  return offset;
}


static const per_sequence_t UE_HistoryInformation_sequence_of[1] = {
  { &hf_s1ap_UE_HistoryInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_LastVisitedCell_Item },
};

static int
dissect_s1ap_UE_HistoryInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_UE_HistoryInformation, UE_HistoryInformation_sequence_of,
                                                  1, maxnoofCells, FALSE);

  return offset;
}


static const per_sequence_t SourceeNB_ToTargeteNB_TransparentContainer_sequence[] = {
  { &hf_s1ap_rRC_Container  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_RRC_Container },
  { &hf_s1ap_e_RABInformationList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_E_RABInformationList },
  { &hf_s1ap_targetCell_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EUTRAN_CGI },
  { &hf_s1ap_subscriberProfileIDforRFP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_SubscriberProfileIDforRFP },
  { &hf_s1ap_uE_HistoryInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_UE_HistoryInformation },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_SourceeNB_ToTargeteNB_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 388 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);

  s1ap_data->transparent_container_type = SOURCE_TO_TARGET_TRANSPARENT_CONTAINER;


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_SourceeNB_ToTargeteNB_TransparentContainer, SourceeNB_ToTargeteNB_TransparentContainer_sequence);

  return offset;
}


static const per_sequence_t SourceeNB_List_sequence_of[1] = {
  { &hf_s1ap_SourceeNB_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_SourceeNB_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_SourceeNB_List, SourceeNB_List_sequence_of,
                                                  1, maxNrOfeNBs, FALSE);

  return offset;
}


static const per_sequence_t SourceeNB_Item_sequence[] = {
  { &hf_s1ap_global_ENB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Global_ENB_ID },
  { &hf_s1ap_needResponse   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_NeedResponse },
  { &hf_s1ap_groupConfigurationContainer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GroupConfigurationContainer },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_SourceeNB_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_SourceeNB_Item, SourceeNB_Item_sequence);

  return offset;
}



static const per_sequence_t ServedPLMNs_sequence_of[1] = {
  { &hf_s1ap_ServedPLMNs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_PLMNidentity },
};

static int
dissect_s1ap_ServedPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ServedPLMNs, ServedPLMNs_sequence_of,
                                                  1, maxnoofPLMNsPerMME, FALSE);

  return offset;
}


static const per_sequence_t ServedGroupIDs_sequence_of[1] = {
  { &hf_s1ap_ServedGroupIDs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_MME_Group_ID },
};

static int
dissect_s1ap_ServedGroupIDs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ServedGroupIDs, ServedGroupIDs_sequence_of,
                                                  1, maxnoofGroupIDs, FALSE);

  return offset;
}


static const per_sequence_t ServedMMECs_sequence_of[1] = {
  { &hf_s1ap_ServedMMECs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_MME_Code },
};

static int
dissect_s1ap_ServedMMECs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ServedMMECs, ServedMMECs_sequence_of,
                                                  1, maxnoofMMECs, FALSE);

  return offset;
}


static const per_sequence_t ServedGUMMEIsItem_sequence[] = {
  { &hf_s1ap_servedPLMNs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ServedPLMNs },
  { &hf_s1ap_servedGroupIDs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ServedGroupIDs },
  { &hf_s1ap_servedMMECs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ServedMMECs },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ServedGUMMEIsItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ServedGUMMEIsItem, ServedGUMMEIsItem_sequence);

  return offset;
}


static const per_sequence_t ServedGUMMEIs_sequence_of[1] = {
  { &hf_s1ap_ServedGUMMEIs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ServedGUMMEIsItem },
};

static int
dissect_s1ap_ServedGUMMEIs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ServedGUMMEIs, ServedGUMMEIs_sequence_of,
                                                  1, maxnoofRATs, FALSE);

  return offset;
}


static const per_sequence_t SupportedTAs_Item_sequence[] = {
  { &hf_s1ap_tAC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TAC },
  { &hf_s1ap_broadcastPLMNs , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BPLMNs },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_SupportedTAs_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1323 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);

  if (!PINFO_FD_VISITED(actx->pinfo) &&
      (s1ap_data->message_type == INITIATING_MESSAGE) &&
      ((s1ap_data->procedure_code == id_S1Setup) ||
       (s1ap_data->procedure_code == id_ENBConfigurationUpdate))) {
    s1ap_data->supported_ta = wmem_new0(wmem_packet_scope(), struct s1ap_supported_ta);
    s1ap_data->supported_ta->plmn = wmem_array_new(wmem_packet_scope(), sizeof(guint32));
  }


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_SupportedTAs_Item, SupportedTAs_Item_sequence);

#line 1334 "./asn1/s1ap/s1ap.cnf"
  s1ap_data->supported_ta = NULL;


  return offset;
}


static const per_sequence_t SupportedTAs_sequence_of[1] = {
  { &hf_s1ap_SupportedTAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_SupportedTAs_Item },
};

static int
dissect_s1ap_SupportedTAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_SupportedTAs, SupportedTAs_sequence_of,
                                                  1, maxnoofTACs, FALSE);

  return offset;
}



static int
dissect_s1ap_StratumLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, TRUE);

  return offset;
}


static const value_string s1ap_SynchronizationStatus_vals[] = {
  {   0, "synchronous" },
  {   1, "asynchronous" },
  { 0, NULL }
};


static int
dissect_s1ap_SynchronizationStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TimeSynchronizationInfo_sequence[] = {
  { &hf_s1ap_stratumLevel   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_StratumLevel },
  { &hf_s1ap_synchronizationStatus, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_SynchronizationStatus },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TimeSynchronizationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TimeSynchronizationInfo, TimeSynchronizationInfo_sequence);

  return offset;
}


static const per_sequence_t S_TMSI_sequence[] = {
  { &hf_s1ap_mMEC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_MME_Code },
  { &hf_s1ap_m_TMSI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_M_TMSI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_S_TMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_S_TMSI, S_TMSI_sequence);

  return offset;
}


static const per_sequence_t TAIListforWarning_sequence_of[1] = {
  { &hf_s1ap_TAIListforWarning_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI },
};

static int
dissect_s1ap_TAIListforWarning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TAIListforWarning, TAIListforWarning_sequence_of,
                                                  1, maxnoofTAIforWarning, FALSE);

  return offset;
}


static const value_string s1ap_TargetID_vals[] = {
  {   0, "targeteNB-ID" },
  {   1, "targetRNC-ID" },
  {   2, "cGI" },
  { 0, NULL }
};

static const per_choice_t TargetID_choice[] = {
  {   0, &hf_s1ap_targeteNB_ID   , ASN1_EXTENSION_ROOT    , dissect_s1ap_TargeteNB_ID },
  {   1, &hf_s1ap_targetRNC_ID   , ASN1_EXTENSION_ROOT    , dissect_s1ap_TargetRNC_ID },
  {   2, &hf_s1ap_cGI            , ASN1_EXTENSION_ROOT    , dissect_s1ap_CGI },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_TargetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_TargetID, TargetID_choice,
                                 NULL);

  return offset;
}


static const value_string s1ap_TrunkingUserIndication_vals[] = {
  {   0, "isTrunkingUser" },
  { 0, NULL }
};


static int
dissect_s1ap_TrunkingUserIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_TE_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}


static const per_sequence_t TE_RABList_sequence_of[1] = {
  { &hf_s1ap_TE_RABList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TE_RABList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TE_RABList, TE_RABList_sequence_of,
                                                  1, maxNrOfTE_RABs, FALSE);

  return offset;
}


static const per_sequence_t TE_RABItem_sequence[] = {
  { &hf_s1ap_tE_RAB_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RAB_ID },
  { &hf_s1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Cause },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TE_RABItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TE_RABItem, TE_RABItem_sequence);

  return offset;
}


static const per_sequence_t TE_RABLevelQoSParameters_sequence[] = {
  { &hf_s1ap_qCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_QCI },
  { &hf_s1ap_allocationRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_AllocationAndRetentionPriority },
  { &hf_s1ap_groupGbrQosInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_Group_GBR_QosInformation },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TE_RABLevelQoSParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TE_RABLevelQoSParameters, TE_RABLevelQoSParameters_sequence);

  return offset;
}


static const per_sequence_t TargeteNB_List_sequence_of[1] = {
  { &hf_s1ap_TargeteNB_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TargeteNB_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TargeteNB_List, TargeteNB_List_sequence_of,
                                                  1, maxNrOfeNBs, FALSE);

  return offset;
}


static const per_sequence_t TargeteNB_Item_sequence[] = {
  { &hf_s1ap_global_ENB_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Global_ENB_ID },
  { &hf_s1ap_needResponse   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_NeedResponse },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TargeteNB_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TargeteNB_Item, TargeteNB_Item_sequence);

  return offset;
}


static const per_sequence_t TargeteNB_ToSourceeNB_TransparentContainer_sequence[] = {
  { &hf_s1ap_rRC_Container  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_RRC_Container },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TargeteNB_ToSourceeNB_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 459 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);

  s1ap_data->transparent_container_type = TARGET_TO_SOURCE_TRANSPARENT_CONTAINER;


  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TargeteNB_ToSourceeNB_TransparentContainer, TargeteNB_ToSourceeNB_TransparentContainer_sequence);

  return offset;
}



static int
dissect_s1ap_Target_ToSource_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 466 "./asn1/s1ap/s1ap.cnf"

  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);


  if ((g_s1ap_dissect_container)&&(parameter_tvb) && (tvb_reported_length(parameter_tvb) > 0)) {
    struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
    subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_ToSourceTransparentContainer);

    switch(s1ap_data->handover_type_value){
    /*
      HandoverType ::= ENUMERATED {
      intralte,
      ltetoutran,
      ltetogeran,
      utrantolte,
      gerantolte,
      ...
      } */
      case intralte:
      /* intralte
        Intra E-UTRAN handover Target eNB to Source eNB
        Transparent Container 36.413
      */
      case utrantolte:
      /* utrantolte */
      case gerantolte:
      /* gerantolte */
      break;
      case ltetoutran:
      /* ltetoutran
        Target RNC to Source RNC
        Transparent Container 25.413
      */
      dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
      break;
      case ltetogeran:
      /* ltetogeran
        Target BSS to Source BSS
        Transparent Container 48.018
      */
      de_bssgp_target_BSS_to_source_BSS_transp_cont(parameter_tvb, subtree, actx->pinfo, 0, tvb_reported_length(parameter_tvb), NULL, 0);
      break;
      default:
      break;
    }
  }



  return offset;
}




static const value_string s1ap_TimeToWait_vals[] = {
  {   0, "v1s" },
  {   1, "v2s" },
  {   2, "v5s" },
  {   3, "v10s" },
  {   4, "v20s" },
  {   5, "v60s" },
  { 0, NULL }
};


static int
dissect_s1ap_TimeToWait(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_s1ap_E_UTRAN_Trace_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 857 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_E_UTRAN_Trace_ID);
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, FALSE);
  proto_tree_add_item(subtree, hf_s1ap_E_UTRAN_Trace_ID_TraceID, parameter_tvb, 3, 3, ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_s1ap_E_UTRAN_Trace_ID_TraceRecordingSessionReference, parameter_tvb, 6, 2, ENC_BIG_ENDIAN);



  return offset;
}


static const value_string s1ap_TraceDepth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  {   3, "minimumWithoutVendorSpecificExtension" },
  {   4, "mediumWithoutVendorSpecificExtension" },
  {   5, "maximumWithoutVendorSpecificExtension" },
  { 0, NULL }
};


static int
dissect_s1ap_TraceDepth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TraceActivation_sequence[] = {
  { &hf_s1ap_e_UTRAN_Trace_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_UTRAN_Trace_ID },
  { &hf_s1ap_interfacesToTrace, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_InterfacesToTrace },
  { &hf_s1ap_traceDepth     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TraceDepth },
  { &hf_s1ap_traceCollectionEntityIPAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TraceActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TraceActivation, TraceActivation_sequence);

  return offset;
}


static const per_sequence_t UEAggregateMaximumBitrate_sequence[] = {
  { &hf_s1ap_uEaggregateMaximumBitRateDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BitRate },
  { &hf_s1ap_uEaggregateMaximumBitRateUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_BitRate },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UEAggregateMaximumBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UEAggregateMaximumBitrate, UEAggregateMaximumBitrate_sequence);

  return offset;
}


static const per_sequence_t UE_S1AP_ID_pair_sequence[] = {
  { &hf_s1ap_mME_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_MME_UE_S1AP_ID },
  { &hf_s1ap_eNB_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ENB_UE_S1AP_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UE_S1AP_ID_pair(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UE_S1AP_ID_pair, UE_S1AP_ID_pair_sequence);

  return offset;
}


static const value_string s1ap_UE_S1AP_IDs_vals[] = {
  {   0, "uE-S1AP-ID-pair" },
  {   1, "mME-UE-S1AP-ID" },
  { 0, NULL }
};

static const per_choice_t UE_S1AP_IDs_choice[] = {
  {   0, &hf_s1ap_uE_S1AP_ID_pair, ASN1_EXTENSION_ROOT    , dissect_s1ap_UE_S1AP_ID_pair },
  {   1, &hf_s1ap_mME_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , dissect_s1ap_MME_UE_S1AP_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_UE_S1AP_IDs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_UE_S1AP_IDs, UE_S1AP_IDs_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UE_associatedLogicalS1_ConnectionItem_sequence[] = {
  { &hf_s1ap_mME_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_MME_UE_S1AP_ID },
  { &hf_s1ap_eNB_UE_S1AP_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ENB_UE_S1AP_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UE_associatedLogicalS1_ConnectionItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UE_associatedLogicalS1_ConnectionItem, UE_associatedLogicalS1_ConnectionItem_sequence);

  return offset;
}



static int
dissect_s1ap_UEIdentityIndexValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string s1ap_UEPagingID_vals[] = {
  {   0, "s-TMSI" },
  {   1, "iMSI" },
  { 0, NULL }
};

static const per_choice_t UEPagingID_choice[] = {
  {   0, &hf_s1ap_s_TMSI         , ASN1_EXTENSION_ROOT    , dissect_s1ap_S_TMSI },
  {   1, &hf_s1ap_iMSI           , ASN1_EXTENSION_ROOT    , dissect_s1ap_IMSI },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_UEPagingID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_UEPagingID, UEPagingID_choice,
                                 NULL);

  return offset;
}



static int
dissect_s1ap_UERadioCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 620 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  if (g_s1ap_dissect_container) {
    struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
    volatile dissector_handle_t handle;
    subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_UERadioCapability);
    {
      handle = lte_rrc_ue_radio_access_cap_info_handle;
    }
    if (handle) {
      TRY {
        call_dissector(handle, parameter_tvb, actx->pinfo, subtree);
      }
      CATCH_BOUNDS_ERRORS {
        show_exception(parameter_tvb, actx->pinfo, subtree, EXCEPT_CODE, GET_MESSAGE);
      }
      ENDTRY;
    }
  }



  return offset;
}


static const per_sequence_t UESecurityCapabilities_sequence[] = {
  { &hf_s1ap_encryptionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_EncryptionAlgorithms },
  { &hf_s1ap_integrityProtectionAlgorithms, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_IntegrityProtectionAlgorithms },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UESecurityCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UESecurityCapabilities, UESecurityCapabilities_sequence);

  return offset;
}


static const value_string s1ap_WarningAreaList_vals[] = {
  {   0, "cellIDList" },
  {   1, "trackingAreaListforWarning" },
  {   2, "emergencyAreaIDList" },
  { 0, NULL }
};

static const per_choice_t WarningAreaList_choice[] = {
  {   0, &hf_s1ap_cellIDList     , ASN1_EXTENSION_ROOT    , dissect_s1ap_ECGIList },
  {   1, &hf_s1ap_trackingAreaListforWarning, ASN1_EXTENSION_ROOT    , dissect_s1ap_TAIListforWarning },
  {   2, &hf_s1ap_emergencyAreaIDList, ASN1_EXTENSION_ROOT    , dissect_s1ap_EmergencyAreaIDList },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_WarningAreaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_WarningAreaList, WarningAreaList_choice,
                                 NULL);

  return offset;
}



static int
dissect_s1ap_WarningType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1071 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_WarningType);
    proto_tree_add_item(subtree, hf_s1ap_WarningType_value, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_s1ap_WarningType_emergency_user_alert, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_s1ap_WarningType_popup, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }



  return offset;
}



static int
dissect_s1ap_WarningSecurityInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       50, 50, FALSE, NULL);

  return offset;
}



static int
dissect_s1ap_WarningMessageContents(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 1095 "./asn1/s1ap/s1ap.cnf"
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 9600, FALSE, &parameter_tvb);

  if (parameter_tvb) {
    struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_s1ap_WarningMessageContents);
    dissect_s1ap_warningMessageContents(parameter_tvb, subtree, actx->pinfo, s1ap_data->data_coding_scheme, hf_s1ap_WarningMessageContents_nb_pages, hf_s1ap_WarningMessageContents_decoded_page);
  }



  return offset;
}



static int
dissect_s1ap_E_RAB_IE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 190 "./asn1/s1ap/s1ap.cnf"
  asn1_stack_frame_push(actx, "ProtocolIE-ContainerList");
  asn1_param_push_integer(actx, 1);
  asn1_param_push_integer(actx, maxnoofE_RABs);
  offset = dissect_s1ap_ProtocolIE_ContainerList(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, "ProtocolIE-ContainerList");


  return offset;
}


static const per_sequence_t HandoverRequired_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 374 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  s1ap_data->handover_type_value = 0xff;
  s1ap_data->srvcc_ho_cs_only = FALSE;
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequired");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverRequired, HandoverRequired_sequence);

  return offset;
}


static const per_sequence_t HandoverCommand_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 378 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  s1ap_data->handover_type_value = 0xff;
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverCommand");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverCommand, HandoverCommand_sequence);

  return offset;
}



static int
dissect_s1ap_E_RABSubjecttoDataForwardingList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s1ap_E_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t E_RABDataForwardingItem_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_dL_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_dL_gTP_TEID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_GTP_TEID },
  { &hf_s1ap_uL_TransportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_uL_GTP_TEID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABDataForwardingItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABDataForwardingItem, E_RABDataForwardingItem_sequence);

  return offset;
}


static const per_sequence_t HandoverPreparationFailure_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverPreparationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2447 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverPreparationFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverPreparationFailure, HandoverPreparationFailure_sequence);

  return offset;
}


static const per_sequence_t HandoverRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 381 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  s1ap_data->handover_type_value = 0xff;
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverRequest, HandoverRequest_sequence);

  return offset;
}



static int
dissect_s1ap_E_RABToBeSetupListHOReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s1ap_E_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t E_RABToBeSetupItemHOReq_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_e_RABlevelQosParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RABLevelQoSParameters },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABToBeSetupItemHOReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABToBeSetupItemHOReq, E_RABToBeSetupItemHOReq_sequence);

  return offset;
}


static const per_sequence_t HandoverRequestAcknowledge_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 384 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  s1ap_data->handover_type_value = 0xff;

  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverRequestAcknowledge, HandoverRequestAcknowledge_sequence);

  return offset;
}



static int
dissect_s1ap_E_RABAdmittedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s1ap_E_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t E_RABAdmittedItem_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_dL_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_dL_gTP_TEID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_GTP_TEID },
  { &hf_s1ap_uL_TransportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_uL_GTP_TEID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABAdmittedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABAdmittedItem, E_RABAdmittedItem_sequence);

  return offset;
}



static int
dissect_s1ap_E_RABFailedtoSetupListHOReqAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s1ap_E_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t E_RABFailedToSetupItemHOReqAck_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_cause          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Cause },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABFailedToSetupItemHOReqAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABFailedToSetupItemHOReqAck, E_RABFailedToSetupItemHOReqAck_sequence);

  return offset;
}


static const per_sequence_t HandoverFailure_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2453 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverFailure, HandoverFailure_sequence);

  return offset;
}


static const per_sequence_t HandoverNotify_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverNotify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2455 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverNotify");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverNotify, HandoverNotify_sequence);

  return offset;
}


static const per_sequence_t PathSwitchRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_PathSwitchRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2457 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PathSwitchRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_PathSwitchRequest, PathSwitchRequest_sequence);

  return offset;
}



static int
dissect_s1ap_E_RABToBeSwitchedDLList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s1ap_E_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t E_RABToBeSwitchedDLItem_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABToBeSwitchedDLItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABToBeSwitchedDLItem, E_RABToBeSwitchedDLItem_sequence);

  return offset;
}


static const per_sequence_t PathSwitchRequestAcknowledge_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_PathSwitchRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2459 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PathSwitchRequestAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_PathSwitchRequestAcknowledge, PathSwitchRequestAcknowledge_sequence);

  return offset;
}



static int
dissect_s1ap_E_RABToBeSwitchedULList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_s1ap_E_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t E_RABToBeSwitchedULItem_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABToBeSwitchedULItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABToBeSwitchedULItem, E_RABToBeSwitchedULItem_sequence);

  return offset;
}


static const per_sequence_t PathSwitchRequestFailure_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_PathSwitchRequestFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2461 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PathSwitchRequestFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_PathSwitchRequestFailure, PathSwitchRequestFailure_sequence);

  return offset;
}


static const per_sequence_t HandoverCancel_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverCancel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2463 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverCancel");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverCancel, HandoverCancel_sequence);

  return offset;
}


static const per_sequence_t HandoverCancelAcknowledge_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_HandoverCancelAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2465 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "HandoverCancelAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_HandoverCancelAcknowledge, HandoverCancelAcknowledge_sequence);

  return offset;
}


static const per_sequence_t E_RABSetupRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2467 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E-RABSetupRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABSetupRequest, E_RABSetupRequest_sequence);

  return offset;
}


static const per_sequence_t E_RABToBeSetupListBearerSUReq_sequence_of[1] = {
  { &hf_s1ap_E_RABToBeSetupListBearerSUReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_E_RABToBeSetupListBearerSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_E_RABToBeSetupListBearerSUReq, E_RABToBeSetupListBearerSUReq_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t E_RABToBeSetupItemBearerSUReq_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_e_RABlevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RABLevelQoSParameters },
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_nAS_PDU        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_NAS_PDU },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABToBeSetupItemBearerSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABToBeSetupItemBearerSUReq, E_RABToBeSetupItemBearerSUReq_sequence);

  return offset;
}


static const per_sequence_t E_RABSetupResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2469 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E-RABSetupResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABSetupResponse, E_RABSetupResponse_sequence);

  return offset;
}


static const per_sequence_t E_RABSetupListBearerSURes_sequence_of[1] = {
  { &hf_s1ap_E_RABSetupListBearerSURes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_E_RABSetupListBearerSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_E_RABSetupListBearerSURes, E_RABSetupListBearerSURes_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t E_RABSetupItemBearerSURes_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABSetupItemBearerSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABSetupItemBearerSURes, E_RABSetupItemBearerSURes_sequence);

  return offset;
}


static const per_sequence_t E_RABModifyRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABModifyRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2471 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E-RABModifyRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABModifyRequest, E_RABModifyRequest_sequence);

  return offset;
}


static const per_sequence_t E_RABToBeModifiedListBearerModReq_sequence_of[1] = {
  { &hf_s1ap_E_RABToBeModifiedListBearerModReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_E_RABToBeModifiedListBearerModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_E_RABToBeModifiedListBearerModReq, E_RABToBeModifiedListBearerModReq_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t E_RABToBeModifiedItemBearerModReq_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_e_RABLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RABLevelQoSParameters },
  { &hf_s1ap_nAS_PDU        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_NAS_PDU },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABToBeModifiedItemBearerModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABToBeModifiedItemBearerModReq, E_RABToBeModifiedItemBearerModReq_sequence);

  return offset;
}


static const per_sequence_t E_RABModifyResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABModifyResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2473 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E-RABModifyResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABModifyResponse, E_RABModifyResponse_sequence);

  return offset;
}


static const per_sequence_t E_RABModifyListBearerModRes_sequence_of[1] = {
  { &hf_s1ap_E_RABModifyListBearerModRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_E_RABModifyListBearerModRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_E_RABModifyListBearerModRes, E_RABModifyListBearerModRes_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t E_RABModifyItemBearerModRes_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABModifyItemBearerModRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABModifyItemBearerModRes, E_RABModifyItemBearerModRes_sequence);

  return offset;
}


static const per_sequence_t E_RABReleaseCommand_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2475 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E-RABReleaseCommand");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABReleaseCommand, E_RABReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t E_RABReleaseResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABReleaseResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2477 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E-RABReleaseResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABReleaseResponse, E_RABReleaseResponse_sequence);

  return offset;
}


static const per_sequence_t E_RABReleaseListBearerRelComp_sequence_of[1] = {
  { &hf_s1ap_E_RABReleaseListBearerRelComp_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_E_RABReleaseListBearerRelComp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_E_RABReleaseListBearerRelComp, E_RABReleaseListBearerRelComp_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t E_RABReleaseItemBearerRelComp_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABReleaseItemBearerRelComp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABReleaseItemBearerRelComp, E_RABReleaseItemBearerRelComp_sequence);

  return offset;
}


static const per_sequence_t E_RABReleaseIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABReleaseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2479 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "E-RABReleaseIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABReleaseIndication, E_RABReleaseIndication_sequence);

  return offset;
}


static const per_sequence_t InitialContextSetupRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_InitialContextSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2481 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "InitialContextSetupRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_InitialContextSetupRequest, InitialContextSetupRequest_sequence);

  return offset;
}


static const per_sequence_t E_RABToBeSetupListCtxtSUReq_sequence_of[1] = {
  { &hf_s1ap_E_RABToBeSetupListCtxtSUReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_E_RABToBeSetupListCtxtSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_E_RABToBeSetupListCtxtSUReq, E_RABToBeSetupListCtxtSUReq_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t E_RABToBeSetupItemCtxtSUReq_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_e_RABlevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RABLevelQoSParameters },
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_nAS_PDU        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_NAS_PDU },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABToBeSetupItemCtxtSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABToBeSetupItemCtxtSUReq, E_RABToBeSetupItemCtxtSUReq_sequence);

  return offset;
}


static const per_sequence_t InitialContextSetupResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_InitialContextSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2483 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "InitialContextSetupResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_InitialContextSetupResponse, InitialContextSetupResponse_sequence);

  return offset;
}


static const per_sequence_t E_RABSetupListCtxtSURes_sequence_of[1] = {
  { &hf_s1ap_E_RABSetupListCtxtSURes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_E_RABSetupListCtxtSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_E_RABSetupListCtxtSURes, E_RABSetupListCtxtSURes_sequence_of,
                                                  1, maxnoofE_RABs, FALSE);

  return offset;
}


static const per_sequence_t E_RABSetupItemCtxtSURes_sequence[] = {
  { &hf_s1ap_e_RAB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_E_RAB_ID },
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_E_RABSetupItemCtxtSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_E_RABSetupItemCtxtSURes, E_RABSetupItemCtxtSURes_sequence);

  return offset;
}


static const per_sequence_t InitialContextSetupFailure_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_InitialContextSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2485 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "InitialContextSetupFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_InitialContextSetupFailure, InitialContextSetupFailure_sequence);

  return offset;
}


static const per_sequence_t Paging_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_Paging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2487 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Paging");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_Paging, Paging_sequence);

  return offset;
}


static const per_sequence_t TAIList_sequence_of[1] = {
  { &hf_s1ap_TAIList_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TAIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TAIList, TAIList_sequence_of,
                                                  1, maxnoofTAIs, FALSE);

  return offset;
}


static const per_sequence_t TAIItem_sequence[] = {
  { &hf_s1ap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TAIItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TAIItem, TAIItem_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UEContextReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2489 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UEContextReleaseRequest, UEContextReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseCommand_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UEContextReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2491 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseCommand");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UEContextReleaseCommand, UEContextReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t UEContextReleaseComplete_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UEContextReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2493 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextReleaseComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UEContextReleaseComplete, UEContextReleaseComplete_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UEContextModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2495 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UEContextModificationRequest, UEContextModificationRequest_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UEContextModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2497 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UEContextModificationResponse, UEContextModificationResponse_sequence);

  return offset;
}


static const per_sequence_t UEContextModificationFailure_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UEContextModificationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2499 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UEContextModificationFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UEContextModificationFailure, UEContextModificationFailure_sequence);

  return offset;
}


static const per_sequence_t DownlinkNASTransport_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_DownlinkNASTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 354 "./asn1/s1ap/s1ap.cnf"
  /* Set the direction of the message */
  actx->pinfo->link_dir=P2P_DIR_DL;

  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DownlinkNASTransport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_DownlinkNASTransport, DownlinkNASTransport_sequence);

  return offset;
}


static const per_sequence_t InitialUEMessage_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_InitialUEMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 350 "./asn1/s1ap/s1ap.cnf"
  /* Set the direction of the message */
  actx->pinfo->link_dir=P2P_DIR_UL;

  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "InitialUEMessage");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_InitialUEMessage, InitialUEMessage_sequence);

  return offset;
}


static const per_sequence_t UplinkNASTransport_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UplinkNASTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 358 "./asn1/s1ap/s1ap.cnf"
  /* Set the direction of the message */
  actx->pinfo->link_dir=P2P_DIR_UL;

  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UplinkNASTransport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UplinkNASTransport, UplinkNASTransport_sequence);

  return offset;
}


static const per_sequence_t NASNonDeliveryIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_NASNonDeliveryIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2511 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "NASNonDeliveryIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_NASNonDeliveryIndication, NASNonDeliveryIndication_sequence);

  return offset;
}


static const per_sequence_t Reset_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2515 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Reset");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_Reset, Reset_sequence);

  return offset;
}


static const value_string s1ap_ResetAll_vals[] = {
  {   0, "reset-all" },
  { 0, NULL }
};


static int
dissect_s1ap_ResetAll(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_associatedLogicalS1_ConnectionListRes_sequence_of[1] = {
  { &hf_s1ap_UE_associatedLogicalS1_ConnectionListRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_UE_associatedLogicalS1_ConnectionListRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_UE_associatedLogicalS1_ConnectionListRes, UE_associatedLogicalS1_ConnectionListRes_sequence_of,
                                                  1, maxNrOfIndividualS1ConnectionsToReset, FALSE);

  return offset;
}


static const value_string s1ap_ResetType_vals[] = {
  {   0, "s1-Interface" },
  {   1, "partOfS1-Interface" },
  { 0, NULL }
};

static const per_choice_t ResetType_choice[] = {
  {   0, &hf_s1ap_s1_Interface   , ASN1_EXTENSION_ROOT    , dissect_s1ap_ResetAll },
  {   1, &hf_s1ap_partOfS1_Interface, ASN1_EXTENSION_ROOT    , dissect_s1ap_UE_associatedLogicalS1_ConnectionListRes },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_ResetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_ResetType, ResetType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ResetAcknowledge_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ResetAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2517 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ResetAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ResetAcknowledge, ResetAcknowledge_sequence);

  return offset;
}


static const per_sequence_t UE_associatedLogicalS1_ConnectionListResAck_sequence_of[1] = {
  { &hf_s1ap_UE_associatedLogicalS1_ConnectionListResAck_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_UE_associatedLogicalS1_ConnectionListResAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_UE_associatedLogicalS1_ConnectionListResAck, UE_associatedLogicalS1_ConnectionListResAck_sequence_of,
                                                  1, maxNrOfIndividualS1ConnectionsToReset, FALSE);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2519 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ErrorIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t S1SetupRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_S1SetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2521 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "S1SetupRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_S1SetupRequest, S1SetupRequest_sequence);

  return offset;
}


static const per_sequence_t S1SetupResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_S1SetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2523 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "S1SetupResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_S1SetupResponse, S1SetupResponse_sequence);

  return offset;
}


static const per_sequence_t S1SetupFailure_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_S1SetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2525 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "S1SetupFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_S1SetupFailure, S1SetupFailure_sequence);

  return offset;
}


static const per_sequence_t ENBConfigurationUpdate_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ENBConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2527 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ENBConfigurationUpdate");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ENBConfigurationUpdate, ENBConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t ENBConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ENBConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2529 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ENBConfigurationUpdateAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ENBConfigurationUpdateAcknowledge, ENBConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t ENBConfigurationUpdateFailure_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ENBConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2531 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ENBConfigurationUpdateFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ENBConfigurationUpdateFailure, ENBConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t MMEConfigurationUpdate_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_MMEConfigurationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2533 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MMEConfigurationUpdate");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_MMEConfigurationUpdate, MMEConfigurationUpdate_sequence);

  return offset;
}


static const per_sequence_t MMEConfigurationUpdateAcknowledge_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_MMEConfigurationUpdateAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2535 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MMEConfigurationUpdateAcknowledge");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_MMEConfigurationUpdateAcknowledge, MMEConfigurationUpdateAcknowledge_sequence);

  return offset;
}


static const per_sequence_t MMEConfigurationUpdateFailure_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_MMEConfigurationUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2537 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MMEConfigurationUpdateFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_MMEConfigurationUpdateFailure, MMEConfigurationUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t DownlinkS1cdma2000tunneling_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_DownlinkS1cdma2000tunneling(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_DownlinkS1cdma2000tunneling, DownlinkS1cdma2000tunneling_sequence);

  return offset;
}


static const per_sequence_t UplinkS1cdma2000tunneling_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UplinkS1cdma2000tunneling(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UplinkS1cdma2000tunneling, UplinkS1cdma2000tunneling_sequence);

  return offset;
}


static const per_sequence_t UECapabilityInfoIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UECapabilityInfoIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2543 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UECapabilityInfoIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UECapabilityInfoIndication, UECapabilityInfoIndication_sequence);

  return offset;
}


static const per_sequence_t ENBStatusTransfer_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ENBStatusTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2545 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ENBStatusTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ENBStatusTransfer, ENBStatusTransfer_sequence);

  return offset;
}


static const per_sequence_t MMEStatusTransfer_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_MMEStatusTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2547 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MMEStatusTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_MMEStatusTransfer, MMEStatusTransfer_sequence);

  return offset;
}


static const per_sequence_t TraceStart_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TraceStart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2549 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "TraceStart");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TraceStart, TraceStart_sequence);

  return offset;
}


static const per_sequence_t TraceFailureIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TraceFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2551 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "TraceFailureIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TraceFailureIndication, TraceFailureIndication_sequence);

  return offset;
}


static const per_sequence_t DeactivateTrace_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_DeactivateTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2553 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DeactivateTrace");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_DeactivateTrace, DeactivateTrace_sequence);

  return offset;
}


static const per_sequence_t CellTrafficTrace_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_CellTrafficTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2555 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "CellTrafficTrace");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_CellTrafficTrace, CellTrafficTrace_sequence);

  return offset;
}


static const per_sequence_t LocationReportingControl_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_LocationReportingControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2557 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "LocationReportingControl");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_LocationReportingControl, LocationReportingControl_sequence);

  return offset;
}


static const per_sequence_t LocationReportingFailureIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_LocationReportingFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2559 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "LocationReportingFailureIndication");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_LocationReportingFailureIndication, LocationReportingFailureIndication_sequence);

  return offset;
}


static const per_sequence_t LocationReport_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_LocationReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2561 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "LocationReport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_LocationReport, LocationReport_sequence);

  return offset;
}


static const per_sequence_t OverloadStart_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_OverloadStart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2563 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "OverloadStart");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_OverloadStart, OverloadStart_sequence);

  return offset;
}


static const per_sequence_t OverloadStop_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_OverloadStop(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2565 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "OverloadStop");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_OverloadStop, OverloadStop_sequence);

  return offset;
}


static const per_sequence_t WriteReplaceWarningRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_WriteReplaceWarningRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2567 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "WriteReplaceWarningRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_WriteReplaceWarningRequest, WriteReplaceWarningRequest_sequence);

  return offset;
}


static const per_sequence_t WriteReplaceWarningResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_WriteReplaceWarningResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2569 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "WriteReplaceWarningResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_WriteReplaceWarningResponse, WriteReplaceWarningResponse_sequence);

  return offset;
}


static const per_sequence_t ENBDirectInformationTransfer_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ENBDirectInformationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2571 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ENBDirectInformationTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ENBDirectInformationTransfer, ENBDirectInformationTransfer_sequence);

  return offset;
}


static const value_string s1ap_Inter_SystemInformationTransferType_vals[] = {
  {   0, "rIMTransfer" },
  { 0, NULL }
};

static const per_choice_t Inter_SystemInformationTransferType_choice[] = {
  {   0, &hf_s1ap_rIMTransfer    , ASN1_EXTENSION_ROOT    , dissect_s1ap_RIMTransfer },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_Inter_SystemInformationTransferType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_Inter_SystemInformationTransferType, Inter_SystemInformationTransferType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MMEDirectInformationTransfer_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_MMEDirectInformationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2573 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MMEDirectInformationTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_MMEDirectInformationTransfer, MMEDirectInformationTransfer_sequence);

  return offset;
}


static const per_sequence_t ENBConfigurationTransfer_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ENBConfigurationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2575 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "ENBConfigurationTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ENBConfigurationTransfer, ENBConfigurationTransfer_sequence);

  return offset;
}


static const per_sequence_t MMEConfigurationTransfer_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_MMEConfigurationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2577 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MMEConfigurationTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_MMEConfigurationTransfer, MMEConfigurationTransfer_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_s1ap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2579 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "PrivateMessage");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t KillRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_KillRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2581 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "KillRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_KillRequest, KillRequest_sequence);

  return offset;
}


static const per_sequence_t KillResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_KillResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2583 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "KillResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_KillResponse, KillResponse_sequence);

  return offset;
}


static const per_sequence_t DownlinkUEAssociatedLPPaTransport_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_DownlinkUEAssociatedLPPaTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2589 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DownlinkUEAssociatedLPPaTransport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_DownlinkUEAssociatedLPPaTransport, DownlinkUEAssociatedLPPaTransport_sequence);

  return offset;
}


static const per_sequence_t UplinkUEAssociatedLPPaTransport_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UplinkUEAssociatedLPPaTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2591 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UplinkUEAssociatedLPPaTransport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UplinkUEAssociatedLPPaTransport, UplinkUEAssociatedLPPaTransport_sequence);

  return offset;
}


static const per_sequence_t DownlinkNonUEAssociatedLPPaTransport_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_DownlinkNonUEAssociatedLPPaTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2593 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "DownlinkNonUEAssociatedLPPaTransport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_DownlinkNonUEAssociatedLPPaTransport, DownlinkNonUEAssociatedLPPaTransport_sequence);

  return offset;
}


static const per_sequence_t UplinkNonUEAssociatedLPPaTransport_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UplinkNonUEAssociatedLPPaTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 2595 "./asn1/s1ap/s1ap.cnf"
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "UplinkNonUEAssociatedLPPaTransport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UplinkNonUEAssociatedLPPaTransport, UplinkNonUEAssociatedLPPaTransport_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextSetupRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextSetupRequest, GroupCallContextSetupRequest_sequence);

  return offset;
}


static const per_sequence_t TE_RABToBeSetupListGroupCtxtSUReq_sequence_of[1] = {
  { &hf_s1ap_TE_RABToBeSetupListGroupCtxtSUReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TE_RABToBeSetupListGroupCtxtSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TE_RABToBeSetupListGroupCtxtSUReq, TE_RABToBeSetupListGroupCtxtSUReq_sequence_of,
                                                  1, maxNrOfTE_RABs, FALSE);

  return offset;
}


static const per_sequence_t UnicastTransportTypeGroupCtxtSUReq_sequence[] = {
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UnicastTransportTypeGroupCtxtSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UnicastTransportTypeGroupCtxtSUReq, UnicastTransportTypeGroupCtxtSUReq_sequence);

  return offset;
}


static const per_sequence_t MulticastTransportTypeGroupCtxtSUReq_sequence[] = {
  { &hf_s1ap_multiAddress   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_sourceAddress  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_MulticastTransportTypeGroupCtxtSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_MulticastTransportTypeGroupCtxtSUReq, MulticastTransportTypeGroupCtxtSUReq_sequence);

  return offset;
}


static const value_string s1ap_TransportTypeGroupCtxtSUReq_vals[] = {
  {   0, "unicast" },
  {   1, "multicast" },
  { 0, NULL }
};

static const per_choice_t TransportTypeGroupCtxtSUReq_choice[] = {
  {   0, &hf_s1ap_unicast        , ASN1_EXTENSION_ROOT    , dissect_s1ap_UnicastTransportTypeGroupCtxtSUReq },
  {   1, &hf_s1ap_multicast      , ASN1_EXTENSION_ROOT    , dissect_s1ap_MulticastTransportTypeGroupCtxtSUReq },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_TransportTypeGroupCtxtSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_TransportTypeGroupCtxtSUReq, TransportTypeGroupCtxtSUReq_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TE_RABToBeSetupItemGroupCtxtSUReq_sequence[] = {
  { &hf_s1ap_tE_RAB_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RAB_ID },
  { &hf_s1ap_tE_RABlevelQosParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RABLevelQoSParameters },
  { &hf_s1ap_transportType  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportTypeGroupCtxtSUReq },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TE_RABToBeSetupItemGroupCtxtSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TE_RABToBeSetupItemGroupCtxtSUReq, TE_RABToBeSetupItemGroupCtxtSUReq_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextSetupResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextSetupResponse, GroupCallContextSetupResponse_sequence);

  return offset;
}


static const per_sequence_t TE_RABSetupListGroupCtxtSURes_sequence_of[1] = {
  { &hf_s1ap_TE_RABSetupListGroupCtxtSURes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TE_RABSetupListGroupCtxtSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TE_RABSetupListGroupCtxtSURes, TE_RABSetupListGroupCtxtSURes_sequence_of,
                                                  1, maxNrOfTE_RABs, FALSE);

  return offset;
}


static const per_sequence_t UnicastTransportTypeGroupCtxtSURes_sequence[] = {
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UnicastTransportTypeGroupCtxtSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UnicastTransportTypeGroupCtxtSURes, UnicastTransportTypeGroupCtxtSURes_sequence);

  return offset;
}


static const value_string s1ap_TransportTypeGroupCtxtSURes_vals[] = {
  {   0, "unicast" },
  {   1, "multicast" },
  { 0, NULL }
};

static const per_choice_t TransportTypeGroupCtxtSURes_choice[] = {
  {   0, &hf_s1ap_unicast_01     , ASN1_EXTENSION_ROOT    , dissect_s1ap_UnicastTransportTypeGroupCtxtSURes },
  {   1, &hf_s1ap_multicast_01   , ASN1_EXTENSION_ROOT    , dissect_s1ap_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_TransportTypeGroupCtxtSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_TransportTypeGroupCtxtSURes, TransportTypeGroupCtxtSURes_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TE_RABSetupItemGroupCtxtSURes_sequence[] = {
  { &hf_s1ap_tE_RAB_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RAB_ID },
  { &hf_s1ap_transportType_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportTypeGroupCtxtSURes },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TE_RABSetupItemGroupCtxtSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TE_RABSetupItemGroupCtxtSURes, TE_RABSetupItemGroupCtxtSURes_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextSetupFailure_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextSetupFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextSetupFailure, GroupCallContextSetupFailure_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextModificationRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextModificationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextModificationRequest, GroupCallContextModificationRequest_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextModificationResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextModificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextModificationResponse, GroupCallContextModificationResponse_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextReleaseCommand_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextReleaseCommand, GroupCallContextReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextReleaseComplete_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextReleaseComplete, GroupCallContextReleaseComplete_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextReleaseIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextReleaseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextReleaseIndication, GroupCallContextReleaseIndication_sequence);

  return offset;
}


static const per_sequence_t InstantGroupCallConfigNotify_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_InstantGroupCallConfigNotify(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_InstantGroupCallConfigNotify, InstantGroupCallConfigNotify_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextExpansionRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextExpansionRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextExpansionRequest, GroupCallContextExpansionRequest_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextExpansionAccept_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextExpansionAccept(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextExpansionAccept, GroupCallContextExpansionAccept_sequence);

  return offset;
}


static const per_sequence_t GroupCallContextExpansionReject_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupCallContextExpansionReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupCallContextExpansionReject, GroupCallContextExpansionReject_sequence);

  return offset;
}


static const per_sequence_t TrunkingIndividualPaging_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TrunkingIndividualPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TrunkingIndividualPaging, TrunkingIndividualPaging_sequence);

  return offset;
}


static const per_sequence_t ListOfTargetTAIsTrunkingIndividualPaging_sequence_of[1] = {
  { &hf_s1ap_ListOfTargetTAIsTrunkingIndividualPaging_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_ListOfTargetTAIsTrunkingIndividualPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_ListOfTargetTAIsTrunkingIndividualPaging, ListOfTargetTAIsTrunkingIndividualPaging_sequence_of,
                                                  1, maxnoofTAIs, FALSE);

  return offset;
}


static const per_sequence_t ListOfTargetTAIsItemTrunkingIndividualPaging_sequence[] = {
  { &hf_s1ap_tAI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TAI },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ListOfTargetTAIsItemTrunkingIndividualPaging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ListOfTargetTAIsItemTrunkingIndividualPaging, ListOfTargetTAIsItemTrunkingIndividualPaging_sequence);

  return offset;
}


static const per_sequence_t GroupDownlinkNASTransport_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupDownlinkNASTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupDownlinkNASTransport, GroupDownlinkNASTransport_sequence);

  return offset;
}


static const per_sequence_t TrunkingErrorIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TrunkingErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TrunkingErrorIndication, TrunkingErrorIndication_sequence);

  return offset;
}


static const per_sequence_t GroupReset_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupReset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupReset, GroupReset_sequence);

  return offset;
}


static const value_string s1ap_GroupResetAll_vals[] = {
  {   0, "reset-all" },
  { 0, NULL }
};


static int
dissect_s1ap_GroupResetAll(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Group_associatedLogicalS1_ConnectionListGroupReset_sequence_of[1] = {
  { &hf_s1ap_Group_associatedLogicalS1_ConnectionListGroupReset_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_Group_associatedLogicalS1_ConnectionListGroupReset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_Group_associatedLogicalS1_ConnectionListGroupReset, Group_associatedLogicalS1_ConnectionListGroupReset_sequence_of,
                                                  1, maxNrOfIndividualS1GroupConnectionsToReset, FALSE);

  return offset;
}


static const per_sequence_t PartOfS1_TInterfaceGroupReset_sequence[] = {
  { &hf_s1ap_group_associatedLogicalS1_Connection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_Group_associatedLogicalS1_ConnectionListGroupReset },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_PartOfS1_TInterfaceGroupReset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_PartOfS1_TInterfaceGroupReset, PartOfS1_TInterfaceGroupReset_sequence);

  return offset;
}


static const value_string s1ap_GroupResetType_vals[] = {
  {   0, "s1-TInterface" },
  {   1, "partOfS1-TInterface" },
  { 0, NULL }
};

static const per_choice_t GroupResetType_choice[] = {
  {   0, &hf_s1ap_s1_TInterface  , ASN1_EXTENSION_ROOT    , dissect_s1ap_GroupResetAll },
  {   1, &hf_s1ap_partOfS1_TInterface, ASN1_EXTENSION_ROOT    , dissect_s1ap_PartOfS1_TInterfaceGroupReset },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_GroupResetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_GroupResetType, GroupResetType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Group_associatedLogicalS1_ConnectionItemGroupReset_sequence[] = {
  { &hf_s1ap_mME_Group_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_MME_Group_S1AP_ID },
  { &hf_s1ap_eNB_Group_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ENB_Group_S1AP_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_Group_associatedLogicalS1_ConnectionItemGroupReset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_Group_associatedLogicalS1_ConnectionItemGroupReset, Group_associatedLogicalS1_ConnectionItemGroupReset_sequence);

  return offset;
}


static const per_sequence_t GroupResetAcknowledge_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupResetAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupResetAcknowledge, GroupResetAcknowledge_sequence);

  return offset;
}


static const per_sequence_t Group_associatedLogicalS1_ConnectionListGroupResetAck_sequence_of[1] = {
  { &hf_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck, Group_associatedLogicalS1_ConnectionListGroupResetAck_sequence_of,
                                                  1, maxNrOfIndividualS1GroupConnectionsToReset, FALSE);

  return offset;
}


static const per_sequence_t Group_associatedLogicalS1_ConnectionItemGroupResetAck_sequence[] = {
  { &hf_s1ap_mME_Group_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_MME_Group_S1AP_ID },
  { &hf_s1ap_eNB_Group_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ENB_Group_S1AP_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_Group_associatedLogicalS1_ConnectionItemGroupResetAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_Group_associatedLogicalS1_ConnectionItemGroupResetAck, Group_associatedLogicalS1_ConnectionItemGroupResetAck_sequence);

  return offset;
}


static const per_sequence_t GroupTE_RABSetupRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupTE_RABSetupRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupTE_RABSetupRequest, GroupTE_RABSetupRequest_sequence);

  return offset;
}


static const per_sequence_t TE_RABToBeSetupListGroupBearerSUReq_sequence_of[1] = {
  { &hf_s1ap_TE_RABToBeSetupListGroupBearerSUReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TE_RABToBeSetupListGroupBearerSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TE_RABToBeSetupListGroupBearerSUReq, TE_RABToBeSetupListGroupBearerSUReq_sequence_of,
                                                  1, maxNrOfTE_RABs, FALSE);

  return offset;
}


static const per_sequence_t UnicastTransportTypeGroupBearerSUReq_sequence[] = {
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UnicastTransportTypeGroupBearerSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UnicastTransportTypeGroupBearerSUReq, UnicastTransportTypeGroupBearerSUReq_sequence);

  return offset;
}


static const per_sequence_t MulticastTransportTypeGroupBearerSUReq_sequence[] = {
  { &hf_s1ap_multiAddress   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_sourceAddress  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_MulticastTransportTypeGroupBearerSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_MulticastTransportTypeGroupBearerSUReq, MulticastTransportTypeGroupBearerSUReq_sequence);

  return offset;
}


static const value_string s1ap_TransportTypeGroupBearerSUReq_vals[] = {
  {   0, "unicast" },
  {   1, "multicast" },
  { 0, NULL }
};

static const per_choice_t TransportTypeGroupBearerSUReq_choice[] = {
  {   0, &hf_s1ap_unicast_02     , ASN1_EXTENSION_ROOT    , dissect_s1ap_UnicastTransportTypeGroupBearerSUReq },
  {   1, &hf_s1ap_multicast_02   , ASN1_EXTENSION_ROOT    , dissect_s1ap_MulticastTransportTypeGroupBearerSUReq },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_TransportTypeGroupBearerSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_TransportTypeGroupBearerSUReq, TransportTypeGroupBearerSUReq_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TE_RABToBeSetupItemGroupBearerSUReq_sequence[] = {
  { &hf_s1ap_tE_RAB_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RAB_ID },
  { &hf_s1ap_tE_RABlevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RABLevelQoSParameters },
  { &hf_s1ap_transportType_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportTypeGroupBearerSUReq },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TE_RABToBeSetupItemGroupBearerSUReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TE_RABToBeSetupItemGroupBearerSUReq, TE_RABToBeSetupItemGroupBearerSUReq_sequence);

  return offset;
}


static const per_sequence_t GroupTE_RABSetupResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupTE_RABSetupResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupTE_RABSetupResponse, GroupTE_RABSetupResponse_sequence);

  return offset;
}


static const per_sequence_t TE_RABSetupListGroupBearerSURes_sequence_of[1] = {
  { &hf_s1ap_TE_RABSetupListGroupBearerSURes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TE_RABSetupListGroupBearerSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TE_RABSetupListGroupBearerSURes, TE_RABSetupListGroupBearerSURes_sequence_of,
                                                  1, maxNrOfTE_RABs, FALSE);

  return offset;
}


static const per_sequence_t UnicastTransportTypeGroupBearerSURes_sequence[] = {
  { &hf_s1ap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportLayerAddress },
  { &hf_s1ap_gTP_TEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_GTP_TEID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UnicastTransportTypeGroupBearerSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UnicastTransportTypeGroupBearerSURes, UnicastTransportTypeGroupBearerSURes_sequence);

  return offset;
}


static const value_string s1ap_TransportTypeGroupBearerSURes_vals[] = {
  {   0, "unicast" },
  {   1, "multicast" },
  { 0, NULL }
};

static const per_choice_t TransportTypeGroupBearerSURes_choice[] = {
  {   0, &hf_s1ap_unicast_03     , ASN1_EXTENSION_ROOT    , dissect_s1ap_UnicastTransportTypeGroupBearerSURes },
  {   1, &hf_s1ap_multicast_01   , ASN1_EXTENSION_ROOT    , dissect_s1ap_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_TransportTypeGroupBearerSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_TransportTypeGroupBearerSURes, TransportTypeGroupBearerSURes_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TE_RABSetupItemGroupBearerSURes_sequence[] = {
  { &hf_s1ap_tE_RAB_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RAB_ID },
  { &hf_s1ap_transportType_03, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TransportTypeGroupBearerSURes },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TE_RABSetupItemGroupBearerSURes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TE_RABSetupItemGroupBearerSURes, TE_RABSetupItemGroupBearerSURes_sequence);

  return offset;
}


static const per_sequence_t GroupTE_RABModifyRequest_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupTE_RABModifyRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupTE_RABModifyRequest, GroupTE_RABModifyRequest_sequence);

  return offset;
}


static const per_sequence_t TE_RABToBeModifiedListGroupBearerModReq_sequence_of[1] = {
  { &hf_s1ap_TE_RABToBeModifiedListGroupBearerModReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TE_RABToBeModifiedListGroupBearerModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TE_RABToBeModifiedListGroupBearerModReq, TE_RABToBeModifiedListGroupBearerModReq_sequence_of,
                                                  1, maxNrOfTE_RABs, FALSE);

  return offset;
}


static const per_sequence_t TE_RABToBeModifiedItemGroupBearerModReq_sequence[] = {
  { &hf_s1ap_tE_RAB_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RAB_ID },
  { &hf_s1ap_tE_RABLevelQoSParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RABLevelQoSParameters },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TE_RABToBeModifiedItemGroupBearerModReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TE_RABToBeModifiedItemGroupBearerModReq, TE_RABToBeModifiedItemGroupBearerModReq_sequence);

  return offset;
}


static const per_sequence_t GroupTE_RABModifyResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupTE_RABModifyResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupTE_RABModifyResponse, GroupTE_RABModifyResponse_sequence);

  return offset;
}


static const per_sequence_t TE_RABModifyListGroupBearerModRes_sequence_of[1] = {
  { &hf_s1ap_TE_RABModifyListGroupBearerModRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TE_RABModifyListGroupBearerModRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TE_RABModifyListGroupBearerModRes, TE_RABModifyListGroupBearerModRes_sequence_of,
                                                  1, maxNrOfTE_RABs, FALSE);

  return offset;
}


static const per_sequence_t TE_RABModifyItemGroupBearerModRes_sequence[] = {
  { &hf_s1ap_tE_RAB_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RAB_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TE_RABModifyItemGroupBearerModRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TE_RABModifyItemGroupBearerModRes, TE_RABModifyItemGroupBearerModRes_sequence);

  return offset;
}


static const per_sequence_t GroupTE_RABReleaseCommand_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupTE_RABReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupTE_RABReleaseCommand, GroupTE_RABReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t GroupTE_RABReleaseResponse_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupTE_RABReleaseResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupTE_RABReleaseResponse, GroupTE_RABReleaseResponse_sequence);

  return offset;
}


static const per_sequence_t TE_RABReleaseListGroupBearerRelRes_sequence_of[1] = {
  { &hf_s1ap_TE_RABReleaseListGroupBearerRelRes_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_SingleContainer },
};

static int
dissect_s1ap_TE_RABReleaseListGroupBearerRelRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_s1ap_TE_RABReleaseListGroupBearerRelRes, TE_RABReleaseListGroupBearerRelRes_sequence_of,
                                                  1, maxNrOfTE_RABs, FALSE);

  return offset;
}


static const per_sequence_t TE_RABReleaseItemGroupBearerRelRes_sequence[] = {
  { &hf_s1ap_tE_RAB_ID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_TE_RAB_ID },
  { &hf_s1ap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_s1ap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TE_RABReleaseItemGroupBearerRelRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TE_RABReleaseItemGroupBearerRelRes, TE_RABReleaseItemGroupBearerRelRes_sequence);

  return offset;
}


static const per_sequence_t GroupTE_RABReleaseIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_GroupTE_RABReleaseIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_GroupTE_RABReleaseIndication, GroupTE_RABReleaseIndication_sequence);

  return offset;
}


static const per_sequence_t TrunkingMessageTransport_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TrunkingMessageTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TrunkingMessageTransport, TrunkingMessageTransport_sequence);

  return offset;
}


static const per_sequence_t TrunkingServingCellUpdateIndication_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_TrunkingServingCellUpdateIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_TrunkingServingCellUpdateIndication, TrunkingServingCellUpdateIndication_sequence);

  return offset;
}


static const per_sequence_t ENBGroupCallConfigurationTransfer_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_ENBGroupCallConfigurationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_ENBGroupCallConfigurationTransfer, ENBGroupCallConfigurationTransfer_sequence);

  return offset;
}


static const per_sequence_t MMEGroupCallConfigurationTransfer_sequence[] = {
  { &hf_s1ap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_s1ap_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_MMEGroupCallConfigurationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_MMEGroupCallConfigurationTransfer, MMEGroupCallConfigurationTransfer_sequence);

  return offset;
}



static int
dissect_s1ap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 142 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  s1ap_data->message_type = INITIATING_MESSAGE;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_s1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProcedureCode },
  { &hf_s1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_Criticality },
  { &hf_s1ap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_s1ap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 146 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  s1ap_data->message_type = SUCCESSFUL_OUTCOME;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_s1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProcedureCode },
  { &hf_s1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_Criticality },
  { &hf_s1ap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_s1ap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 150 "./asn1/s1ap/s1ap.cnf"
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(actx->pinfo);
  s1ap_data->message_type = UNSUCCESSFUL_OUTCOME;




  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_s1ap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_ProcedureCode },
  { &hf_s1ap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_Criticality },
  { &hf_s1ap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_s1ap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_s1ap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_s1ap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string s1ap_S1AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t S1AP_PDU_choice[] = {
  {   0, &hf_s1ap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_s1ap_InitiatingMessage },
  {   1, &hf_s1ap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_s1ap_SuccessfulOutcome },
  {   2, &hf_s1ap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_s1ap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_s1ap_S1AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_s1ap_S1AP_PDU, S1AP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AddModGroupCallConfigurationItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_AddModGroupCallConfigurationItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_AddModGroupCallConfigurationItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMROverPDCPIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_AMROverPDCPIndicator(tvb, offset, &asn1_ctx, tree, hf_s1ap_AMROverPDCPIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AMROverPDCPCapablityIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_AMROverPDCPCapablityIndicator(tvb, offset, &asn1_ctx, tree, hf_s1ap_AMROverPDCPCapablityIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Bearers_SubjectToStatusTransfer_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Bearers_SubjectToStatusTransfer_Item(tvb, offset, &asn1_ctx, tree, hf_s1ap_Bearers_SubjectToStatusTransfer_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BroadcastCancelledAreaList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_BroadcastCancelledAreaList(tvb, offset, &asn1_ctx, tree, hf_s1ap_BroadcastCancelledAreaList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BroadcastCompletedAreaList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_BroadcastCompletedAreaList(tvb, offset, &asn1_ctx, tree, hf_s1ap_BroadcastCompletedAreaList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Cause(tvb, offset, &asn1_ctx, tree, hf_s1ap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CallPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CallPriority(tvb, offset, &asn1_ctx, tree, hf_s1ap_CallPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CallSequence_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CallSequence(tvb, offset, &asn1_ctx, tree, hf_s1ap_CallSequence_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellAccessMode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CellAccessMode(tvb, offset, &asn1_ctx, tree, hf_s1ap_CellAccessMode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cdma2000PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Cdma2000PDU(tvb, offset, &asn1_ctx, tree, hf_s1ap_Cdma2000PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cdma2000RATType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Cdma2000RATType(tvb, offset, &asn1_ctx, tree, hf_s1ap_Cdma2000RATType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cdma2000SectorID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Cdma2000SectorID(tvb, offset, &asn1_ctx, tree, hf_s1ap_Cdma2000SectorID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cdma2000HOStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Cdma2000HOStatus(tvb, offset, &asn1_ctx, tree, hf_s1ap_Cdma2000HOStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cdma2000HORequiredIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Cdma2000HORequiredIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_Cdma2000HORequiredIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cdma2000OneXSRVCCInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Cdma2000OneXSRVCCInfo(tvb, offset, &asn1_ctx, tree, hf_s1ap_Cdma2000OneXSRVCCInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cdma2000OneXRAND_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Cdma2000OneXRAND(tvb, offset, &asn1_ctx, tree, hf_s1ap_Cdma2000OneXRAND_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNDomain_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CNDomain(tvb, offset, &asn1_ctx, tree, hf_s1ap_CNDomain_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ConcurrentWarningMessageIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ConcurrentWarningMessageIndicator(tvb, offset, &asn1_ctx, tree, hf_s1ap_ConcurrentWarningMessageIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSFallbackIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CSFallbackIndicator(tvb, offset, &asn1_ctx, tree, hf_s1ap_CSFallbackIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_Id_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CSG_Id(tvb, offset, &asn1_ctx, tree, hf_s1ap_CSG_Id_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_IdList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CSG_IdList(tvb, offset, &asn1_ctx, tree, hf_s1ap_CSG_IdList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSGMembershipStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CSGMembershipStatus(tvb, offset, &asn1_ctx, tree, hf_s1ap_CSGMembershipStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_s1ap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataCodingScheme_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_DataCodingScheme(tvb, offset, &asn1_ctx, tree, hf_s1ap_DataCodingScheme_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Direct_Forwarding_Path_Availability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Direct_Forwarding_Path_Availability(tvb, offset, &asn1_ctx, tree, hf_s1ap_Direct_Forwarding_Path_Availability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Data_Forwarding_Not_Possible_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Data_Forwarding_Not_Possible(tvb, offset, &asn1_ctx, tree, hf_s1ap_Data_Forwarding_Not_Possible_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_s1ap_Global_ENB_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Global_ENB_ID(tvb, offset, &asn1_ctx, tree, hf_s1ap_s1ap_Global_ENB_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_s1ap_ENB_StatusTransfer_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ENB_StatusTransfer_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_s1ap_s1ap_ENB_StatusTransfer_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENB_UE_S1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ENB_UE_S1AP_ID(tvb, offset, &asn1_ctx, tree, hf_s1ap_ENB_UE_S1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBname_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ENBname(tvb, offset, &asn1_ctx, tree, hf_s1ap_ENBname_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABInformationListItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABInformationListItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABInformationListItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABList(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_s1ap_EUTRAN_CGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_EUTRAN_CGI(tvb, offset, &asn1_ctx, tree, hf_s1ap_s1ap_EUTRAN_CGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EUTRANRoundTripDelayEstimationInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_EUTRANRoundTripDelayEstimationInfo(tvb, offset, &asn1_ctx, tree, hf_s1ap_EUTRANRoundTripDelayEstimationInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedRepetitionPeriod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ExtendedRepetitionPeriod(tvb, offset, &asn1_ctx, tree, hf_s1ap_ExtendedRepetitionPeriod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Group_S1AP_IDs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Group_S1AP_IDs(tvb, offset, &asn1_ctx, tree, hf_s1ap_Group_S1AP_IDs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupIdentity(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TAIListItemGroupServiceArea_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TAIListItemGroupServiceArea(tvb, offset, &asn1_ctx, tree, hf_s1ap_TAIListItemGroupServiceArea_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellListItemGroupServiceArea_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CellListItemGroupServiceArea(tvb, offset, &asn1_ctx, tree, hf_s1ap_CellListItemGroupServiceArea_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupConfigurationContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupConfigurationContainer(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupConfigurationContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupConfigurationContainerItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupConfigurationContainerItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupConfigurationContainerItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupAggregateMaximumBitrate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupAggregateMaximumBitrate(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupAggregateMaximumBitrate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MME_Group_S1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MME_Group_S1AP_ID(tvb, offset, &asn1_ctx, tree, hf_s1ap_MME_Group_S1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReleaseGroupCallConfigurationItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ReleaseGroupCallConfigurationItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_ReleaseGroupCallConfigurationItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GUMMEI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GUMMEI(tvb, offset, &asn1_ctx, tree, hf_s1ap_GUMMEI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_s1ap_HandoverRestrictionList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverRestrictionList(tvb, offset, &asn1_ctx, tree, hf_s1ap_s1ap_HandoverRestrictionList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverType(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_LAI(tvb, offset, &asn1_ctx, tree, hf_s1ap_LAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_s1ap_LastVisitedEUTRANCellInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_LastVisitedEUTRANCellInformation(tvb, offset, &asn1_ctx, tree, hf_s1ap_s1ap_LastVisitedEUTRANCellInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_s1ap_LastVisitedGERANCellInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_LastVisitedGERANCellInformation(tvb, offset, &asn1_ctx, tree, hf_s1ap_s1ap_LastVisitedGERANCellInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LPPa_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_LPPa_PDU(tvb, offset, &asn1_ctx, tree, hf_s1ap_LPPa_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MessageIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MessageIdentifier(tvb, offset, &asn1_ctx, tree, hf_s1ap_MessageIdentifier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MMEname_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MMEname(tvb, offset, &asn1_ctx, tree, hf_s1ap_MMEname_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MME_UE_S1AP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MME_UE_S1AP_ID(tvb, offset, &asn1_ctx, tree, hf_s1ap_MME_UE_S1AP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MSClassmark2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MSClassmark2(tvb, offset, &asn1_ctx, tree, hf_s1ap_MSClassmark2_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MSClassmark3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MSClassmark3(tvb, offset, &asn1_ctx, tree, hf_s1ap_MSClassmark3_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NAS_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_NAS_PDU(tvb, offset, &asn1_ctx, tree, hf_s1ap_NAS_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NASSecurityParametersfromE_UTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_NASSecurityParametersfromE_UTRAN(tvb, offset, &asn1_ctx, tree, hf_s1ap_NASSecurityParametersfromE_UTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NASSecurityParameterstoE_UTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_NASSecurityParameterstoE_UTRAN(tvb, offset, &asn1_ctx, tree, hf_s1ap_NASSecurityParameterstoE_UTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NumberofBroadcastRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_NumberofBroadcastRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_NumberofBroadcastRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OverloadResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_OverloadResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_OverloadResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingDRX_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_PagingDRX(tvb, offset, &asn1_ctx, tree, hf_s1ap_PagingDRX_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PS_ServiceNotAvailable_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_PS_ServiceNotAvailable(tvb, offset, &asn1_ctx, tree, hf_s1ap_PS_ServiceNotAvailable_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NAS_PDUType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_NAS_PDUType(tvb, offset, &asn1_ctx, tree, hf_s1ap_NAS_PDUType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NeedResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_NeedResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_NeedResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelativeMMECapacity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_RelativeMMECapacity(tvb, offset, &asn1_ctx, tree, hf_s1ap_RelativeMMECapacity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_RequestType(tvb, offset, &asn1_ctx, tree, hf_s1ap_RequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RepetitionPeriod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_RepetitionPeriod(tvb, offset, &asn1_ctx, tree, hf_s1ap_RepetitionPeriod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRC_Establishment_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_RRC_Establishment_Cause(tvb, offset, &asn1_ctx, tree, hf_s1ap_RRC_Establishment_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Routing_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Routing_ID(tvb, offset, &asn1_ctx, tree, hf_s1ap_Routing_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SecurityKey(tvb, offset, &asn1_ctx, tree, hf_s1ap_SecurityKey_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityContext_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SecurityContext(tvb, offset, &asn1_ctx, tree, hf_s1ap_SecurityContext_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SerialNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SerialNumber(tvb, offset, &asn1_ctx, tree, hf_s1ap_SerialNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SONConfigurationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SONConfigurationTransfer(tvb, offset, &asn1_ctx, tree, hf_s1ap_SONConfigurationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Source_ToTarget_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Source_ToTarget_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_s1ap_Source_ToTarget_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCCOperationPossible_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SRVCCOperationPossible(tvb, offset, &asn1_ctx, tree, hf_s1ap_SRVCCOperationPossible_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCCHOIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SRVCCHOIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_SRVCCHOIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_s1ap_SourceeNB_ToTargeteNB_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SourceeNB_ToTargeteNB_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_s1ap_s1ap_SourceeNB_ToTargeteNB_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SourceeNB_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SourceeNB_List(tvb, offset, &asn1_ctx, tree, hf_s1ap_SourceeNB_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SourceeNB_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SourceeNB_Item(tvb, offset, &asn1_ctx, tree, hf_s1ap_SourceeNB_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedGUMMEIs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ServedGUMMEIs(tvb, offset, &asn1_ctx, tree, hf_s1ap_ServedGUMMEIs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ServedPLMNs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ServedPLMNs(tvb, offset, &asn1_ctx, tree, hf_s1ap_ServedPLMNs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SubscriberProfileIDforRFP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SubscriberProfileIDforRFP(tvb, offset, &asn1_ctx, tree, hf_s1ap_SubscriberProfileIDforRFP_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SupportedTAs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_SupportedTAs(tvb, offset, &asn1_ctx, tree, hf_s1ap_SupportedTAs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_S_TMSI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_S_TMSI(tvb, offset, &asn1_ctx, tree, hf_s1ap_S_TMSI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TAI(tvb, offset, &asn1_ctx, tree, hf_s1ap_TAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargetID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TargetID(tvb, offset, &asn1_ctx, tree, hf_s1ap_TargetID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TrunkingUserIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TrunkingUserIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_TrunkingUserIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargeteNB_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TargeteNB_List(tvb, offset, &asn1_ctx, tree, hf_s1ap_TargeteNB_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargeteNB_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TargeteNB_Item(tvb, offset, &asn1_ctx, tree, hf_s1ap_TargeteNB_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_s1ap_TargeteNB_ToSourceeNB_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TargeteNB_ToSourceeNB_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_s1ap_s1ap_TargeteNB_ToSourceeNB_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Target_ToSource_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Target_ToSource_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_s1ap_Target_ToSource_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToWait_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TimeToWait(tvb, offset, &asn1_ctx, tree, hf_s1ap_TimeToWait_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransportLayerAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TransportLayerAddress(tvb, offset, &asn1_ctx, tree, hf_s1ap_TransportLayerAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TraceActivation(tvb, offset, &asn1_ctx, tree, hf_s1ap_TraceActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_UTRAN_Trace_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_UTRAN_Trace_ID(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_UTRAN_Trace_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEAggregateMaximumBitrate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UEAggregateMaximumBitrate(tvb, offset, &asn1_ctx, tree, hf_s1ap_UEAggregateMaximumBitrate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_S1AP_IDs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UE_S1AP_IDs(tvb, offset, &asn1_ctx, tree, hf_s1ap_UE_S1AP_IDs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalS1_ConnectionItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UE_associatedLogicalS1_ConnectionItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_UE_associatedLogicalS1_ConnectionItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEIdentityIndexValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UEIdentityIndexValue(tvb, offset, &asn1_ctx, tree, hf_s1ap_UEIdentityIndexValue_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_s1ap_UE_HistoryInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UE_HistoryInformation(tvb, offset, &asn1_ctx, tree, hf_s1ap_s1ap_UE_HistoryInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEPagingID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UEPagingID(tvb, offset, &asn1_ctx, tree, hf_s1ap_UEPagingID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERadioCapability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UERadioCapability(tvb, offset, &asn1_ctx, tree, hf_s1ap_UERadioCapability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UESecurityCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UESecurityCapabilities(tvb, offset, &asn1_ctx, tree, hf_s1ap_UESecurityCapabilities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningAreaList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_WarningAreaList(tvb, offset, &asn1_ctx, tree, hf_s1ap_WarningAreaList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_WarningType(tvb, offset, &asn1_ctx, tree, hf_s1ap_WarningType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningSecurityInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_WarningSecurityInfo(tvb, offset, &asn1_ctx, tree, hf_s1ap_WarningSecurityInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WarningMessageContents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_WarningMessageContents(tvb, offset, &asn1_ctx, tree, hf_s1ap_WarningMessageContents_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverRequired(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverCommand(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABSubjecttoDataForwardingList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABSubjecttoDataForwardingList(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABSubjecttoDataForwardingList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABDataForwardingItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABDataForwardingItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABDataForwardingItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverPreparationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverPreparationFailure(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverPreparationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSetupListHOReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSetupListHOReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSetupListHOReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSetupItemHOReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSetupItemHOReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSetupItemHOReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABAdmittedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABAdmittedList(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABAdmittedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABAdmittedItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABAdmittedItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABAdmittedItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABFailedtoSetupListHOReqAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABFailedtoSetupListHOReqAck(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABFailedtoSetupListHOReqAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABFailedToSetupItemHOReqAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABFailedToSetupItemHOReqAck(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABFailedToSetupItemHOReqAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverFailure(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverNotify_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverNotify(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverNotify_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_PathSwitchRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_PathSwitchRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSwitchedDLList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSwitchedDLList(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSwitchedDLList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSwitchedDLItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSwitchedDLItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSwitchedDLItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_PathSwitchRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_s1ap_PathSwitchRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSwitchedULList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSwitchedULList(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSwitchedULList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSwitchedULItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSwitchedULItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSwitchedULItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PathSwitchRequestFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_PathSwitchRequestFailure(tvb, offset, &asn1_ctx, tree, hf_s1ap_PathSwitchRequestFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCancel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverCancel(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverCancel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HandoverCancelAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_HandoverCancelAcknowledge(tvb, offset, &asn1_ctx, tree, hf_s1ap_HandoverCancelAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABSetupRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSetupListBearerSUReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSetupListBearerSUReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSetupListBearerSUReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSetupItemBearerSUReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSetupItemBearerSUReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSetupItemBearerSUReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABSetupResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABSetupListBearerSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABSetupListBearerSURes(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABSetupListBearerSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABSetupItemBearerSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABSetupItemBearerSURes(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABSetupItemBearerSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABModifyRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABModifyRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABModifyRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeModifiedListBearerModReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeModifiedListBearerModReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeModifiedListBearerModReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeModifiedItemBearerModReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeModifiedItemBearerModReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeModifiedItemBearerModReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABModifyResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABModifyResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABModifyResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABModifyListBearerModRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABModifyListBearerModRes(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABModifyListBearerModRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABModifyItemBearerModRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABModifyItemBearerModRes(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABModifyItemBearerModRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABReleaseResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABReleaseResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABReleaseResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABReleaseListBearerRelComp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABReleaseListBearerRelComp(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABReleaseListBearerRelComp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABReleaseItemBearerRelComp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABReleaseItemBearerRelComp(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABReleaseItemBearerRelComp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABReleaseIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABReleaseIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABReleaseIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_InitialContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_InitialContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSetupListCtxtSUReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSetupListCtxtSUReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSetupListCtxtSUReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABToBeSetupItemCtxtSUReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABToBeSetupItemCtxtSUReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABToBeSetupItemCtxtSUReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_InitialContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_InitialContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABSetupListCtxtSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABSetupListCtxtSURes(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABSetupListCtxtSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_RABSetupItemCtxtSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_E_RABSetupItemCtxtSURes(tvb, offset, &asn1_ctx, tree, hf_s1ap_E_RABSetupItemCtxtSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialContextSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_InitialContextSetupFailure(tvb, offset, &asn1_ctx, tree, hf_s1ap_InitialContextSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Paging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Paging(tvb, offset, &asn1_ctx, tree, hf_s1ap_Paging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TAIList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TAIList(tvb, offset, &asn1_ctx, tree, hf_s1ap_TAIList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TAIItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TAIItem(tvb, offset, &asn1_ctx, tree, hf_s1ap_TAIItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UEContextReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_UEContextReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UEContextReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_s1ap_UEContextReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UEContextReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_s1ap_UEContextReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UEContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_UEContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UEContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_UEContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEContextModificationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UEContextModificationFailure(tvb, offset, &asn1_ctx, tree, hf_s1ap_UEContextModificationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DownlinkNASTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_DownlinkNASTransport(tvb, offset, &asn1_ctx, tree, hf_s1ap_DownlinkNASTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialUEMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_InitialUEMessage(tvb, offset, &asn1_ctx, tree, hf_s1ap_InitialUEMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkNASTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UplinkNASTransport(tvb, offset, &asn1_ctx, tree, hf_s1ap_UplinkNASTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NASNonDeliveryIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_NASNonDeliveryIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_NASNonDeliveryIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Reset(tvb, offset, &asn1_ctx, tree, hf_s1ap_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ResetType(tvb, offset, &asn1_ctx, tree, hf_s1ap_ResetType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ResetAcknowledge(tvb, offset, &asn1_ctx, tree, hf_s1ap_ResetAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_associatedLogicalS1_ConnectionListResAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UE_associatedLogicalS1_ConnectionListResAck(tvb, offset, &asn1_ctx, tree, hf_s1ap_UE_associatedLogicalS1_ConnectionListResAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_S1SetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_S1SetupRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_S1SetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_S1SetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_S1SetupResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_S1SetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_S1SetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_S1SetupFailure(tvb, offset, &asn1_ctx, tree, hf_s1ap_S1SetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ENBConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_s1ap_ENBConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ENBConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_s1ap_ENBConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ENBConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_s1ap_ENBConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MMEConfigurationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MMEConfigurationUpdate(tvb, offset, &asn1_ctx, tree, hf_s1ap_MMEConfigurationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MMEConfigurationUpdateAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MMEConfigurationUpdateAcknowledge(tvb, offset, &asn1_ctx, tree, hf_s1ap_MMEConfigurationUpdateAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MMEConfigurationUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MMEConfigurationUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_s1ap_MMEConfigurationUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UECapabilityInfoIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UECapabilityInfoIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_UECapabilityInfoIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBStatusTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ENBStatusTransfer(tvb, offset, &asn1_ctx, tree, hf_s1ap_ENBStatusTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MMEStatusTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MMEStatusTransfer(tvb, offset, &asn1_ctx, tree, hf_s1ap_MMEStatusTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceStart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TraceStart(tvb, offset, &asn1_ctx, tree, hf_s1ap_TraceStart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TraceFailureIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_TraceFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DeactivateTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_DeactivateTrace(tvb, offset, &asn1_ctx, tree, hf_s1ap_DeactivateTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellTrafficTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_CellTrafficTrace(tvb, offset, &asn1_ctx, tree, hf_s1ap_CellTrafficTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReportingControl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_LocationReportingControl(tvb, offset, &asn1_ctx, tree, hf_s1ap_LocationReportingControl_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReportingFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_LocationReportingFailureIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_LocationReportingFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_LocationReport(tvb, offset, &asn1_ctx, tree, hf_s1ap_LocationReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OverloadStart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_OverloadStart(tvb, offset, &asn1_ctx, tree, hf_s1ap_OverloadStart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OverloadStop_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_OverloadStop(tvb, offset, &asn1_ctx, tree, hf_s1ap_OverloadStop_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WriteReplaceWarningRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_WriteReplaceWarningRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_WriteReplaceWarningRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WriteReplaceWarningResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_WriteReplaceWarningResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_WriteReplaceWarningResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBDirectInformationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ENBDirectInformationTransfer(tvb, offset, &asn1_ctx, tree, hf_s1ap_ENBDirectInformationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Inter_SystemInformationTransferType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Inter_SystemInformationTransferType(tvb, offset, &asn1_ctx, tree, hf_s1ap_Inter_SystemInformationTransferType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MMEDirectInformationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MMEDirectInformationTransfer(tvb, offset, &asn1_ctx, tree, hf_s1ap_MMEDirectInformationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ENBConfigurationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ENBConfigurationTransfer(tvb, offset, &asn1_ctx, tree, hf_s1ap_ENBConfigurationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MMEConfigurationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MMEConfigurationTransfer(tvb, offset, &asn1_ctx, tree, hf_s1ap_MMEConfigurationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_s1ap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_KillRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_KillRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_KillRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_KillResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_KillResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_KillResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DownlinkUEAssociatedLPPaTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_DownlinkUEAssociatedLPPaTransport(tvb, offset, &asn1_ctx, tree, hf_s1ap_DownlinkUEAssociatedLPPaTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkUEAssociatedLPPaTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UplinkUEAssociatedLPPaTransport(tvb, offset, &asn1_ctx, tree, hf_s1ap_UplinkUEAssociatedLPPaTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DownlinkNonUEAssociatedLPPaTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_DownlinkNonUEAssociatedLPPaTransport(tvb, offset, &asn1_ctx, tree, hf_s1ap_DownlinkNonUEAssociatedLPPaTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkNonUEAssociatedLPPaTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_UplinkNonUEAssociatedLPPaTransport(tvb, offset, &asn1_ctx, tree, hf_s1ap_UplinkNonUEAssociatedLPPaTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupCallContextSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupCallContextSetupRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupCallContextSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABToBeSetupListGroupCtxtSUReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABToBeSetupListGroupCtxtSUReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABToBeSetupListGroupCtxtSUReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABToBeSetupItemGroupCtxtSUReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABToBeSetupItemGroupCtxtSUReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABToBeSetupItemGroupCtxtSUReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupCallContextSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupCallContextSetupResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupCallContextSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABSetupListGroupCtxtSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABSetupListGroupCtxtSURes(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABSetupListGroupCtxtSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABSetupItemGroupCtxtSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABSetupItemGroupCtxtSURes(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABSetupItemGroupCtxtSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupCallContextSetupFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupCallContextSetupFailure(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupCallContextSetupFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupCallContextModificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupCallContextModificationRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupCallContextModificationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupCallContextModificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupCallContextModificationResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupCallContextModificationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupCallContextReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupCallContextReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupCallContextReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupCallContextReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupCallContextReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupCallContextReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupCallContextReleaseIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupCallContextReleaseIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupCallContextReleaseIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InstantGroupCallConfigNotify_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_InstantGroupCallConfigNotify(tvb, offset, &asn1_ctx, tree, hf_s1ap_InstantGroupCallConfigNotify_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TrunkingIndividualPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TrunkingIndividualPaging(tvb, offset, &asn1_ctx, tree, hf_s1ap_TrunkingIndividualPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ListOfTargetTAIsTrunkingIndividualPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ListOfTargetTAIsTrunkingIndividualPaging(tvb, offset, &asn1_ctx, tree, hf_s1ap_ListOfTargetTAIsTrunkingIndividualPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ListOfTargetTAIsItemTrunkingIndividualPaging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_ListOfTargetTAIsItemTrunkingIndividualPaging(tvb, offset, &asn1_ctx, tree, hf_s1ap_ListOfTargetTAIsItemTrunkingIndividualPaging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupDownlinkNASTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupDownlinkNASTransport(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupDownlinkNASTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TrunkingErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TrunkingErrorIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_TrunkingErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupReset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupReset(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupReset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupResetType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupResetType(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupResetType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Group_associatedLogicalS1_ConnectionItemGroupReset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Group_associatedLogicalS1_ConnectionItemGroupReset(tvb, offset, &asn1_ctx, tree, hf_s1ap_Group_associatedLogicalS1_ConnectionItemGroupReset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Group_associatedLogicalS1_ConnectionListGroupResetAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck(tvb, offset, &asn1_ctx, tree, hf_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Group_associatedLogicalS1_ConnectionItemGroupResetAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_Group_associatedLogicalS1_ConnectionItemGroupResetAck(tvb, offset, &asn1_ctx, tree, hf_s1ap_Group_associatedLogicalS1_ConnectionItemGroupResetAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupTE_RABSetupRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupTE_RABSetupRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupTE_RABSetupRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABToBeSetupListGroupBearerSUReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABToBeSetupListGroupBearerSUReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABToBeSetupListGroupBearerSUReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABToBeSetupItemGroupBearerSUReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABToBeSetupItemGroupBearerSUReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABToBeSetupItemGroupBearerSUReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupTE_RABSetupResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupTE_RABSetupResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupTE_RABSetupResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABSetupListGroupBearerSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABSetupListGroupBearerSURes(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABSetupListGroupBearerSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABSetupItemGroupBearerSURes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABSetupItemGroupBearerSURes(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABSetupItemGroupBearerSURes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupTE_RABModifyRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupTE_RABModifyRequest(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupTE_RABModifyRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABToBeModifiedListGroupBearerModReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABToBeModifiedListGroupBearerModReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABToBeModifiedListGroupBearerModReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABToBeModifiedItemGroupBearerModReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABToBeModifiedItemGroupBearerModReq(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABToBeModifiedItemGroupBearerModReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupTE_RABModifyResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupTE_RABModifyResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupTE_RABModifyResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABModifyListGroupBearerModRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABModifyListGroupBearerModRes(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABModifyListGroupBearerModRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABModifyItemGroupBearerModRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABModifyItemGroupBearerModRes(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABModifyItemGroupBearerModRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupTE_RABReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupTE_RABReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupTE_RABReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupTE_RABReleaseResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupTE_RABReleaseResponse(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupTE_RABReleaseResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABReleaseListGroupBearerRelRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABReleaseListGroupBearerRelRes(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABReleaseListGroupBearerRelRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TE_RABReleaseItemGroupBearerRelRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TE_RABReleaseItemGroupBearerRelRes(tvb, offset, &asn1_ctx, tree, hf_s1ap_TE_RABReleaseItemGroupBearerRelRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GroupTE_RABReleaseIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_GroupTE_RABReleaseIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_GroupTE_RABReleaseIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TrunkingMessageTransport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TrunkingMessageTransport(tvb, offset, &asn1_ctx, tree, hf_s1ap_TrunkingMessageTransport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TrunkingServingCellUpdateIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_TrunkingServingCellUpdateIndication(tvb, offset, &asn1_ctx, tree, hf_s1ap_TrunkingServingCellUpdateIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MMEGroupCallConfigurationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_MMEGroupCallConfigurationTransfer(tvb, offset, &asn1_ctx, tree, hf_s1ap_MMEGroupCallConfigurationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_S1AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_s1ap_S1AP_PDU(tvb, offset, &asn1_ctx, tree, hf_s1ap_S1AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-s1ap-fn.c ---*/
#line 396 "./asn1/s1ap/packet-s1ap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  s1ap_ctx_t s1ap_ctx;
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  s1ap_ctx.message_type        = s1ap_data->message_type;
  s1ap_ctx.ProcedureCode       = s1ap_data->procedure_code;
  s1ap_ctx.ProtocolIE_ID       = s1ap_data->protocol_ie_id;
  s1ap_ctx.ProtocolExtensionID = s1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(s1ap_ies_dissector_table, s1ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &s1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint(s1ap_ies_p1_dissector_table, s1ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint(s1ap_ies_p2_dissector_table, s1ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
*/

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  s1ap_ctx_t s1ap_ctx;
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  s1ap_ctx.message_type        = s1ap_data->message_type;
  s1ap_ctx.ProcedureCode       = s1ap_data->procedure_code;
  s1ap_ctx.ProtocolIE_ID       = s1ap_data->protocol_ie_id;
  s1ap_ctx.ProtocolExtensionID = s1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(s1ap_extension_dissector_table, s1ap_data->protocol_extension_id, tvb, pinfo, tree, FALSE, &s1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(s1ap_proc_imsg_dissector_table, s1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(s1ap_proc_sout_dissector_table, s1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(s1ap_proc_uout_dissector_table, s1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_s1ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *s1ap_item = NULL;
  proto_tree *s1ap_tree = NULL;
  conversation_t *conversation;
  struct s1ap_private_data* s1ap_data;
  wmem_list_frame_t *prev_layer;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "S1AP");
  /* ensure that parent dissector is not S1AP before clearing fence */
  prev_layer = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
  if (prev_layer && GPOINTER_TO_INT(wmem_list_frame_data(prev_layer)) != proto_s1ap)
    col_clear_fence(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the s1ap protocol tree */
  s1ap_item = proto_tree_add_item(tree, proto_s1ap, tvb, 0, -1, ENC_NA);
  s1ap_tree = proto_item_add_subtree(s1ap_item, ett_s1ap);

  s1ap_data = s1ap_get_private_data(pinfo);
  conversation = find_or_create_conversation(pinfo);
  s1ap_data->s1ap_conv = (struct s1ap_conv_info *)conversation_get_proto_data(conversation, proto_s1ap);
  if (!s1ap_data->s1ap_conv) {
    s1ap_data->s1ap_conv = wmem_new(wmem_file_scope(), struct s1ap_conv_info);
    s1ap_data->s1ap_conv->nbiot_ta = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
    s1ap_data->s1ap_conv->nbiot_enb_ue_s1ap_id = wmem_tree_new(wmem_file_scope());
    conversation_add_proto_data(conversation, proto_s1ap, s1ap_data->s1ap_conv);
  }

  dissect_S1AP_PDU_PDU(tvb, pinfo, s1ap_tree, NULL);
  return tvb_captured_length(tvb);
}

/*--- proto_reg_handoff_s1ap ---------------------------------------*/
void
proto_reg_handoff_s1ap(void)
{
  static gboolean Initialized=FALSE;
  static guint SctpPort;

  if (!Initialized) {
    gcsna_handle = find_dissector_add_dependency("gcsna", proto_s1ap);
    nas_eps_handle = find_dissector_add_dependency("nas-eps", proto_s1ap);
    lppa_handle = find_dissector_add_dependency("lppa", proto_s1ap);
    bssgp_handle = find_dissector_add_dependency("bssgp", proto_s1ap);
    lte_rrc_ue_radio_access_cap_info_handle = find_dissector_add_dependency("lte-rrc.ue_radio_access_cap_info", proto_s1ap);
    lte_rrc_ue_radio_access_cap_info_nb_handle = find_dissector_add_dependency("lte-rrc.ue_radio_access_cap_info.nb", proto_s1ap);
    nr_rrc_ue_radio_access_cap_info_handle = find_dissector_add_dependency("nr-rrc.ue_radio_access_cap_info", proto_s1ap);
    lte_rrc_ue_radio_paging_info_handle = find_dissector_add_dependency("lte-rrc.ue_radio_paging_info", proto_s1ap);
    lte_rrc_ue_radio_paging_info_nb_handle = find_dissector_add_dependency("lte-rrc.ue_radio_paging_info.nb", proto_s1ap);
    dissector_add_for_decode_as("sctp.port", s1ap_handle);
    dissector_add_uint("sctp.ppi", S1AP_PAYLOAD_PROTOCOL_ID, s1ap_handle);
    Initialized=TRUE;

/*--- Included file: packet-s1ap-dis-tab.c ---*/
#line 1 "./asn1/s1ap/packet-s1ap-dis-tab.c"
  dissector_add_uint("s1ap.ies", id_MME_UE_S1AP_ID, create_dissector_handle(dissect_MME_UE_S1AP_ID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_HandoverType, create_dissector_handle(dissect_HandoverType_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TargetID, create_dissector_handle(dissect_TargetID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_eNB_UE_S1AP_ID, create_dissector_handle(dissect_ENB_UE_S1AP_ID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABSubjecttoDataForwardingList, create_dissector_handle(dissect_E_RABSubjecttoDataForwardingList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABtoReleaseListHOCmd, create_dissector_handle(dissect_E_RABList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABDataForwardingItem, create_dissector_handle(dissect_E_RABDataForwardingItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABReleaseItemBearerRelComp, create_dissector_handle(dissect_E_RABReleaseItemBearerRelComp_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSetupListBearerSUReq, create_dissector_handle(dissect_E_RABToBeSetupListBearerSUReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSetupItemBearerSUReq, create_dissector_handle(dissect_E_RABToBeSetupItemBearerSUReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABAdmittedList, create_dissector_handle(dissect_E_RABAdmittedList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABFailedToSetupListHOReqAck, create_dissector_handle(dissect_E_RABFailedtoSetupListHOReqAck_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABAdmittedItem, create_dissector_handle(dissect_E_RABAdmittedItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABFailedtoSetupItemHOReqAck, create_dissector_handle(dissect_E_RABFailedToSetupItemHOReqAck_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSwitchedDLList, create_dissector_handle(dissect_E_RABToBeSwitchedDLList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSwitchedDLItem, create_dissector_handle(dissect_E_RABToBeSwitchedDLItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSetupListCtxtSUReq, create_dissector_handle(dissect_E_RABToBeSetupListCtxtSUReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TraceActivation, create_dissector_handle(dissect_TraceActivation_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_UTRAN_Trace_ID, create_dissector_handle(dissect_E_UTRAN_Trace_ID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_NAS_PDU, create_dissector_handle(dissect_NAS_PDU_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSetupItemHOReq, create_dissector_handle(dissect_E_RABToBeSetupItemHOReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABSetupListBearerSURes, create_dissector_handle(dissect_E_RABSetupListBearerSURes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABFailedToSetupListBearerSURes, create_dissector_handle(dissect_E_RABList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeModifiedListBearerModReq, create_dissector_handle(dissect_E_RABToBeModifiedListBearerModReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABModifyListBearerModRes, create_dissector_handle(dissect_E_RABModifyListBearerModRes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABFailedToModifyList, create_dissector_handle(dissect_E_RABList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeReleasedList, create_dissector_handle(dissect_E_RABList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABFailedToReleaseList, create_dissector_handle(dissect_E_RABList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABItem, create_dissector_handle(dissect_E_RABItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeModifiedItemBearerModReq, create_dissector_handle(dissect_E_RABToBeModifiedItemBearerModReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABModifyItemBearerModRes, create_dissector_handle(dissect_E_RABModifyItemBearerModRes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABSetupItemBearerSURes, create_dissector_handle(dissect_E_RABSetupItemBearerSURes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SecurityContext, create_dissector_handle(dissect_SecurityContext_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_HandoverRestrictionList, create_dissector_handle(dissect_s1ap_HandoverRestrictionList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_UEPagingID, create_dissector_handle(dissect_UEPagingID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_pagingDRX, create_dissector_handle(dissect_PagingDRX_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TAIList, create_dissector_handle(dissect_TAIList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TAIItem, create_dissector_handle(dissect_TAIItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABFailedToSetupListCtxtSURes, create_dissector_handle(dissect_E_RABList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABSetupItemCtxtSURes, create_dissector_handle(dissect_E_RABSetupItemCtxtSURes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABSetupListCtxtSURes, create_dissector_handle(dissect_E_RABSetupListCtxtSURes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSetupItemCtxtSUReq, create_dissector_handle(dissect_E_RABToBeSetupItemCtxtSUReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSetupListHOReq, create_dissector_handle(dissect_E_RABToBeSetupListHOReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Global_ENB_ID, create_dissector_handle(dissect_s1ap_Global_ENB_ID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_eNBname, create_dissector_handle(dissect_ENBname_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_MMEname, create_dissector_handle(dissect_MMEname_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_ServedPLMNs, create_dissector_handle(dissect_ServedPLMNs_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SupportedTAs, create_dissector_handle(dissect_SupportedTAs_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TimeToWait, create_dissector_handle(dissect_TimeToWait_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_uEaggregateMaximumBitrate, create_dissector_handle(dissect_UEAggregateMaximumBitrate_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TAI, create_dissector_handle(dissect_TAI_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABReleaseListBearerRelComp, create_dissector_handle(dissect_E_RABReleaseListBearerRelComp_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_cdma2000PDU, create_dissector_handle(dissect_Cdma2000PDU_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_cdma2000RATType, create_dissector_handle(dissect_Cdma2000RATType_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_cdma2000SectorID, create_dissector_handle(dissect_Cdma2000SectorID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SecurityKey, create_dissector_handle(dissect_SecurityKey_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_UERadioCapability, create_dissector_handle(dissect_UERadioCapability_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_GUMMEI_ID, create_dissector_handle(dissect_GUMMEI_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABInformationListItem, create_dissector_handle(dissect_E_RABInformationListItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Direct_Forwarding_Path_Availability, create_dissector_handle(dissect_Direct_Forwarding_Path_Availability_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_UEIdentityIndexValue, create_dissector_handle(dissect_UEIdentityIndexValue_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_cdma2000HOStatus, create_dissector_handle(dissect_Cdma2000HOStatus_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_cdma2000HORequiredIndication, create_dissector_handle(dissect_Cdma2000HORequiredIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_RelativeMMECapacity, create_dissector_handle(dissect_RelativeMMECapacity_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SourceMME_UE_S1AP_ID, create_dissector_handle(dissect_MME_UE_S1AP_ID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Bearers_SubjectToStatusTransfer_Item, create_dissector_handle(dissect_Bearers_SubjectToStatusTransfer_Item_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_eNB_StatusTransfer_TransparentContainer, create_dissector_handle(dissect_s1ap_ENB_StatusTransfer_TransparentContainer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_UE_associatedLogicalS1_ConnectionItem, create_dissector_handle(dissect_UE_associatedLogicalS1_ConnectionItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_ResetType, create_dissector_handle(dissect_ResetType_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_UE_associatedLogicalS1_ConnectionListResAck, create_dissector_handle(dissect_UE_associatedLogicalS1_ConnectionListResAck_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSwitchedULItem, create_dissector_handle(dissect_E_RABToBeSwitchedULItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABToBeSwitchedULList, create_dissector_handle(dissect_E_RABToBeSwitchedULList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_S_TMSI, create_dissector_handle(dissect_S_TMSI_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_cdma2000OneXRAND, create_dissector_handle(dissect_Cdma2000OneXRAND_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_RequestType, create_dissector_handle(dissect_RequestType_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_UE_S1AP_IDs, create_dissector_handle(dissect_UE_S1AP_IDs_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_EUTRAN_CGI, create_dissector_handle(dissect_s1ap_EUTRAN_CGI_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_OverloadResponse, create_dissector_handle(dissect_OverloadResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_cdma2000OneXSRVCCInfo, create_dissector_handle(dissect_Cdma2000OneXSRVCCInfo_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Source_ToTarget_TransparentContainer, create_dissector_handle(dissect_Source_ToTarget_TransparentContainer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_ServedGUMMEIs, create_dissector_handle(dissect_ServedGUMMEIs_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SubscriberProfileIDforRFP, create_dissector_handle(dissect_SubscriberProfileIDforRFP_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_UESecurityCapabilities, create_dissector_handle(dissect_UESecurityCapabilities_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CSFallbackIndicator, create_dissector_handle(dissect_CSFallbackIndicator_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CNDomain, create_dissector_handle(dissect_CNDomain_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_E_RABReleasedList, create_dissector_handle(dissect_E_RABList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_MessageIdentifier, create_dissector_handle(dissect_MessageIdentifier_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SerialNumber, create_dissector_handle(dissect_SerialNumber_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_WarningAreaList, create_dissector_handle(dissect_WarningAreaList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_RepetitionPeriod, create_dissector_handle(dissect_RepetitionPeriod_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_NumberofBroadcastRequest, create_dissector_handle(dissect_NumberofBroadcastRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_WarningType, create_dissector_handle(dissect_WarningType_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_WarningSecurityInfo, create_dissector_handle(dissect_WarningSecurityInfo_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_DataCodingScheme, create_dissector_handle(dissect_DataCodingScheme_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_WarningMessageContents, create_dissector_handle(dissect_WarningMessageContents_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_BroadcastCompletedAreaList, create_dissector_handle(dissect_BroadcastCompletedAreaList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Inter_SystemInformationTransferTypeEDT, create_dissector_handle(dissect_Inter_SystemInformationTransferType_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Inter_SystemInformationTransferTypeMDT, create_dissector_handle(dissect_Inter_SystemInformationTransferType_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Target_ToSource_TransparentContainer, create_dissector_handle(dissect_Target_ToSource_TransparentContainer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SRVCCOperationPossible, create_dissector_handle(dissect_SRVCCOperationPossible_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SRVCCHOIndication, create_dissector_handle(dissect_SRVCCHOIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CSG_Id, create_dissector_handle(dissect_CSG_Id_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CSG_IdList, create_dissector_handle(dissect_CSG_IdList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SONConfigurationTransferECT, create_dissector_handle(dissect_SONConfigurationTransfer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SONConfigurationTransferMCT, create_dissector_handle(dissect_SONConfigurationTransfer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TraceCollectionEntityIPAddress, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_MSClassmark2, create_dissector_handle(dissect_MSClassmark2_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_MSClassmark3, create_dissector_handle(dissect_MSClassmark3_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_RRC_Establishment_Cause, create_dissector_handle(dissect_RRC_Establishment_Cause_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_NASSecurityParametersfromE_UTRAN, create_dissector_handle(dissect_NASSecurityParametersfromE_UTRAN_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_NASSecurityParameterstoE_UTRAN, create_dissector_handle(dissect_NASSecurityParameterstoE_UTRAN_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_DefaultPagingDRX, create_dissector_handle(dissect_PagingDRX_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Source_ToTarget_TransparentContainer_Secondary, create_dissector_handle(dissect_Source_ToTarget_TransparentContainer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Target_ToSource_TransparentContainer_Secondary, create_dissector_handle(dissect_Target_ToSource_TransparentContainer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_EUTRANRoundTripDelayEstimationInfo, create_dissector_handle(dissect_EUTRANRoundTripDelayEstimationInfo_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_BroadcastCancelledAreaList, create_dissector_handle(dissect_BroadcastCancelledAreaList_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_ConcurrentWarningMessageIndicator, create_dissector_handle(dissect_ConcurrentWarningMessageIndicator_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_ExtendedRepetitionPeriod, create_dissector_handle(dissect_ExtendedRepetitionPeriod_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CellAccessMode, create_dissector_handle(dissect_CellAccessMode_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CSGMembershipStatus, create_dissector_handle(dissect_CSGMembershipStatus_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_LPPa_PDU, create_dissector_handle(dissect_LPPa_PDU_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Routing_ID, create_dissector_handle(dissect_Routing_ID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_PS_ServiceNotAvailable, create_dissector_handle(dissect_PS_ServiceNotAvailable_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_RegisteredLAI, create_dissector_handle(dissect_LAI_PDU, proto_s1ap));
  dissector_add_uint("s1ap.extension", id_Data_Forwarding_Not_Possible, create_dissector_handle(dissect_Data_Forwarding_Not_Possible_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_GroupIdentity, create_dissector_handle(dissect_GroupIdentity_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_MME_Group_S1AP_ID, create_dissector_handle(dissect_MME_Group_S1AP_ID_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CallPriority, create_dissector_handle(dissect_CallPriority_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CallSequence, create_dissector_handle(dissect_CallSequence_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_GroupAggregateMaximumBitrate, create_dissector_handle(dissect_GroupAggregateMaximumBitrate_PDU, proto_s1ap));
  dissector_add_uint("s1ap.extension", id_TE_RABToBeSetupListGroupCtxtSUReq, create_dissector_handle(dissect_TE_RABToBeSetupListGroupCtxtSUReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABToBeSetupItemGroupCtxtSUReq, create_dissector_handle(dissect_TE_RABToBeSetupItemGroupCtxtSUReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABSetupListGroupCtxtSURes, create_dissector_handle(dissect_TE_RABSetupListGroupCtxtSURes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABSetupItemGroupCtxtSURes, create_dissector_handle(dissect_TE_RABSetupItemGroupCtxtSURes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TAIListItemGroupServiceArea, create_dissector_handle(dissect_TAIListItemGroupServiceArea_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_CellListItemGroupServiceArea, create_dissector_handle(dissect_CellListItemGroupServiceArea_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Group_S1AP_IDs, create_dissector_handle(dissect_Group_S1AP_IDs_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_ListOfTargetTAIsTrunkingIndividualPaging, create_dissector_handle(dissect_ListOfTargetTAIsTrunkingIndividualPaging_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_ListOfTargetTAIsItemTrunkingIndividualPaging, create_dissector_handle(dissect_ListOfTargetTAIsItemTrunkingIndividualPaging_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_NAS_PDUType, create_dissector_handle(dissect_NAS_PDUType_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_GroupResetType, create_dissector_handle(dissect_GroupResetType_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Group_associatedLogicalS1_ConnectionItemGroupReset, create_dissector_handle(dissect_Group_associatedLogicalS1_ConnectionItemGroupReset_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Group_associatedLogicalS1_ConnectionListGroupResetAck, create_dissector_handle(dissect_Group_associatedLogicalS1_ConnectionListGroupResetAck_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_Group_associatedLogicalS1_ConnectionItemGroupResetAck, create_dissector_handle(dissect_Group_associatedLogicalS1_ConnectionItemGroupResetAck_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABToBeSetupListGroupBearerSUReq, create_dissector_handle(dissect_TE_RABToBeSetupListGroupBearerSUReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABToBeSetupItemGroupBearerSUReq, create_dissector_handle(dissect_TE_RABToBeSetupItemGroupBearerSUReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABSetupListGroupBearerSURes, create_dissector_handle(dissect_TE_RABSetupListGroupBearerSURes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABSetupItemGroupBearerSURes, create_dissector_handle(dissect_TE_RABSetupItemGroupBearerSURes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABToBeModifiedListGroupBearerModReq, create_dissector_handle(dissect_TE_RABToBeModifiedListGroupBearerModReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABToBeModifiedItemGroupBearerModReq, create_dissector_handle(dissect_TE_RABToBeModifiedItemGroupBearerModReq_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABModifyListGroupBearerModRes, create_dissector_handle(dissect_TE_RABModifyListGroupBearerModRes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABModifyItemGroupBearerModRes, create_dissector_handle(dissect_TE_RABModifyItemGroupBearerModRes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABReleaseListGroupBearerRelRes, create_dissector_handle(dissect_TE_RABReleaseListGroupBearerRelRes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABReleaseItemGroupBearerRelRes, create_dissector_handle(dissect_TE_RABReleaseItemGroupBearerRelRes_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TrunkingUserIndication, create_dissector_handle(dissect_TrunkingUserIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TE_RABItem, create_dissector_handle(dissect_TE_RABItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TargeteNB_List, create_dissector_handle(dissect_TargeteNB_List_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_TargeteNB_Item, create_dissector_handle(dissect_TargeteNB_Item_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SourceeNB_List, create_dissector_handle(dissect_SourceeNB_List_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_NeedResponse, create_dissector_handle(dissect_NeedResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_GroupConfigurationContainer, create_dissector_handle(dissect_GroupConfigurationContainer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_GroupConfigurationContainerItem, create_dissector_handle(dissect_GroupConfigurationContainerItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_AddModGroupCallConfigurationItem, create_dissector_handle(dissect_AddModGroupCallConfigurationItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_ReleaseGroupCallConfigurationItem, create_dissector_handle(dissect_ReleaseGroupCallConfigurationItem_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_AMROverPDCPCapablityIndicator, create_dissector_handle(dissect_AMROverPDCPCapablityIndicator_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_SourceeNB_Item, create_dissector_handle(dissect_SourceeNB_Item_PDU, proto_s1ap));
  dissector_add_uint("s1ap.ies", id_AMROverPDCPIndicator, create_dissector_handle(dissect_AMROverPDCPIndicator_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_HandoverPreparation, create_dissector_handle(dissect_HandoverRequired_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_HandoverPreparation, create_dissector_handle(dissect_HandoverCommand_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.uout", id_HandoverPreparation, create_dissector_handle(dissect_HandoverPreparationFailure_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_HandoverResourceAllocation, create_dissector_handle(dissect_HandoverRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_HandoverResourceAllocation, create_dissector_handle(dissect_HandoverRequestAcknowledge_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.uout", id_HandoverResourceAllocation, create_dissector_handle(dissect_HandoverFailure_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_HandoverNotification, create_dissector_handle(dissect_HandoverNotify_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_PathSwitchRequest, create_dissector_handle(dissect_PathSwitchRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_PathSwitchRequest, create_dissector_handle(dissect_PathSwitchRequestAcknowledge_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.uout", id_PathSwitchRequest, create_dissector_handle(dissect_PathSwitchRequestFailure_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_E_RABSetup, create_dissector_handle(dissect_E_RABSetupRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_E_RABSetup, create_dissector_handle(dissect_E_RABSetupResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_E_RABModify, create_dissector_handle(dissect_E_RABModifyRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_E_RABModify, create_dissector_handle(dissect_E_RABModifyResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_E_RABRelease, create_dissector_handle(dissect_E_RABReleaseCommand_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_E_RABRelease, create_dissector_handle(dissect_E_RABReleaseResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_E_RABReleaseIndication, create_dissector_handle(dissect_E_RABReleaseIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_InitialContextSetup, create_dissector_handle(dissect_InitialContextSetupRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_InitialContextSetup, create_dissector_handle(dissect_InitialContextSetupResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.uout", id_InitialContextSetup, create_dissector_handle(dissect_InitialContextSetupFailure_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_UEContextReleaseRequest, create_dissector_handle(dissect_UEContextReleaseRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_Paging, create_dissector_handle(dissect_Paging_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_downlinkNASTransport, create_dissector_handle(dissect_DownlinkNASTransport_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_initialUEMessage, create_dissector_handle(dissect_InitialUEMessage_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_uplinkNASTransport, create_dissector_handle(dissect_UplinkNASTransport_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_NASNonDeliveryIndication, create_dissector_handle(dissect_NASNonDeliveryIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_HandoverCancel, create_dissector_handle(dissect_HandoverCancel_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_HandoverCancel, create_dissector_handle(dissect_HandoverCancelAcknowledge_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_Reset, create_dissector_handle(dissect_Reset_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_Reset, create_dissector_handle(dissect_ResetAcknowledge_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_ErrorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_S1Setup, create_dissector_handle(dissect_S1SetupRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_S1Setup, create_dissector_handle(dissect_S1SetupResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.uout", id_S1Setup, create_dissector_handle(dissect_S1SetupFailure_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_ENBConfigurationUpdate, create_dissector_handle(dissect_ENBConfigurationUpdate_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_ENBConfigurationUpdate, create_dissector_handle(dissect_ENBConfigurationUpdateAcknowledge_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.uout", id_ENBConfigurationUpdate, create_dissector_handle(dissect_ENBConfigurationUpdateFailure_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_MMEConfigurationUpdate, create_dissector_handle(dissect_MMEConfigurationUpdate_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_MMEConfigurationUpdate, create_dissector_handle(dissect_MMEConfigurationUpdateAcknowledge_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.uout", id_MMEConfigurationUpdate, create_dissector_handle(dissect_MMEConfigurationUpdateFailure_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.uout", id_UEContextModification, create_dissector_handle(dissect_UEContextModificationFailure_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_UECapabilityInfoIndication, create_dissector_handle(dissect_UECapabilityInfoIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_UEContextRelease, create_dissector_handle(dissect_UEContextReleaseCommand_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_UEContextRelease, create_dissector_handle(dissect_UEContextReleaseComplete_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_eNBStatusTransfer, create_dissector_handle(dissect_ENBStatusTransfer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_MMEStatusTransfer, create_dissector_handle(dissect_MMEStatusTransfer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_DeactivateTrace, create_dissector_handle(dissect_DeactivateTrace_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_TraceStart, create_dissector_handle(dissect_TraceStart_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_TraceFailureIndication, create_dissector_handle(dissect_TraceFailureIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_LocationReportingControl, create_dissector_handle(dissect_LocationReportingControl_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_LocationReportingFailureIndication, create_dissector_handle(dissect_LocationReportingFailureIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_LocationReport, create_dissector_handle(dissect_LocationReport_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_OverloadStart, create_dissector_handle(dissect_OverloadStart_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_OverloadStop, create_dissector_handle(dissect_OverloadStop_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_WriteReplaceWarning, create_dissector_handle(dissect_WriteReplaceWarningRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_WriteReplaceWarning, create_dissector_handle(dissect_WriteReplaceWarningResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_eNBDirectInformationTransfer, create_dissector_handle(dissect_ENBDirectInformationTransfer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_MMEDirectInformationTransfer, create_dissector_handle(dissect_MMEDirectInformationTransfer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_eNBConfigurationTransfer, create_dissector_handle(dissect_ENBConfigurationTransfer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_MMEConfigurationTransfer, create_dissector_handle(dissect_MMEConfigurationTransfer_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_CellTrafficTrace, create_dissector_handle(dissect_CellTrafficTrace_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_PrivateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_Kill, create_dissector_handle(dissect_KillRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_Kill, create_dissector_handle(dissect_KillResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_downlinkUEAssociatedLPPaTransport, create_dissector_handle(dissect_DownlinkUEAssociatedLPPaTransport_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_uplinkUEAssociatedLPPaTransport, create_dissector_handle(dissect_UplinkUEAssociatedLPPaTransport_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_downlinkNonUEAssociatedLPPaTransport, create_dissector_handle(dissect_DownlinkNonUEAssociatedLPPaTransport_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_uplinkNonUEAssociatedLPPaTransport, create_dissector_handle(dissect_UplinkNonUEAssociatedLPPaTransport_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_GroupCallContextSetup, create_dissector_handle(dissect_GroupCallContextSetupRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_GroupCallContextSetup, create_dissector_handle(dissect_GroupCallContextSetupResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_GroupCallContextModification, create_dissector_handle(dissect_GroupCallContextModificationRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_GroupCallContextModification, create_dissector_handle(dissect_GroupCallContextModificationResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_GroupCallContextRelease, create_dissector_handle(dissect_GroupCallContextReleaseCommand_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_GroupCallContextRelease, create_dissector_handle(dissect_GroupCallContextReleaseComplete_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_GroupTE_RABSetup, create_dissector_handle(dissect_GroupTE_RABSetupRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_GroupTE_RABSetup, create_dissector_handle(dissect_GroupTE_RABSetupResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_GroupTE_RABModify, create_dissector_handle(dissect_GroupTE_RABModifyRequest_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_GroupTE_RABModify, create_dissector_handle(dissect_GroupTE_RABModifyResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_GroupTE_RABRelease, create_dissector_handle(dissect_GroupTE_RABReleaseCommand_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_GroupTE_RABRelease, create_dissector_handle(dissect_GroupTE_RABReleaseResponse_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_GroupTE_RABReleaseIndication, create_dissector_handle(dissect_GroupTE_RABReleaseIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_GroupCallContextReleaseIndication, create_dissector_handle(dissect_GroupCallContextReleaseIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_InstantGroupCallConfigNotify, create_dissector_handle(dissect_InstantGroupCallConfigNotify_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_TrunkingIndividualPaging, create_dissector_handle(dissect_TrunkingIndividualPaging_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.sout", id_GroupDownlinkNASTransport, create_dissector_handle(dissect_GroupDownlinkNASTransport_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_TrunkingErrorIndication, create_dissector_handle(dissect_TrunkingErrorIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_GroupReset, create_dissector_handle(dissect_GroupReset_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_TrunkingMessageTransport, create_dissector_handle(dissect_TrunkingMessageTransport_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_TrunkingServingCellUpdateIndication, create_dissector_handle(dissect_TrunkingServingCellUpdateIndication_PDU, proto_s1ap));
  dissector_add_uint("s1ap.proc.imsg", id_MMEGroupCallConfigurationTransfer, create_dissector_handle(dissect_MMEGroupCallConfigurationTransfer_PDU, proto_s1ap));


/*--- End of included file: packet-s1ap-dis-tab.c ---*/
#line 516 "./asn1/s1ap/packet-s1ap-template.c"
  } else {
    if (SctpPort != 0) {
      dissector_delete_uint("sctp.port", SctpPort, s1ap_handle);
    }
  }

  SctpPort=gbl_s1apSctpPort;
  if (SctpPort != 0) {
    dissector_add_uint("sctp.port", SctpPort, s1ap_handle);
  }
}

/*--- proto_register_s1ap -------------------------------------------*/
void proto_register_s1ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_s1ap_transportLayerAddressIPv4,
      { "transportLayerAddress(IPv4)", "s1ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_transportLayerAddressIPv6,
      { "transportLayerAddress(IPv6)", "s1ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_UTRAN_Trace_ID_TraceID,
      { "TraceID", "s1ap.E_UTRAN_Trace_ID.TraceID",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_UTRAN_Trace_ID_TraceRecordingSessionReference,
      { "TraceRecordingSessionReference", "s1ap.E_UTRAN_Trace_ID.TraceRecordingSessionReference",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_S1_MME,
      { "S1-MME", "s1ap.interfacesToTrace.S1_MME",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x80,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_X2,
      { "X2", "s1ap.interfacesToTrace.X2",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x40,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_Uu,
      { "Uu", "s1ap.interfacesToTrace.Uu",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x20,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_F1_C,
      { "F1-C", "s1ap.interfacesToTrace.F1_C",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x10,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_E1,
      { "E1", "s1ap.interfacesToTrace.E1",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x08,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_Reserved,
      { "Reserved", "s1ap.interfacesToTrace.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_s1ap_encryptionAlgorithms_EEA1,
      { "128-EEA1", "s1ap.encryptionAlgorithms.EEA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_s1ap_encryptionAlgorithms_EEA2,
      { "128-EEA2", "s1ap.encryptionAlgorithms.EEA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_s1ap_encryptionAlgorithms_EEA3,
      { "128-EEA3", "s1ap.encryptionAlgorithms.EEA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_s1ap_encryptionAlgorithms_Reserved,
      { "Reserved", "s1ap.encryptionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_s1ap_integrityProtectionAlgorithms_EIA1,
      { "128-EIA1", "s1ap.integrityProtectionAlgorithms.EIA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_s1ap_integrityProtectionAlgorithms_EIA2,
      { "128-EIA2", "s1ap.integrityProtectionAlgorithms.EIA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_s1ap_integrityProtectionAlgorithms_EIA3,
      { "128-EIA3", "s1ap.integrityProtectionAlgorithms.EIA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_s1ap_integrityProtectionAlgorithms_Reserved,
      { "Reserved", "s1ap.integrityProtectionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_s1ap_SerialNumber_gs,
      { "Geographical Scope", "s1ap.SerialNumber.gs",
        FT_UINT16, BASE_DEC, VALS(s1ap_serialNumber_gs_vals), 0xc000,
        NULL, HFILL }},
    { &hf_s1ap_SerialNumber_msg_code,
      { "Message Code", "s1ap.SerialNumber.msg_code",
        FT_UINT16, BASE_DEC, NULL, 0x3ff0,
        NULL, HFILL }},
    { &hf_s1ap_SerialNumber_upd_nb,
      { "Update Number", "s1ap.SerialNumber.upd_nb",
        FT_UINT16, BASE_DEC, NULL, 0x000f,
        NULL, HFILL }},
    { &hf_s1ap_WarningType_value,
      { "Warning Type Value", "s1ap.WarningType.value",
        FT_UINT16, BASE_DEC, VALS(s1ap_warningType_vals), 0xfe00,
        NULL, HFILL }},
    { &hf_s1ap_WarningType_emergency_user_alert,
      { "Emergency User Alert", "s1ap.WarningType.emergency_user_alert",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
        NULL, HFILL }},
    { &hf_s1ap_WarningType_popup,
      { "Popup", "s1ap.WarningType.popup",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
        NULL, HFILL }},
    { &hf_s1ap_WarningMessageContents_nb_pages,
      { "Number of Pages", "s1ap.WarningMessageContents.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_WarningMessageContents_decoded_page,
      { "Decoded Page", "s1ap.WarningMessageContents.decoded_page",
        FT_STRING, STR_UNICODE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M1,
      { "M1", "s1ap.measurementsToActivate.M1",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x80,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M2,
      { "M2", "s1ap.measurementsToActivate.M2",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x40,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M3,
      { "M3", "s1ap.measurementsToActivate.M3",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x20,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M4,
      { "M4", "s1ap.measurementsToActivate.M4",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x10,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M5,
      { "M5", "s1ap.measurementsToActivate.M5",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x08,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_LoggingM1FromEventTriggered,
      { "LoggingOfM1FromEventTriggeredMeasurementReports", "s1ap.measurementsToActivate.LoggingM1FromEventTriggered",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x04,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M6,
      { "M6", "s1ap.measurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x02,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M7,
      { "M7", "s1ap.measurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x01,
        NULL, HFILL }},
    { &hf_s1ap_MDT_Location_Info_GNSS,
      { "GNSS", "s1ap.MDT_Location_Info.GNSS",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x80,
        NULL, HFILL }},
    { &hf_s1ap_MDT_Location_Info_E_CID,
      { "E-CID", "s1ap.MDT_Location_Info.E_CID",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x40,
        NULL, HFILL }},
    { &hf_s1ap_MDT_Location_Info_Reserved,
      { "Reserved", "s1ap.MDT_Location_Info.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x3f,
        NULL, HFILL }},
    { &hf_s1ap_NRencryptionAlgorithms_NEA1,
      { "128-NEA1", "s1ap.NRencryptionAlgorithms.NEA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_s1ap_NRencryptionAlgorithms_NEA2,
      { "128-NEA2", "s1ap.NRencryptionAlgorithms.NEA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_s1ap_NRencryptionAlgorithms_NEA3,
      { "128-NEA3", "s1ap.NRencryptionAlgorithms.NEA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_s1ap_NRencryptionAlgorithms_Reserved,
      { "Reserved", "s1ap.NRencryptionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_s1ap_NRintegrityProtectionAlgorithms_NIA1,
      { "128-NIA1", "s1ap.NRintegrityProtectionAlgorithms.NIA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_s1ap_NRintegrityProtectionAlgorithms_NIA2,
      { "128-NIA2", "s1ap.NRintegrityProtectionAlgorithms.NIA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_s1ap_NRintegrityProtectionAlgorithms_NIA3,
      { "128-NIA3", "s1ap.NRintegrityProtectionAlgorithms.NIA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_s1ap_NRintegrityProtectionAlgorithms_Reserved,
      { "Reserved", "s1ap.NRintegrityProtectionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_s1ap_UE_Application_Layer_Measurement_Capability_QoE_Measurement_for_streaming_service,
      { "QoE Measurement for streaming service", "s1ap.UE_Application_Layer_Measurement_Capability.QoE_Measurement_for_streaming_service",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
        NULL, HFILL }},
    { &hf_s1ap_UE_Application_Layer_Measurement_Capability_QoE_Measurement_for_MTSI_service,
      { "QoE Measurement for MTSI service", "s1ap.UE_Application_Layer_Measurement_Capability.QoE_Measurement_for_MTSI_service",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }},
    { &hf_s1ap_UE_Application_Layer_Measurement_Capability_Reserved,
      { "Reserved", "s1ap.UE_Application_Layer_Measurement_Capability.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x3f,
        NULL, HFILL }},

/*--- Included file: packet-s1ap-hfarr.c ---*/
#line 1 "./asn1/s1ap/packet-s1ap-hfarr.c"
    { &hf_s1ap_AddModGroupCallConfigurationItem_PDU,
      { "AddModGroupCallConfigurationItem", "s1ap.AddModGroupCallConfigurationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_AMROverPDCPIndicator_PDU,
      { "AMROverPDCPIndicator", "s1ap.AMROverPDCPIndicator",
        FT_UINT32, BASE_DEC, VALS(s1ap_AMROverPDCPIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_AMROverPDCPCapablityIndicator_PDU,
      { "AMROverPDCPCapablityIndicator", "s1ap.AMROverPDCPCapablityIndicator",
        FT_UINT32, BASE_DEC, VALS(s1ap_AMROverPDCPCapablityIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_Bearers_SubjectToStatusTransfer_Item_PDU,
      { "Bearers-SubjectToStatusTransfer-Item", "s1ap.Bearers_SubjectToStatusTransfer_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_BroadcastCancelledAreaList_PDU,
      { "BroadcastCancelledAreaList", "s1ap.BroadcastCancelledAreaList",
        FT_UINT32, BASE_DEC, VALS(s1ap_BroadcastCancelledAreaList_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_BroadcastCompletedAreaList_PDU,
      { "BroadcastCompletedAreaList", "s1ap.BroadcastCompletedAreaList",
        FT_UINT32, BASE_DEC, VALS(s1ap_BroadcastCompletedAreaList_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_Cause_PDU,
      { "Cause", "s1ap.Cause",
        FT_UINT32, BASE_DEC, VALS(s1ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_CallPriority_PDU,
      { "CallPriority", "s1ap.CallPriority",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CallSequence_PDU,
      { "CallSequence", "s1ap.CallSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CellAccessMode_PDU,
      { "CellAccessMode", "s1ap.CellAccessMode",
        FT_UINT32, BASE_DEC, VALS(s1ap_CellAccessMode_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_Cdma2000PDU_PDU,
      { "Cdma2000PDU", "s1ap.Cdma2000PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Cdma2000RATType_PDU,
      { "Cdma2000RATType", "s1ap.Cdma2000RATType",
        FT_UINT32, BASE_DEC, VALS(s1ap_Cdma2000RATType_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_Cdma2000SectorID_PDU,
      { "Cdma2000SectorID", "s1ap.Cdma2000SectorID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Cdma2000HOStatus_PDU,
      { "Cdma2000HOStatus", "s1ap.Cdma2000HOStatus",
        FT_UINT32, BASE_DEC, VALS(s1ap_Cdma2000HOStatus_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_Cdma2000HORequiredIndication_PDU,
      { "Cdma2000HORequiredIndication", "s1ap.Cdma2000HORequiredIndication",
        FT_UINT32, BASE_DEC, VALS(s1ap_Cdma2000HORequiredIndication_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_Cdma2000OneXSRVCCInfo_PDU,
      { "Cdma2000OneXSRVCCInfo", "s1ap.Cdma2000OneXSRVCCInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Cdma2000OneXRAND_PDU,
      { "Cdma2000OneXRAND", "s1ap.Cdma2000OneXRAND",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CNDomain_PDU,
      { "CNDomain", "s1ap.CNDomain",
        FT_UINT32, BASE_DEC, VALS(s1ap_CNDomain_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_ConcurrentWarningMessageIndicator_PDU,
      { "ConcurrentWarningMessageIndicator", "s1ap.ConcurrentWarningMessageIndicator",
        FT_UINT32, BASE_DEC, VALS(s1ap_ConcurrentWarningMessageIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_CSFallbackIndicator_PDU,
      { "CSFallbackIndicator", "s1ap.CSFallbackIndicator",
        FT_UINT32, BASE_DEC, VALS(s1ap_CSFallbackIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_CSG_Id_PDU,
      { "CSG-Id", "s1ap.CSG_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CSG_IdList_PDU,
      { "CSG-IdList", "s1ap.CSG_IdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CSGMembershipStatus_PDU,
      { "CSGMembershipStatus", "s1ap.CSGMembershipStatus",
        FT_UINT32, BASE_DEC, VALS(s1ap_CSGMembershipStatus_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "s1ap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_DataCodingScheme_PDU,
      { "DataCodingScheme", "s1ap.DataCodingScheme",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Direct_Forwarding_Path_Availability_PDU,
      { "Direct-Forwarding-Path-Availability", "s1ap.Direct_Forwarding_Path_Availability",
        FT_UINT32, BASE_DEC, VALS(s1ap_Direct_Forwarding_Path_Availability_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_Data_Forwarding_Not_Possible_PDU,
      { "Data-Forwarding-Not-Possible", "s1ap.Data_Forwarding_Not_Possible",
        FT_UINT32, BASE_DEC, VALS(s1ap_Data_Forwarding_Not_Possible_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_s1ap_Global_ENB_ID_PDU,
      { "Global-ENB-ID", "s1ap.Global_ENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_s1ap_ENB_StatusTransfer_TransparentContainer_PDU,
      { "ENB-StatusTransfer-TransparentContainer", "s1ap.ENB_StatusTransfer_TransparentContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ENB_UE_S1AP_ID_PDU,
      { "ENB-UE-S1AP-ID", "s1ap.ENB_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ENBname_PDU,
      { "ENBname", "s1ap.ENBname",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABInformationListItem_PDU,
      { "E-RABInformationListItem", "s1ap.E_RABInformationListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABList_PDU,
      { "E-RABList", "s1ap.E_RABList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABItem_PDU,
      { "E-RABItem", "s1ap.E_RABItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_s1ap_EUTRAN_CGI_PDU,
      { "EUTRAN-CGI", "s1ap.EUTRAN_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_EUTRANRoundTripDelayEstimationInfo_PDU,
      { "EUTRANRoundTripDelayEstimationInfo", "s1ap.EUTRANRoundTripDelayEstimationInfo",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(s1ap_EUTRANRoundTripDelayEstimationInfo_fmt), 0,
        NULL, HFILL }},
    { &hf_s1ap_ExtendedRepetitionPeriod_PDU,
      { "ExtendedRepetitionPeriod", "s1ap.ExtendedRepetitionPeriod",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_s1ap_Group_S1AP_IDs_PDU,
      { "Group-S1AP-IDs", "s1ap.Group_S1AP_IDs",
        FT_UINT32, BASE_DEC, VALS(s1ap_Group_S1AP_IDs_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupIdentity_PDU,
      { "GroupIdentity", "s1ap.GroupIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TAIListItemGroupServiceArea_PDU,
      { "TAIListItemGroupServiceArea", "s1ap.TAIListItemGroupServiceArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CellListItemGroupServiceArea_PDU,
      { "CellListItemGroupServiceArea", "s1ap.CellListItemGroupServiceArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupConfigurationContainer_PDU,
      { "GroupConfigurationContainer", "s1ap.GroupConfigurationContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupConfigurationContainerItem_PDU,
      { "GroupConfigurationContainerItem", "s1ap.GroupConfigurationContainerItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupAggregateMaximumBitrate_PDU,
      { "GroupAggregateMaximumBitrate", "s1ap.GroupAggregateMaximumBitrate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MME_Group_S1AP_ID_PDU,
      { "MME-Group-S1AP-ID", "s1ap.MME_Group_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ReleaseGroupCallConfigurationItem_PDU,
      { "ReleaseGroupCallConfigurationItem", "s1ap.ReleaseGroupCallConfigurationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GUMMEI_PDU,
      { "GUMMEI", "s1ap.GUMMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_s1ap_HandoverRestrictionList_PDU,
      { "HandoverRestrictionList", "s1ap.HandoverRestrictionList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverType_PDU,
      { "HandoverType", "s1ap.HandoverType",
        FT_UINT32, BASE_DEC, VALS(s1ap_HandoverType_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_LAI_PDU,
      { "LAI", "s1ap.LAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_s1ap_LastVisitedEUTRANCellInformation_PDU,
      { "LastVisitedEUTRANCellInformation", "s1ap.LastVisitedEUTRANCellInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_s1ap_LastVisitedGERANCellInformation_PDU,
      { "LastVisitedGERANCellInformation", "s1ap.LastVisitedGERANCellInformation",
        FT_UINT32, BASE_DEC, VALS(s1ap_LastVisitedGERANCellInformation_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_LPPa_PDU_PDU,
      { "LPPa-PDU", "s1ap.LPPa_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MessageIdentifier_PDU,
      { "MessageIdentifier", "s1ap.MessageIdentifier",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &lte_rrc_messageIdentifier_vals_ext, 0,
        NULL, HFILL }},
    { &hf_s1ap_MMEname_PDU,
      { "MMEname", "s1ap.MMEname",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MME_UE_S1AP_ID_PDU,
      { "MME-UE-S1AP-ID", "s1ap.MME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MSClassmark2_PDU,
      { "MSClassmark2", "s1ap.MSClassmark2",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MSClassmark3_PDU,
      { "MSClassmark3", "s1ap.MSClassmark3",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_NAS_PDU_PDU,
      { "NAS-PDU", "s1ap.NAS_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_NASSecurityParametersfromE_UTRAN_PDU,
      { "NASSecurityParametersfromE-UTRAN", "s1ap.NASSecurityParametersfromE_UTRAN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_NASSecurityParameterstoE_UTRAN_PDU,
      { "NASSecurityParameterstoE-UTRAN", "s1ap.NASSecurityParameterstoE_UTRAN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_NumberofBroadcastRequest_PDU,
      { "NumberofBroadcastRequest", "s1ap.NumberofBroadcastRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_OverloadResponse_PDU,
      { "OverloadResponse", "s1ap.OverloadResponse",
        FT_UINT32, BASE_DEC, VALS(s1ap_OverloadResponse_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_PagingDRX_PDU,
      { "PagingDRX", "s1ap.PagingDRX",
        FT_UINT32, BASE_DEC, VALS(s1ap_PagingDRX_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_PS_ServiceNotAvailable_PDU,
      { "PS-ServiceNotAvailable", "s1ap.PS_ServiceNotAvailable",
        FT_UINT32, BASE_DEC, VALS(s1ap_PS_ServiceNotAvailable_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_NAS_PDUType_PDU,
      { "NAS-PDUType", "s1ap.NAS_PDUType",
        FT_UINT32, BASE_DEC, VALS(s1ap_NAS_PDUType_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_NeedResponse_PDU,
      { "NeedResponse", "s1ap.NeedResponse",
        FT_UINT32, BASE_DEC, VALS(s1ap_NeedResponse_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_RelativeMMECapacity_PDU,
      { "RelativeMMECapacity", "s1ap.RelativeMMECapacity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_RequestType_PDU,
      { "RequestType", "s1ap.RequestType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_RepetitionPeriod_PDU,
      { "RepetitionPeriod", "s1ap.RepetitionPeriod",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_s1ap_RRC_Establishment_Cause_PDU,
      { "RRC-Establishment-Cause", "s1ap.RRC_Establishment_Cause",
        FT_UINT32, BASE_DEC, VALS(s1ap_RRC_Establishment_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_Routing_ID_PDU,
      { "Routing-ID", "s1ap.Routing_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SecurityKey_PDU,
      { "SecurityKey", "s1ap.SecurityKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SecurityContext_PDU,
      { "SecurityContext", "s1ap.SecurityContext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SerialNumber_PDU,
      { "SerialNumber", "s1ap.SerialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SONConfigurationTransfer_PDU,
      { "SONConfigurationTransfer", "s1ap.SONConfigurationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Source_ToTarget_TransparentContainer_PDU,
      { "Source-ToTarget-TransparentContainer", "s1ap.Source_ToTarget_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SRVCCOperationPossible_PDU,
      { "SRVCCOperationPossible", "s1ap.SRVCCOperationPossible",
        FT_UINT32, BASE_DEC, VALS(s1ap_SRVCCOperationPossible_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_SRVCCHOIndication_PDU,
      { "SRVCCHOIndication", "s1ap.SRVCCHOIndication",
        FT_UINT32, BASE_DEC, VALS(s1ap_SRVCCHOIndication_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_s1ap_SourceeNB_ToTargeteNB_TransparentContainer_PDU,
      { "SourceeNB-ToTargeteNB-TransparentContainer", "s1ap.SourceeNB_ToTargeteNB_TransparentContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SourceeNB_List_PDU,
      { "SourceeNB-List", "s1ap.SourceeNB_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SourceeNB_Item_PDU,
      { "SourceeNB-Item", "s1ap.SourceeNB_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ServedGUMMEIs_PDU,
      { "ServedGUMMEIs", "s1ap.ServedGUMMEIs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ServedPLMNs_PDU,
      { "ServedPLMNs", "s1ap.ServedPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SubscriberProfileIDforRFP_PDU,
      { "SubscriberProfileIDforRFP", "s1ap.SubscriberProfileIDforRFP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SupportedTAs_PDU,
      { "SupportedTAs", "s1ap.SupportedTAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_S_TMSI_PDU,
      { "S-TMSI", "s1ap.S_TMSI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TAI_PDU,
      { "TAI", "s1ap.TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TargetID_PDU,
      { "TargetID", "s1ap.TargetID",
        FT_UINT32, BASE_DEC, VALS(s1ap_TargetID_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_TrunkingUserIndication_PDU,
      { "TrunkingUserIndication", "s1ap.TrunkingUserIndication",
        FT_UINT32, BASE_DEC, VALS(s1ap_TrunkingUserIndication_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABItem_PDU,
      { "TE-RABItem", "s1ap.TE_RABItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TargeteNB_List_PDU,
      { "TargeteNB-List", "s1ap.TargeteNB_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TargeteNB_Item_PDU,
      { "TargeteNB-Item", "s1ap.TargeteNB_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_s1ap_TargeteNB_ToSourceeNB_TransparentContainer_PDU,
      { "TargeteNB-ToSourceeNB-TransparentContainer", "s1ap.TargeteNB_ToSourceeNB_TransparentContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Target_ToSource_TransparentContainer_PDU,
      { "Target-ToSource-TransparentContainer", "s1ap.Target_ToSource_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TimeToWait_PDU,
      { "TimeToWait", "s1ap.TimeToWait",
        FT_UINT32, BASE_DEC, VALS(s1ap_TimeToWait_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_TransportLayerAddress_PDU,
      { "TransportLayerAddress", "s1ap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TraceActivation_PDU,
      { "TraceActivation", "s1ap.TraceActivation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_UTRAN_Trace_ID_PDU,
      { "E-UTRAN-Trace-ID", "s1ap.E_UTRAN_Trace_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UEAggregateMaximumBitrate_PDU,
      { "UEAggregateMaximumBitrate", "s1ap.UEAggregateMaximumBitrate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UE_S1AP_IDs_PDU,
      { "UE-S1AP-IDs", "s1ap.UE_S1AP_IDs",
        FT_UINT32, BASE_DEC, VALS(s1ap_UE_S1AP_IDs_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_UE_associatedLogicalS1_ConnectionItem_PDU,
      { "UE-associatedLogicalS1-ConnectionItem", "s1ap.UE_associatedLogicalS1_ConnectionItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UEIdentityIndexValue_PDU,
      { "UEIdentityIndexValue", "s1ap.UEIdentityIndexValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_s1ap_UE_HistoryInformation_PDU,
      { "UE-HistoryInformation", "s1ap.UE_HistoryInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UEPagingID_PDU,
      { "UEPagingID", "s1ap.UEPagingID",
        FT_UINT32, BASE_DEC, VALS(s1ap_UEPagingID_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_UERadioCapability_PDU,
      { "UERadioCapability", "s1ap.UERadioCapability",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UESecurityCapabilities_PDU,
      { "UESecurityCapabilities", "s1ap.UESecurityCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_WarningAreaList_PDU,
      { "WarningAreaList", "s1ap.WarningAreaList",
        FT_UINT32, BASE_DEC, VALS(s1ap_WarningAreaList_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_WarningType_PDU,
      { "WarningType", "s1ap.WarningType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_WarningSecurityInfo_PDU,
      { "WarningSecurityInfo", "s1ap.WarningSecurityInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_WarningMessageContents_PDU,
      { "WarningMessageContents", "s1ap.WarningMessageContents",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverRequired_PDU,
      { "HandoverRequired", "s1ap.HandoverRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverCommand_PDU,
      { "HandoverCommand", "s1ap.HandoverCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABSubjecttoDataForwardingList_PDU,
      { "E-RABSubjecttoDataForwardingList", "s1ap.E_RABSubjecttoDataForwardingList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABDataForwardingItem_PDU,
      { "E-RABDataForwardingItem", "s1ap.E_RABDataForwardingItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverPreparationFailure_PDU,
      { "HandoverPreparationFailure", "s1ap.HandoverPreparationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverRequest_PDU,
      { "HandoverRequest", "s1ap.HandoverRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSetupListHOReq_PDU,
      { "E-RABToBeSetupListHOReq", "s1ap.E_RABToBeSetupListHOReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSetupItemHOReq_PDU,
      { "E-RABToBeSetupItemHOReq", "s1ap.E_RABToBeSetupItemHOReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverRequestAcknowledge_PDU,
      { "HandoverRequestAcknowledge", "s1ap.HandoverRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABAdmittedList_PDU,
      { "E-RABAdmittedList", "s1ap.E_RABAdmittedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABAdmittedItem_PDU,
      { "E-RABAdmittedItem", "s1ap.E_RABAdmittedItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABFailedtoSetupListHOReqAck_PDU,
      { "E-RABFailedtoSetupListHOReqAck", "s1ap.E_RABFailedtoSetupListHOReqAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABFailedToSetupItemHOReqAck_PDU,
      { "E-RABFailedToSetupItemHOReqAck", "s1ap.E_RABFailedToSetupItemHOReqAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverFailure_PDU,
      { "HandoverFailure", "s1ap.HandoverFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverNotify_PDU,
      { "HandoverNotify", "s1ap.HandoverNotify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_PathSwitchRequest_PDU,
      { "PathSwitchRequest", "s1ap.PathSwitchRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSwitchedDLList_PDU,
      { "E-RABToBeSwitchedDLList", "s1ap.E_RABToBeSwitchedDLList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSwitchedDLItem_PDU,
      { "E-RABToBeSwitchedDLItem", "s1ap.E_RABToBeSwitchedDLItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_PathSwitchRequestAcknowledge_PDU,
      { "PathSwitchRequestAcknowledge", "s1ap.PathSwitchRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSwitchedULList_PDU,
      { "E-RABToBeSwitchedULList", "s1ap.E_RABToBeSwitchedULList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSwitchedULItem_PDU,
      { "E-RABToBeSwitchedULItem", "s1ap.E_RABToBeSwitchedULItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_PathSwitchRequestFailure_PDU,
      { "PathSwitchRequestFailure", "s1ap.PathSwitchRequestFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverCancel_PDU,
      { "HandoverCancel", "s1ap.HandoverCancel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_HandoverCancelAcknowledge_PDU,
      { "HandoverCancelAcknowledge", "s1ap.HandoverCancelAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABSetupRequest_PDU,
      { "E-RABSetupRequest", "s1ap.E_RABSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSetupListBearerSUReq_PDU,
      { "E-RABToBeSetupListBearerSUReq", "s1ap.E_RABToBeSetupListBearerSUReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSetupItemBearerSUReq_PDU,
      { "E-RABToBeSetupItemBearerSUReq", "s1ap.E_RABToBeSetupItemBearerSUReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABSetupResponse_PDU,
      { "E-RABSetupResponse", "s1ap.E_RABSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABSetupListBearerSURes_PDU,
      { "E-RABSetupListBearerSURes", "s1ap.E_RABSetupListBearerSURes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABSetupItemBearerSURes_PDU,
      { "E-RABSetupItemBearerSURes", "s1ap.E_RABSetupItemBearerSURes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABModifyRequest_PDU,
      { "E-RABModifyRequest", "s1ap.E_RABModifyRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeModifiedListBearerModReq_PDU,
      { "E-RABToBeModifiedListBearerModReq", "s1ap.E_RABToBeModifiedListBearerModReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeModifiedItemBearerModReq_PDU,
      { "E-RABToBeModifiedItemBearerModReq", "s1ap.E_RABToBeModifiedItemBearerModReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABModifyResponse_PDU,
      { "E-RABModifyResponse", "s1ap.E_RABModifyResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABModifyListBearerModRes_PDU,
      { "E-RABModifyListBearerModRes", "s1ap.E_RABModifyListBearerModRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABModifyItemBearerModRes_PDU,
      { "E-RABModifyItemBearerModRes", "s1ap.E_RABModifyItemBearerModRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABReleaseCommand_PDU,
      { "E-RABReleaseCommand", "s1ap.E_RABReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABReleaseResponse_PDU,
      { "E-RABReleaseResponse", "s1ap.E_RABReleaseResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABReleaseListBearerRelComp_PDU,
      { "E-RABReleaseListBearerRelComp", "s1ap.E_RABReleaseListBearerRelComp",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABReleaseItemBearerRelComp_PDU,
      { "E-RABReleaseItemBearerRelComp", "s1ap.E_RABReleaseItemBearerRelComp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABReleaseIndication_PDU,
      { "E-RABReleaseIndication", "s1ap.E_RABReleaseIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_InitialContextSetupRequest_PDU,
      { "InitialContextSetupRequest", "s1ap.InitialContextSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSetupListCtxtSUReq_PDU,
      { "E-RABToBeSetupListCtxtSUReq", "s1ap.E_RABToBeSetupListCtxtSUReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSetupItemCtxtSUReq_PDU,
      { "E-RABToBeSetupItemCtxtSUReq", "s1ap.E_RABToBeSetupItemCtxtSUReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_InitialContextSetupResponse_PDU,
      { "InitialContextSetupResponse", "s1ap.InitialContextSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABSetupListCtxtSURes_PDU,
      { "E-RABSetupListCtxtSURes", "s1ap.E_RABSetupListCtxtSURes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABSetupItemCtxtSURes_PDU,
      { "E-RABSetupItemCtxtSURes", "s1ap.E_RABSetupItemCtxtSURes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_InitialContextSetupFailure_PDU,
      { "InitialContextSetupFailure", "s1ap.InitialContextSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Paging_PDU,
      { "Paging", "s1ap.Paging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TAIList_PDU,
      { "TAIList", "s1ap.TAIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TAIItem_PDU,
      { "TAIItem", "s1ap.TAIItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UEContextReleaseRequest_PDU,
      { "UEContextReleaseRequest", "s1ap.UEContextReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UEContextReleaseCommand_PDU,
      { "UEContextReleaseCommand", "s1ap.UEContextReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UEContextReleaseComplete_PDU,
      { "UEContextReleaseComplete", "s1ap.UEContextReleaseComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UEContextModificationRequest_PDU,
      { "UEContextModificationRequest", "s1ap.UEContextModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UEContextModificationResponse_PDU,
      { "UEContextModificationResponse", "s1ap.UEContextModificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UEContextModificationFailure_PDU,
      { "UEContextModificationFailure", "s1ap.UEContextModificationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_DownlinkNASTransport_PDU,
      { "DownlinkNASTransport", "s1ap.DownlinkNASTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_InitialUEMessage_PDU,
      { "InitialUEMessage", "s1ap.InitialUEMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UplinkNASTransport_PDU,
      { "UplinkNASTransport", "s1ap.UplinkNASTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_NASNonDeliveryIndication_PDU,
      { "NASNonDeliveryIndication", "s1ap.NASNonDeliveryIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Reset_PDU,
      { "Reset", "s1ap.Reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ResetType_PDU,
      { "ResetType", "s1ap.ResetType",
        FT_UINT32, BASE_DEC, VALS(s1ap_ResetType_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_ResetAcknowledge_PDU,
      { "ResetAcknowledge", "s1ap.ResetAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UE_associatedLogicalS1_ConnectionListResAck_PDU,
      { "UE-associatedLogicalS1-ConnectionListResAck", "s1ap.UE_associatedLogicalS1_ConnectionListResAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ErrorIndication_PDU,
      { "ErrorIndication", "s1ap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_S1SetupRequest_PDU,
      { "S1SetupRequest", "s1ap.S1SetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_S1SetupResponse_PDU,
      { "S1SetupResponse", "s1ap.S1SetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_S1SetupFailure_PDU,
      { "S1SetupFailure", "s1ap.S1SetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ENBConfigurationUpdate_PDU,
      { "ENBConfigurationUpdate", "s1ap.ENBConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ENBConfigurationUpdateAcknowledge_PDU,
      { "ENBConfigurationUpdateAcknowledge", "s1ap.ENBConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ENBConfigurationUpdateFailure_PDU,
      { "ENBConfigurationUpdateFailure", "s1ap.ENBConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MMEConfigurationUpdate_PDU,
      { "MMEConfigurationUpdate", "s1ap.MMEConfigurationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MMEConfigurationUpdateAcknowledge_PDU,
      { "MMEConfigurationUpdateAcknowledge", "s1ap.MMEConfigurationUpdateAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MMEConfigurationUpdateFailure_PDU,
      { "MMEConfigurationUpdateFailure", "s1ap.MMEConfigurationUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UECapabilityInfoIndication_PDU,
      { "UECapabilityInfoIndication", "s1ap.UECapabilityInfoIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ENBStatusTransfer_PDU,
      { "ENBStatusTransfer", "s1ap.ENBStatusTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MMEStatusTransfer_PDU,
      { "MMEStatusTransfer", "s1ap.MMEStatusTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TraceStart_PDU,
      { "TraceStart", "s1ap.TraceStart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TraceFailureIndication_PDU,
      { "TraceFailureIndication", "s1ap.TraceFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_DeactivateTrace_PDU,
      { "DeactivateTrace", "s1ap.DeactivateTrace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CellTrafficTrace_PDU,
      { "CellTrafficTrace", "s1ap.CellTrafficTrace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_LocationReportingControl_PDU,
      { "LocationReportingControl", "s1ap.LocationReportingControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_LocationReportingFailureIndication_PDU,
      { "LocationReportingFailureIndication", "s1ap.LocationReportingFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_LocationReport_PDU,
      { "LocationReport", "s1ap.LocationReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_OverloadStart_PDU,
      { "OverloadStart", "s1ap.OverloadStart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_OverloadStop_PDU,
      { "OverloadStop", "s1ap.OverloadStop_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_WriteReplaceWarningRequest_PDU,
      { "WriteReplaceWarningRequest", "s1ap.WriteReplaceWarningRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_WriteReplaceWarningResponse_PDU,
      { "WriteReplaceWarningResponse", "s1ap.WriteReplaceWarningResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ENBDirectInformationTransfer_PDU,
      { "ENBDirectInformationTransfer", "s1ap.ENBDirectInformationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Inter_SystemInformationTransferType_PDU,
      { "Inter-SystemInformationTransferType", "s1ap.Inter_SystemInformationTransferType",
        FT_UINT32, BASE_DEC, VALS(s1ap_Inter_SystemInformationTransferType_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_MMEDirectInformationTransfer_PDU,
      { "MMEDirectInformationTransfer", "s1ap.MMEDirectInformationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ENBConfigurationTransfer_PDU,
      { "ENBConfigurationTransfer", "s1ap.ENBConfigurationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MMEConfigurationTransfer_PDU,
      { "MMEConfigurationTransfer", "s1ap.MMEConfigurationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_PrivateMessage_PDU,
      { "PrivateMessage", "s1ap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_KillRequest_PDU,
      { "KillRequest", "s1ap.KillRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_KillResponse_PDU,
      { "KillResponse", "s1ap.KillResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_DownlinkUEAssociatedLPPaTransport_PDU,
      { "DownlinkUEAssociatedLPPaTransport", "s1ap.DownlinkUEAssociatedLPPaTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UplinkUEAssociatedLPPaTransport_PDU,
      { "UplinkUEAssociatedLPPaTransport", "s1ap.UplinkUEAssociatedLPPaTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_DownlinkNonUEAssociatedLPPaTransport_PDU,
      { "DownlinkNonUEAssociatedLPPaTransport", "s1ap.DownlinkNonUEAssociatedLPPaTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UplinkNonUEAssociatedLPPaTransport_PDU,
      { "UplinkNonUEAssociatedLPPaTransport", "s1ap.UplinkNonUEAssociatedLPPaTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupCallContextSetupRequest_PDU,
      { "GroupCallContextSetupRequest", "s1ap.GroupCallContextSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABToBeSetupListGroupCtxtSUReq_PDU,
      { "TE-RABToBeSetupListGroupCtxtSUReq", "s1ap.TE_RABToBeSetupListGroupCtxtSUReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABToBeSetupItemGroupCtxtSUReq_PDU,
      { "TE-RABToBeSetupItemGroupCtxtSUReq", "s1ap.TE_RABToBeSetupItemGroupCtxtSUReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupCallContextSetupResponse_PDU,
      { "GroupCallContextSetupResponse", "s1ap.GroupCallContextSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABSetupListGroupCtxtSURes_PDU,
      { "TE-RABSetupListGroupCtxtSURes", "s1ap.TE_RABSetupListGroupCtxtSURes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABSetupItemGroupCtxtSURes_PDU,
      { "TE-RABSetupItemGroupCtxtSURes", "s1ap.TE_RABSetupItemGroupCtxtSURes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupCallContextSetupFailure_PDU,
      { "GroupCallContextSetupFailure", "s1ap.GroupCallContextSetupFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupCallContextModificationRequest_PDU,
      { "GroupCallContextModificationRequest", "s1ap.GroupCallContextModificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupCallContextModificationResponse_PDU,
      { "GroupCallContextModificationResponse", "s1ap.GroupCallContextModificationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupCallContextReleaseCommand_PDU,
      { "GroupCallContextReleaseCommand", "s1ap.GroupCallContextReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupCallContextReleaseComplete_PDU,
      { "GroupCallContextReleaseComplete", "s1ap.GroupCallContextReleaseComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupCallContextReleaseIndication_PDU,
      { "GroupCallContextReleaseIndication", "s1ap.GroupCallContextReleaseIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_InstantGroupCallConfigNotify_PDU,
      { "InstantGroupCallConfigNotify", "s1ap.InstantGroupCallConfigNotify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TrunkingIndividualPaging_PDU,
      { "TrunkingIndividualPaging", "s1ap.TrunkingIndividualPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ListOfTargetTAIsTrunkingIndividualPaging_PDU,
      { "ListOfTargetTAIsTrunkingIndividualPaging", "s1ap.ListOfTargetTAIsTrunkingIndividualPaging",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ListOfTargetTAIsItemTrunkingIndividualPaging_PDU,
      { "ListOfTargetTAIsItemTrunkingIndividualPaging", "s1ap.ListOfTargetTAIsItemTrunkingIndividualPaging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupDownlinkNASTransport_PDU,
      { "GroupDownlinkNASTransport", "s1ap.GroupDownlinkNASTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TrunkingErrorIndication_PDU,
      { "TrunkingErrorIndication", "s1ap.TrunkingErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupReset_PDU,
      { "GroupReset", "s1ap.GroupReset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupResetType_PDU,
      { "GroupResetType", "s1ap.GroupResetType",
        FT_UINT32, BASE_DEC, VALS(s1ap_GroupResetType_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_Group_associatedLogicalS1_ConnectionItemGroupReset_PDU,
      { "Group-associatedLogicalS1-ConnectionItemGroupReset", "s1ap.Group_associatedLogicalS1_ConnectionItemGroupReset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck_PDU,
      { "Group-associatedLogicalS1-ConnectionListGroupResetAck", "s1ap.Group_associatedLogicalS1_ConnectionListGroupResetAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Group_associatedLogicalS1_ConnectionItemGroupResetAck_PDU,
      { "Group-associatedLogicalS1-ConnectionItemGroupResetAck", "s1ap.Group_associatedLogicalS1_ConnectionItemGroupResetAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupTE_RABSetupRequest_PDU,
      { "GroupTE-RABSetupRequest", "s1ap.GroupTE_RABSetupRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABToBeSetupListGroupBearerSUReq_PDU,
      { "TE-RABToBeSetupListGroupBearerSUReq", "s1ap.TE_RABToBeSetupListGroupBearerSUReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABToBeSetupItemGroupBearerSUReq_PDU,
      { "TE-RABToBeSetupItemGroupBearerSUReq", "s1ap.TE_RABToBeSetupItemGroupBearerSUReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupTE_RABSetupResponse_PDU,
      { "GroupTE-RABSetupResponse", "s1ap.GroupTE_RABSetupResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABSetupListGroupBearerSURes_PDU,
      { "TE-RABSetupListGroupBearerSURes", "s1ap.TE_RABSetupListGroupBearerSURes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABSetupItemGroupBearerSURes_PDU,
      { "TE-RABSetupItemGroupBearerSURes", "s1ap.TE_RABSetupItemGroupBearerSURes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupTE_RABModifyRequest_PDU,
      { "GroupTE-RABModifyRequest", "s1ap.GroupTE_RABModifyRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABToBeModifiedListGroupBearerModReq_PDU,
      { "TE-RABToBeModifiedListGroupBearerModReq", "s1ap.TE_RABToBeModifiedListGroupBearerModReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABToBeModifiedItemGroupBearerModReq_PDU,
      { "TE-RABToBeModifiedItemGroupBearerModReq", "s1ap.TE_RABToBeModifiedItemGroupBearerModReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupTE_RABModifyResponse_PDU,
      { "GroupTE-RABModifyResponse", "s1ap.GroupTE_RABModifyResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABModifyListGroupBearerModRes_PDU,
      { "TE-RABModifyListGroupBearerModRes", "s1ap.TE_RABModifyListGroupBearerModRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABModifyItemGroupBearerModRes_PDU,
      { "TE-RABModifyItemGroupBearerModRes", "s1ap.TE_RABModifyItemGroupBearerModRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupTE_RABReleaseCommand_PDU,
      { "GroupTE-RABReleaseCommand", "s1ap.GroupTE_RABReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupTE_RABReleaseResponse_PDU,
      { "GroupTE-RABReleaseResponse", "s1ap.GroupTE_RABReleaseResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABReleaseListGroupBearerRelRes_PDU,
      { "TE-RABReleaseListGroupBearerRelRes", "s1ap.TE_RABReleaseListGroupBearerRelRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABReleaseItemGroupBearerRelRes_PDU,
      { "TE-RABReleaseItemGroupBearerRelRes", "s1ap.TE_RABReleaseItemGroupBearerRelRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupTE_RABReleaseIndication_PDU,
      { "GroupTE-RABReleaseIndication", "s1ap.GroupTE_RABReleaseIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TrunkingMessageTransport_PDU,
      { "TrunkingMessageTransport", "s1ap.TrunkingMessageTransport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TrunkingServingCellUpdateIndication_PDU,
      { "TrunkingServingCellUpdateIndication", "s1ap.TrunkingServingCellUpdateIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_MMEGroupCallConfigurationTransfer_PDU,
      { "MMEGroupCallConfigurationTransfer", "s1ap.MMEGroupCallConfigurationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_S1AP_PDU_PDU,
      { "S1AP-PDU", "s1ap.S1AP_PDU",
        FT_UINT32, BASE_DEC, VALS(s1ap_S1AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_local,
      { "local", "s1ap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_s1ap_global,
      { "global", "s1ap.global",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "s1ap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_id,
      { "id", "s1ap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &s1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_s1ap_criticality,
      { "criticality", "s1ap.criticality",
        FT_UINT32, BASE_DEC, VALS(s1ap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_ie_field_value,
      { "value", "s1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_s1ap_ProtocolIE_ContainerList_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "s1ap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ext_id,
      { "id", "s1ap.id",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &s1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_s1ap_extensionValue,
      { "extensionValue", "s1ap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_PrivateIE_Container_item,
      { "PrivateIE-Field", "s1ap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_private_id,
      { "id", "s1ap.id",
        FT_UINT32, BASE_DEC, VALS(s1ap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_s1ap_value,
      { "value", "s1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_priorityLevel,
      { "priorityLevel", "s1ap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(s1ap_PriorityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_pre_emptionCapability,
      { "pre-emptionCapability", "s1ap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(s1ap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "s1ap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(s1ap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_iE_Extensions,
      { "iE-Extensions", "s1ap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_s1ap_AddModGroupCallConfigurationList_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_eCGI,
      { "eCGI", "s1ap.eCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRAN_CGI", HFILL }},
    { &hf_s1ap_groupRRC_Container,
      { "groupRRC-Container", "s1ap.groupRRC_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RRC_Container", HFILL }},
    { &hf_s1ap_Bearers_SubjectToStatusTransferList_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_e_RAB_ID,
      { "e-RAB-ID", "s1ap.e_RAB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_uL_COUNTvalue,
      { "uL-COUNTvalue", "s1ap.uL_COUNTvalue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTvalue", HFILL }},
    { &hf_s1ap_dL_COUNTvalue,
      { "dL-COUNTvalue", "s1ap.dL_COUNTvalue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "COUNTvalue", HFILL }},
    { &hf_s1ap_receiveStatusofULPDCPSDUs,
      { "receiveStatusofULPDCPSDUs", "s1ap.receiveStatusofULPDCPSDUs",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_BPLMNs_item,
      { "PLMNidentity", "s1ap.PLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cellID_Cancelled,
      { "cellID-Cancelled", "s1ap.cellID_Cancelled",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_tAI_Cancelled,
      { "tAI-Cancelled", "s1ap.tAI_Cancelled",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_emergencyAreaID_Cancelled,
      { "emergencyAreaID-Cancelled", "s1ap.emergencyAreaID_Cancelled",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cellID_Broadcast,
      { "cellID-Broadcast", "s1ap.cellID_Broadcast",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_tAI_Broadcast,
      { "tAI-Broadcast", "s1ap.tAI_Broadcast",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_emergencyAreaID_Broadcast,
      { "emergencyAreaID-Broadcast", "s1ap.emergencyAreaID_Broadcast",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CancelledCellinEAI_item,
      { "CancelledCellinEAI-Item", "s1ap.CancelledCellinEAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_numberOfBroadcasts,
      { "numberOfBroadcasts", "s1ap.numberOfBroadcasts",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CancelledCellinTAI_item,
      { "CancelledCellinTAI-Item", "s1ap.CancelledCellinTAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_radioNetwork,
      { "radioNetwork", "s1ap.radioNetwork",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &s1ap_CauseRadioNetwork_vals_ext, 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_s1ap_transport,
      { "transport", "s1ap.transport",
        FT_UINT32, BASE_DEC, VALS(s1ap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_s1ap_nas,
      { "nas", "s1ap.nas",
        FT_UINT32, BASE_DEC, VALS(s1ap_CauseNas_vals), 0,
        "CauseNas", HFILL }},
    { &hf_s1ap_protocol,
      { "protocol", "s1ap.protocol",
        FT_UINT32, BASE_DEC, VALS(s1ap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_s1ap_misc,
      { "misc", "s1ap.misc",
        FT_UINT32, BASE_DEC, VALS(s1ap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_s1ap_CellID_Broadcast_item,
      { "CellID-Broadcast-Item", "s1ap.CellID_Broadcast_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CellID_Cancelled_item,
      { "CellID-Cancelled-Item", "s1ap.CellID_Cancelled_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cdma2000OneXMEID,
      { "cdma2000OneXMEID", "s1ap.cdma2000OneXMEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cdma2000OneXMSI,
      { "cdma2000OneXMSI", "s1ap.cdma2000OneXMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cdma2000OneXPilot,
      { "cdma2000OneXPilot", "s1ap.cdma2000OneXPilot",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cell_Size,
      { "cell-Size", "s1ap.cell_Size",
        FT_UINT32, BASE_DEC, VALS(s1ap_Cell_Size_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_pLMNidentity,
      { "pLMNidentity", "s1ap.pLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_lAC,
      { "lAC", "s1ap.lAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cI,
      { "cI", "s1ap.cI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_rAC,
      { "rAC", "s1ap.rAC",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CSG_IdList_item,
      { "CSG-IdList-Item", "s1ap.CSG_IdList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cSG_Id,
      { "cSG-Id", "s1ap.cSG_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_pDCP_SN,
      { "pDCP-SN", "s1ap.pDCP_SN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_hFN,
      { "hFN", "s1ap.hFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_procedureCode,
      { "procedureCode", "s1ap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &s1ap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_s1ap_triggeringMessage,
      { "triggeringMessage", "s1ap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(s1ap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_procedureCriticality,
      { "procedureCriticality", "s1ap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(s1ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_s1ap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "s1ap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_s1ap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-Item", "s1ap.CriticalityDiagnostics_IE_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_iECriticality,
      { "iECriticality", "s1ap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(s1ap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_s1ap_iE_ID,
      { "iE-ID", "s1ap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &s1ap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_s1ap_typeOfError,
      { "typeOfError", "s1ap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(s1ap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_ECGIList_item,
      { "EUTRAN-CGI", "s1ap.EUTRAN_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_EmergencyAreaIDList_item,
      { "EmergencyAreaID", "s1ap.EmergencyAreaID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_EmergencyAreaID_Broadcast_item,
      { "EmergencyAreaID-Broadcast-Item", "s1ap.EmergencyAreaID_Broadcast_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_emergencyAreaID,
      { "emergencyAreaID", "s1ap.emergencyAreaID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_completedCellinEAI,
      { "completedCellinEAI", "s1ap.completedCellinEAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_EmergencyAreaID_Cancelled_item,
      { "EmergencyAreaID-Cancelled-Item", "s1ap.EmergencyAreaID_Cancelled_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cancelledCellinEAI,
      { "cancelledCellinEAI", "s1ap.cancelledCellinEAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CompletedCellinEAI_item,
      { "CompletedCellinEAI-Item", "s1ap.CompletedCellinEAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_macroENB_ID,
      { "macroENB-ID", "s1ap.macroENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_s1ap_homeENB_ID,
      { "homeENB-ID", "s1ap.homeENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_s1ap_lAI,
      { "lAI", "s1ap.lAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_eNB_ID,
      { "eNB-ID", "s1ap.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(s1ap_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_bearers_SubjectToStatusTransferList,
      { "bearers-SubjectToStatusTransferList", "s1ap.bearers_SubjectToStatusTransferList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ENBX2TLAs_item,
      { "TransportLayerAddress", "s1ap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_EPLMNs_item,
      { "PLMNidentity", "s1ap.PLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABInformationList_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_dL_Forwarding,
      { "dL-Forwarding", "s1ap.dL_Forwarding",
        FT_UINT32, BASE_DEC, VALS(s1ap_DL_Forwarding_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABList_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cause,
      { "cause", "s1ap.cause",
        FT_UINT32, BASE_DEC, VALS(s1ap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_qCI,
      { "qCI", "s1ap.qCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_allocationRetentionPriority,
      { "allocationRetentionPriority", "s1ap.allocationRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AllocationAndRetentionPriority", HFILL }},
    { &hf_s1ap_gbrQosInformation,
      { "gbrQosInformation", "s1ap.gbrQosInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GBR_QosInformation", HFILL }},
    { &hf_s1ap_cell_ID,
      { "cell-ID", "s1ap.CellIdentity",
        FT_UINT32, BASE_HEX, NULL, 0,
        "CellIdentity", HFILL }},
    { &hf_s1ap_ForbiddenTAs_item,
      { "ForbiddenTAs-Item", "s1ap.ForbiddenTAs_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_pLMN_Identity,
      { "pLMN-Identity", "s1ap.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNidentity", HFILL }},
    { &hf_s1ap_forbiddenTACs,
      { "forbiddenTACs", "s1ap.forbiddenTACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ForbiddenTACs_item,
      { "TAC", "s1ap.TAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ForbiddenLAs_item,
      { "ForbiddenLAs-Item", "s1ap.ForbiddenLAs_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_forbiddenLACs,
      { "forbiddenLACs", "s1ap.forbiddenLACs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ForbiddenLACs_item,
      { "LAC", "s1ap.LAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_e_RAB_MaximumBitrateDL,
      { "e-RAB-MaximumBitrateDL", "s1ap.e_RAB_MaximumBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_s1ap_e_RAB_MaximumBitrateUL,
      { "e-RAB-MaximumBitrateUL", "s1ap.e_RAB_MaximumBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_s1ap_e_RAB_GuaranteedBitrateDL,
      { "e-RAB-GuaranteedBitrateDL", "s1ap.e_RAB_GuaranteedBitrateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_s1ap_e_RAB_GuaranteedBitrateUL,
      { "e-RAB-GuaranteedBitrateUL", "s1ap.e_RAB_GuaranteedBitrateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_s1ap_group_S1AP_ID_pair,
      { "group-S1AP-ID-pair", "s1ap.group_S1AP_ID_pair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_mME_Group_S1AP_ID,
      { "mME-Group-S1AP-ID", "s1ap.mME_Group_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_eNB_Group_S1AP_ID,
      { "eNB-Group-S1AP-ID", "s1ap.eNB_Group_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_tAIList,
      { "tAIList", "s1ap.tAIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TAIListGroupServiceArea", HFILL }},
    { &hf_s1ap_cellList,
      { "cellList", "s1ap.cellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellListGroupServiceArea", HFILL }},
    { &hf_s1ap_TAIListGroupServiceArea_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_tAI,
      { "tAI", "s1ap.tAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CellListGroupServiceArea_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_groupCallcipheringAlgorithm,
      { "groupCallcipheringAlgorithm", "s1ap.groupCallcipheringAlgorithm",
        FT_UINT32, BASE_DEC, VALS(s1ap_GroupCallcipheringAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_groupCallintegrityProtAlgorithm,
      { "groupCallintegrityProtAlgorithm", "s1ap.groupCallintegrityProtAlgorithm",
        FT_UINT32, BASE_DEC, VALS(s1ap_GroupCallintegrityProtAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_groupCallSecurityKey,
      { "groupCallSecurityKey", "s1ap.groupCallSecurityKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SecurityKey", HFILL }},
    { &hf_s1ap_randGroup,
      { "randGroup", "s1ap.randGroup",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_securityAlgorithms,
      { "securityAlgorithms", "s1ap.securityAlgorithms_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GroupCallAlgorithms", HFILL }},
    { &hf_s1ap_gkVersion,
      { "gkVersion", "s1ap.gkVersion",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_groupConfigurationContainerList,
      { "groupConfigurationContainerList", "s1ap.groupConfigurationContainerList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_GroupConfigurationContainerList_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_groupIdentity,
      { "groupIdentity", "s1ap.groupIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_addModGroupCallConfigurationList,
      { "addModGroupCallConfigurationList", "s1ap.addModGroupCallConfigurationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_releaseGroupCallConfigurationList,
      { "releaseGroupCallConfigurationList", "s1ap.releaseGroupCallConfigurationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_groupaggregateMaximumBitRate,
      { "groupaggregateMaximumBitRate", "s1ap.groupaggregateMaximumBitRate",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_s1ap_te_RAB_MaximumBitrate,
      { "te-RAB-MaximumBitrate", "s1ap.te_RAB_MaximumBitrate",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_s1ap_te_RAB_GuaranteedBitrate,
      { "te-RAB-GuaranteedBitrate", "s1ap.te_RAB_GuaranteedBitrate",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_s1ap_ReleaseGroupCallConfigurationList_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ecgi,
      { "ecgi", "s1ap.ecgi_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRAN_CGI", HFILL }},
    { &hf_s1ap_mME_Group_ID,
      { "mME-Group-ID", "s1ap.mME_Group_ID",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_mME_Code,
      { "mME-Code", "s1ap.mME_Code",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_servingPLMN,
      { "servingPLMN", "s1ap.servingPLMN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNidentity", HFILL }},
    { &hf_s1ap_equivalentPLMNs,
      { "equivalentPLMNs", "s1ap.equivalentPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EPLMNs", HFILL }},
    { &hf_s1ap_forbiddenTAs,
      { "forbiddenTAs", "s1ap.forbiddenTAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_forbiddenLAs,
      { "forbiddenLAs", "s1ap.forbiddenLAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_forbiddenInterRATs,
      { "forbiddenInterRATs", "s1ap.forbiddenInterRATs",
        FT_UINT32, BASE_DEC, VALS(s1ap_ForbiddenInterRATs_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_e_UTRAN_Cell,
      { "e-UTRAN-Cell", "s1ap.e_UTRAN_Cell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LastVisitedEUTRANCellInformation", HFILL }},
    { &hf_s1ap_uTRAN_Cell,
      { "uTRAN-Cell", "s1ap.uTRAN_Cell",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LastVisitedUTRANCellInformation", HFILL }},
    { &hf_s1ap_gERAN_Cell,
      { "gERAN-Cell", "s1ap.gERAN_Cell",
        FT_UINT32, BASE_DEC, VALS(s1ap_LastVisitedGERANCellInformation_vals), 0,
        "LastVisitedGERANCellInformation", HFILL }},
    { &hf_s1ap_global_Cell_ID,
      { "global-Cell-ID", "s1ap.global_Cell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRAN_CGI", HFILL }},
    { &hf_s1ap_cellType,
      { "cellType", "s1ap.cellType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_time_UE_StayedInCell,
      { "time-UE-StayedInCell", "s1ap.time_UE_StayedInCell",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        NULL, HFILL }},
    { &hf_s1ap_undefined,
      { "undefined", "s1ap.undefined_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_overloadAction,
      { "overloadAction", "s1ap.overloadAction",
        FT_UINT32, BASE_DEC, VALS(s1ap_OverloadAction_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_eventType,
      { "eventType", "s1ap.eventType",
        FT_UINT32, BASE_DEC, VALS(s1ap_EventType_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_reportArea,
      { "reportArea", "s1ap.reportArea",
        FT_UINT32, BASE_DEC, VALS(s1ap_ReportArea_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_rIMInformation,
      { "rIMInformation", "s1ap.rIMInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_rIMRoutingAddress,
      { "rIMRoutingAddress", "s1ap.rIMRoutingAddress",
        FT_UINT32, BASE_DEC, VALS(s1ap_RIMRoutingAddress_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_gERAN_Cell_ID,
      { "gERAN-Cell-ID", "s1ap.gERAN_Cell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_targetRNC_ID,
      { "targetRNC-ID", "s1ap.targetRNC_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_nextHopChainingCount,
      { "nextHopChainingCount", "s1ap.nextHopChainingCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_s1ap_nextHopParameter,
      { "nextHopParameter", "s1ap.nextHopParameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SecurityKey", HFILL }},
    { &hf_s1ap_sONInformationRequest,
      { "sONInformationRequest", "s1ap.sONInformationRequest",
        FT_UINT32, BASE_DEC, VALS(s1ap_SONInformationRequest_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_sONInformationReply,
      { "sONInformationReply", "s1ap.sONInformationReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_x2TNLConfigurationInfo,
      { "x2TNLConfigurationInfo", "s1ap.x2TNLConfigurationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_targeteNB_ID,
      { "targeteNB-ID", "s1ap.targeteNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_sourceeNB_ID,
      { "sourceeNB-ID", "s1ap.sourceeNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_sONInformation,
      { "sONInformation", "s1ap.sONInformation",
        FT_UINT32, BASE_DEC, VALS(s1ap_SONInformation_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_global_ENB_ID,
      { "global-ENB-ID", "s1ap.global_ENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_selected_TAI,
      { "selected-TAI", "s1ap.selected_TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TAI", HFILL }},
    { &hf_s1ap_rRC_Container,
      { "rRC-Container", "s1ap.rRC_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_e_RABInformationList,
      { "e-RABInformationList", "s1ap.e_RABInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_targetCell_ID,
      { "targetCell-ID", "s1ap.targetCell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EUTRAN_CGI", HFILL }},
    { &hf_s1ap_subscriberProfileIDforRFP,
      { "subscriberProfileIDforRFP", "s1ap.subscriberProfileIDforRFP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_uE_HistoryInformation,
      { "uE-HistoryInformation", "s1ap.uE_HistoryInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SourceeNB_List_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_needResponse,
      { "needResponse", "s1ap.needResponse",
        FT_UINT32, BASE_DEC, VALS(s1ap_NeedResponse_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_groupConfigurationContainer,
      { "groupConfigurationContainer", "s1ap.groupConfigurationContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ServedGUMMEIs_item,
      { "ServedGUMMEIsItem", "s1ap.ServedGUMMEIsItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_servedPLMNs,
      { "servedPLMNs", "s1ap.servedPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_servedGroupIDs,
      { "servedGroupIDs", "s1ap.servedGroupIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_servedMMECs,
      { "servedMMECs", "s1ap.servedMMECs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ServedGroupIDs_item,
      { "MME-Group-ID", "s1ap.MME_Group_ID",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ServedMMECs_item,
      { "MME-Code", "s1ap.MME_Code",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ServedPLMNs_item,
      { "PLMNidentity", "s1ap.PLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_SupportedTAs_item,
      { "SupportedTAs-Item", "s1ap.SupportedTAs_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_tAC,
      { "tAC", "s1ap.tAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_broadcastPLMNs,
      { "broadcastPLMNs", "s1ap.broadcastPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BPLMNs", HFILL }},
    { &hf_s1ap_stratumLevel,
      { "stratumLevel", "s1ap.stratumLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_synchronizationStatus,
      { "synchronizationStatus", "s1ap.synchronizationStatus",
        FT_UINT32, BASE_DEC, VALS(s1ap_SynchronizationStatus_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_mMEC,
      { "mMEC", "s1ap.mMEC",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        "MME_Code", HFILL }},
    { &hf_s1ap_m_TMSI,
      { "m-TMSI", "s1ap.m_TMSI",
        FT_UINT32, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TAIListforWarning_item,
      { "TAI", "s1ap.TAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TAI_Broadcast_item,
      { "TAI-Broadcast-Item", "s1ap.TAI_Broadcast_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_completedCellinTAI,
      { "completedCellinTAI", "s1ap.completedCellinTAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TAI_Cancelled_item,
      { "TAI-Cancelled-Item", "s1ap.TAI_Cancelled_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cancelledCellinTAI,
      { "cancelledCellinTAI", "s1ap.cancelledCellinTAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_CompletedCellinTAI_item,
      { "CompletedCellinTAI-Item", "s1ap.CompletedCellinTAI_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cGI,
      { "cGI", "s1ap.cGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABList_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_tE_RAB_ID,
      { "tE-RAB-ID", "s1ap.tE_RAB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_groupGbrQosInformation,
      { "groupGbrQosInformation", "s1ap.groupGbrQosInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Group_GBR_QosInformation", HFILL }},
    { &hf_s1ap_TargeteNB_List_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_rNC_ID,
      { "rNC-ID", "s1ap.rNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_extendedRNC_ID,
      { "extendedRNC-ID", "s1ap.extendedRNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_e_UTRAN_Trace_ID,
      { "e-UTRAN-Trace-ID", "s1ap.e_UTRAN_Trace_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace,
      { "interfacesToTrace", "s1ap.interfacesToTrace",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_traceDepth,
      { "traceDepth", "s1ap.traceDepth",
        FT_UINT32, BASE_DEC, VALS(s1ap_TraceDepth_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_traceCollectionEntityIPAddress,
      { "traceCollectionEntityIPAddress", "s1ap.traceCollectionEntityIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_s1ap_uEaggregateMaximumBitRateDL,
      { "uEaggregateMaximumBitRateDL", "s1ap.uEaggregateMaximumBitRateDL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_s1ap_uEaggregateMaximumBitRateUL,
      { "uEaggregateMaximumBitRateUL", "s1ap.uEaggregateMaximumBitRateUL",
        FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_bit_sec, 0,
        "BitRate", HFILL }},
    { &hf_s1ap_uE_S1AP_ID_pair,
      { "uE-S1AP-ID-pair", "s1ap.uE_S1AP_ID_pair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_mME_UE_S1AP_ID,
      { "mME-UE-S1AP-ID", "s1ap.mME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_eNB_UE_S1AP_ID,
      { "eNB-UE-S1AP-ID", "s1ap.eNB_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UE_HistoryInformation_item,
      { "LastVisitedCell-Item", "s1ap.LastVisitedCell_Item",
        FT_UINT32, BASE_DEC, VALS(s1ap_LastVisitedCell_Item_vals), 0,
        NULL, HFILL }},
    { &hf_s1ap_s_TMSI,
      { "s-TMSI", "s1ap.s_TMSI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_iMSI,
      { "iMSI", "s1ap.iMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_encryptionAlgorithms,
      { "encryptionAlgorithms", "s1ap.encryptionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_integrityProtectionAlgorithms,
      { "integrityProtectionAlgorithms", "s1ap.integrityProtectionAlgorithms",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_cellIDList,
      { "cellIDList", "s1ap.cellIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ECGIList", HFILL }},
    { &hf_s1ap_trackingAreaListforWarning,
      { "trackingAreaListforWarning", "s1ap.trackingAreaListforWarning",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TAIListforWarning", HFILL }},
    { &hf_s1ap_emergencyAreaIDList,
      { "emergencyAreaIDList", "s1ap.emergencyAreaIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_eNBX2TransportLayerAddresses,
      { "eNBX2TransportLayerAddresses", "s1ap.eNBX2TransportLayerAddresses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ENBX2TLAs", HFILL }},
    { &hf_s1ap_protocolIEs,
      { "protocolIEs", "s1ap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_s1ap_dL_transportLayerAddress,
      { "dL-transportLayerAddress", "s1ap.dL_transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_s1ap_dL_gTP_TEID,
      { "dL-gTP-TEID", "s1ap.dL_gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GTP_TEID", HFILL }},
    { &hf_s1ap_uL_TransportLayerAddress,
      { "uL-TransportLayerAddress", "s1ap.uL_TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_s1ap_uL_GTP_TEID,
      { "uL-GTP-TEID", "s1ap.uL_GTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GTP_TEID", HFILL }},
    { &hf_s1ap_transportLayerAddress,
      { "transportLayerAddress", "s1ap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_gTP_TEID,
      { "gTP-TEID", "s1ap.gTP_TEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_e_RABlevelQosParameters,
      { "e-RABlevelQosParameters", "s1ap.e_RABlevelQosParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSetupListBearerSUReq_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_e_RABlevelQoSParameters,
      { "e-RABlevelQoSParameters", "s1ap.e_RABlevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_nAS_PDU,
      { "nAS-PDU", "s1ap.nAS_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABSetupListBearerSURes_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeModifiedListBearerModReq_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_e_RABLevelQoSParameters,
      { "e-RABLevelQoSParameters", "s1ap.e_RABLevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABModifyListBearerModRes_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABReleaseListBearerRelComp_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABToBeSetupListCtxtSUReq_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_RABSetupListCtxtSURes_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TAIList_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_s1_Interface,
      { "s1-Interface", "s1ap.s1_Interface",
        FT_UINT32, BASE_DEC, VALS(s1ap_ResetAll_vals), 0,
        "ResetAll", HFILL }},
    { &hf_s1ap_partOfS1_Interface,
      { "partOfS1-Interface", "s1ap.partOfS1_Interface",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UE_associatedLogicalS1_ConnectionListRes", HFILL }},
    { &hf_s1ap_UE_associatedLogicalS1_ConnectionListRes_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_UE_associatedLogicalS1_ConnectionListResAck_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_rIMTransfer,
      { "rIMTransfer", "s1ap.rIMTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_privateIEs,
      { "privateIEs", "s1ap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_s1ap_TE_RABToBeSetupListGroupCtxtSUReq_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_tE_RABlevelQosParameters,
      { "tE-RABlevelQosParameters", "s1ap.tE_RABlevelQosParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_transportType,
      { "transportType", "s1ap.transportType",
        FT_UINT32, BASE_DEC, VALS(s1ap_TransportTypeGroupCtxtSUReq_vals), 0,
        "TransportTypeGroupCtxtSUReq", HFILL }},
    { &hf_s1ap_unicast,
      { "unicast", "s1ap.unicast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnicastTransportTypeGroupCtxtSUReq", HFILL }},
    { &hf_s1ap_multicast,
      { "multicast", "s1ap.multicast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MulticastTransportTypeGroupCtxtSUReq", HFILL }},
    { &hf_s1ap_multiAddress,
      { "multiAddress", "s1ap.multiAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_s1ap_sourceAddress,
      { "sourceAddress", "s1ap.sourceAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_s1ap_TE_RABSetupListGroupCtxtSURes_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_transportType_01,
      { "transportType", "s1ap.transportType",
        FT_UINT32, BASE_DEC, VALS(s1ap_TransportTypeGroupCtxtSURes_vals), 0,
        "TransportTypeGroupCtxtSURes", HFILL }},
    { &hf_s1ap_unicast_01,
      { "unicast", "s1ap.unicast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnicastTransportTypeGroupCtxtSURes", HFILL }},
    { &hf_s1ap_multicast_01,
      { "multicast", "s1ap.multicast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_ListOfTargetTAIsTrunkingIndividualPaging_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_s1_TInterface,
      { "s1-TInterface", "s1ap.s1_TInterface",
        FT_UINT32, BASE_DEC, VALS(s1ap_GroupResetAll_vals), 0,
        "GroupResetAll", HFILL }},
    { &hf_s1ap_partOfS1_TInterface,
      { "partOfS1-TInterface", "s1ap.partOfS1_TInterface_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartOfS1_TInterfaceGroupReset", HFILL }},
    { &hf_s1ap_group_associatedLogicalS1_Connection,
      { "group-associatedLogicalS1-Connection", "s1ap.group_associatedLogicalS1_Connection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Group_associatedLogicalS1_ConnectionListGroupReset", HFILL }},
    { &hf_s1ap_Group_associatedLogicalS1_ConnectionListGroupReset_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABToBeSetupListGroupBearerSUReq_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_tE_RABlevelQoSParameters,
      { "tE-RABlevelQoSParameters", "s1ap.tE_RABlevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_transportType_02,
      { "transportType", "s1ap.transportType",
        FT_UINT32, BASE_DEC, VALS(s1ap_TransportTypeGroupBearerSUReq_vals), 0,
        "TransportTypeGroupBearerSUReq", HFILL }},
    { &hf_s1ap_unicast_02,
      { "unicast", "s1ap.unicast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnicastTransportTypeGroupBearerSUReq", HFILL }},
    { &hf_s1ap_multicast_02,
      { "multicast", "s1ap.multicast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MulticastTransportTypeGroupBearerSUReq", HFILL }},
    { &hf_s1ap_TE_RABSetupListGroupBearerSURes_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_transportType_03,
      { "transportType", "s1ap.transportType",
        FT_UINT32, BASE_DEC, VALS(s1ap_TransportTypeGroupBearerSURes_vals), 0,
        "TransportTypeGroupBearerSURes", HFILL }},
    { &hf_s1ap_unicast_03,
      { "unicast", "s1ap.unicast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnicastTransportTypeGroupBearerSURes", HFILL }},
    { &hf_s1ap_TE_RABToBeModifiedListGroupBearerModReq_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_tE_RABLevelQoSParameters,
      { "tE-RABLevelQoSParameters", "s1ap.tE_RABLevelQoSParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABModifyListGroupBearerModRes_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_TE_RABReleaseListGroupBearerRelRes_item,
      { "ProtocolIE-SingleContainer", "s1ap.ProtocolIE_SingleContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_initiatingMessage,
      { "initiatingMessage", "s1ap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_successfulOutcome,
      { "successfulOutcome", "s1ap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "s1ap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_initiatingMessagevalue,
      { "value", "s1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_s1ap_successfulOutcome_value,
      { "value", "s1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_s1ap_unsuccessfulOutcome_value,
      { "value", "s1ap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-s1ap-hfarr.c ---*/
#line 727 "./asn1/s1ap/packet-s1ap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_s1ap,
    &ett_s1ap_TransportLayerAddress,
    &ett_s1ap_ToTargetTransparentContainer,
    &ett_s1ap_ToSourceTransparentContainer,
    &ett_s1ap_RRCContainer,
    &ett_s1ap_UERadioCapability,
    &ett_s1ap_RIMInformation,
    &ett_s1ap_Cdma2000PDU,
    &ett_s1ap_Cdma2000SectorID,
    &ett_s1ap_UERadioPagingInformation,
    &ett_s1ap_UE_HistoryInformationFromTheUE,
    &ett_s1ap_CELevel,
    &ett_s1ap_UE_RLF_Report_Container,
    &ett_s1ap_UE_RLF_Report_Container_for_extended_bands,
    &ett_s1ap_S1_Message,
    &ett_s1ap_E_UTRAN_Trace_ID,
    &ett_s1ap_InterfacesToTrace,
    &ett_s1ap_EncryptionAlgorithms,
    &ett_s1ap_IntegrityProtectionAlgorithms,
    &ett_s1ap_LastVisitedNGRANCellInformation,
    &ett_s1ap_LastVisitedUTRANCellInformation,
    &ett_s1ap_SerialNumber,
    &ett_s1ap_WarningType,
    &ett_s1ap_DataCodingScheme,
    &ett_s1ap_WarningMessageContents,
    &ett_s1ap_MSClassmark,
    &ett_s1ap_MeasurementsToActivate,
    &ett_s1ap_MDT_Location_Info,
    &ett_s1ap_IMSI,
    &ett_s1ap_NASSecurityParameters,
    &ett_s1ap_NRencryptionAlgorithms,
    &ett_s1ap_NRintegrityProtectionAlgorithms,
    &ett_s1ap_UE_Application_Layer_Measurement_Capability,
    &ett_s1ap_sMTC,
    &ett_s1ap_threshRS_Index_r15,
    &ett_s1ap_sSBToMeasure,
    &ett_s1ap_sSRSSIMeasurement,
    &ett_s1ap_quantityConfigNR_R15,
    &ett_s1ap_blackCellsToAddModList,
    &ett_s1ap_NB_IoT_RLF_Report_Container,
    &ett_s1ap_MDT_ConfigurationNR,
    &ett_s1ap_IntersystemSONConfigurationTransfer,

/*--- Included file: packet-s1ap-ettarr.c ---*/
#line 1 "./asn1/s1ap/packet-s1ap-ettarr.c"
    &ett_s1ap_PrivateIE_ID,
    &ett_s1ap_ProtocolIE_Container,
    &ett_s1ap_ProtocolIE_Field,
    &ett_s1ap_ProtocolIE_ContainerList,
    &ett_s1ap_ProtocolExtensionContainer,
    &ett_s1ap_ProtocolExtensionField,
    &ett_s1ap_PrivateIE_Container,
    &ett_s1ap_PrivateIE_Field,
    &ett_s1ap_AllocationAndRetentionPriority,
    &ett_s1ap_AddModGroupCallConfigurationList,
    &ett_s1ap_AddModGroupCallConfigurationItem,
    &ett_s1ap_Bearers_SubjectToStatusTransferList,
    &ett_s1ap_Bearers_SubjectToStatusTransfer_Item,
    &ett_s1ap_BPLMNs,
    &ett_s1ap_BroadcastCancelledAreaList,
    &ett_s1ap_BroadcastCompletedAreaList,
    &ett_s1ap_CancelledCellinEAI,
    &ett_s1ap_CancelledCellinEAI_Item,
    &ett_s1ap_CancelledCellinTAI,
    &ett_s1ap_CancelledCellinTAI_Item,
    &ett_s1ap_Cause,
    &ett_s1ap_CellID_Broadcast,
    &ett_s1ap_CellID_Broadcast_Item,
    &ett_s1ap_CellID_Cancelled,
    &ett_s1ap_CellID_Cancelled_Item,
    &ett_s1ap_Cdma2000OneXSRVCCInfo,
    &ett_s1ap_CellType,
    &ett_s1ap_CGI,
    &ett_s1ap_CSG_IdList,
    &ett_s1ap_CSG_IdList_Item,
    &ett_s1ap_COUNTvalue,
    &ett_s1ap_CriticalityDiagnostics,
    &ett_s1ap_CriticalityDiagnostics_IE_List,
    &ett_s1ap_CriticalityDiagnostics_IE_Item,
    &ett_s1ap_ECGIList,
    &ett_s1ap_EmergencyAreaIDList,
    &ett_s1ap_EmergencyAreaID_Broadcast,
    &ett_s1ap_EmergencyAreaID_Broadcast_Item,
    &ett_s1ap_EmergencyAreaID_Cancelled,
    &ett_s1ap_EmergencyAreaID_Cancelled_Item,
    &ett_s1ap_CompletedCellinEAI,
    &ett_s1ap_CompletedCellinEAI_Item,
    &ett_s1ap_ENB_ID,
    &ett_s1ap_GERAN_Cell_ID,
    &ett_s1ap_Global_ENB_ID,
    &ett_s1ap_ENB_StatusTransfer_TransparentContainer,
    &ett_s1ap_ENBX2TLAs,
    &ett_s1ap_EPLMNs,
    &ett_s1ap_E_RABInformationList,
    &ett_s1ap_E_RABInformationListItem,
    &ett_s1ap_E_RABList,
    &ett_s1ap_E_RABItem,
    &ett_s1ap_E_RABLevelQoSParameters,
    &ett_s1ap_EUTRAN_CGI,
    &ett_s1ap_ForbiddenTAs,
    &ett_s1ap_ForbiddenTAs_Item,
    &ett_s1ap_ForbiddenTACs,
    &ett_s1ap_ForbiddenLAs,
    &ett_s1ap_ForbiddenLAs_Item,
    &ett_s1ap_ForbiddenLACs,
    &ett_s1ap_GBR_QosInformation,
    &ett_s1ap_Group_S1AP_IDs,
    &ett_s1ap_Group_S1AP_ID_pair,
    &ett_s1ap_GroupServiceArea,
    &ett_s1ap_TAIListGroupServiceArea,
    &ett_s1ap_TAIListItemGroupServiceArea,
    &ett_s1ap_CellListGroupServiceArea,
    &ett_s1ap_CellListItemGroupServiceArea,
    &ett_s1ap_GroupCallAlgorithms,
    &ett_s1ap_GroupSecurityInformation,
    &ett_s1ap_GroupConfigurationContainer,
    &ett_s1ap_GroupConfigurationContainerList,
    &ett_s1ap_GroupConfigurationContainerItem,
    &ett_s1ap_GroupAggregateMaximumBitrate,
    &ett_s1ap_Group_GBR_QosInformation,
    &ett_s1ap_ReleaseGroupCallConfigurationList,
    &ett_s1ap_ReleaseGroupCallConfigurationItem,
    &ett_s1ap_GUMMEI,
    &ett_s1ap_HandoverRestrictionList,
    &ett_s1ap_LAI,
    &ett_s1ap_LastVisitedCell_Item,
    &ett_s1ap_LastVisitedEUTRANCellInformation,
    &ett_s1ap_LastVisitedGERANCellInformation,
    &ett_s1ap_OverloadResponse,
    &ett_s1ap_RequestType,
    &ett_s1ap_RIMTransfer,
    &ett_s1ap_RIMRoutingAddress,
    &ett_s1ap_SecurityContext,
    &ett_s1ap_SONInformation,
    &ett_s1ap_SONInformationReply,
    &ett_s1ap_SONConfigurationTransfer,
    &ett_s1ap_SourceeNB_ID,
    &ett_s1ap_SourceeNB_ToTargeteNB_TransparentContainer,
    &ett_s1ap_SourceeNB_List,
    &ett_s1ap_SourceeNB_Item,
    &ett_s1ap_ServedGUMMEIs,
    &ett_s1ap_ServedGUMMEIsItem,
    &ett_s1ap_ServedGroupIDs,
    &ett_s1ap_ServedMMECs,
    &ett_s1ap_ServedPLMNs,
    &ett_s1ap_SupportedTAs,
    &ett_s1ap_SupportedTAs_Item,
    &ett_s1ap_TimeSynchronizationInfo,
    &ett_s1ap_S_TMSI,
    &ett_s1ap_TAIListforWarning,
    &ett_s1ap_TAI,
    &ett_s1ap_TAI_Broadcast,
    &ett_s1ap_TAI_Broadcast_Item,
    &ett_s1ap_TAI_Cancelled,
    &ett_s1ap_TAI_Cancelled_Item,
    &ett_s1ap_CompletedCellinTAI,
    &ett_s1ap_CompletedCellinTAI_Item,
    &ett_s1ap_TargetID,
    &ett_s1ap_TargeteNB_ID,
    &ett_s1ap_TE_RABList,
    &ett_s1ap_TE_RABItem,
    &ett_s1ap_TE_RABLevelQoSParameters,
    &ett_s1ap_TargeteNB_List,
    &ett_s1ap_TargeteNB_Item,
    &ett_s1ap_TargetRNC_ID,
    &ett_s1ap_TargeteNB_ToSourceeNB_TransparentContainer,
    &ett_s1ap_TraceActivation,
    &ett_s1ap_UEAggregateMaximumBitrate,
    &ett_s1ap_UE_S1AP_IDs,
    &ett_s1ap_UE_S1AP_ID_pair,
    &ett_s1ap_UE_associatedLogicalS1_ConnectionItem,
    &ett_s1ap_UE_HistoryInformation,
    &ett_s1ap_UEPagingID,
    &ett_s1ap_UESecurityCapabilities,
    &ett_s1ap_WarningAreaList,
    &ett_s1ap_X2TNLConfigurationInfo,
    &ett_s1ap_HandoverRequired,
    &ett_s1ap_HandoverCommand,
    &ett_s1ap_E_RABDataForwardingItem,
    &ett_s1ap_HandoverPreparationFailure,
    &ett_s1ap_HandoverRequest,
    &ett_s1ap_E_RABToBeSetupItemHOReq,
    &ett_s1ap_HandoverRequestAcknowledge,
    &ett_s1ap_E_RABAdmittedItem,
    &ett_s1ap_E_RABFailedToSetupItemHOReqAck,
    &ett_s1ap_HandoverFailure,
    &ett_s1ap_HandoverNotify,
    &ett_s1ap_PathSwitchRequest,
    &ett_s1ap_E_RABToBeSwitchedDLItem,
    &ett_s1ap_PathSwitchRequestAcknowledge,
    &ett_s1ap_E_RABToBeSwitchedULItem,
    &ett_s1ap_PathSwitchRequestFailure,
    &ett_s1ap_HandoverCancel,
    &ett_s1ap_HandoverCancelAcknowledge,
    &ett_s1ap_E_RABSetupRequest,
    &ett_s1ap_E_RABToBeSetupListBearerSUReq,
    &ett_s1ap_E_RABToBeSetupItemBearerSUReq,
    &ett_s1ap_E_RABSetupResponse,
    &ett_s1ap_E_RABSetupListBearerSURes,
    &ett_s1ap_E_RABSetupItemBearerSURes,
    &ett_s1ap_E_RABModifyRequest,
    &ett_s1ap_E_RABToBeModifiedListBearerModReq,
    &ett_s1ap_E_RABToBeModifiedItemBearerModReq,
    &ett_s1ap_E_RABModifyResponse,
    &ett_s1ap_E_RABModifyListBearerModRes,
    &ett_s1ap_E_RABModifyItemBearerModRes,
    &ett_s1ap_E_RABReleaseCommand,
    &ett_s1ap_E_RABReleaseResponse,
    &ett_s1ap_E_RABReleaseListBearerRelComp,
    &ett_s1ap_E_RABReleaseItemBearerRelComp,
    &ett_s1ap_E_RABReleaseIndication,
    &ett_s1ap_InitialContextSetupRequest,
    &ett_s1ap_E_RABToBeSetupListCtxtSUReq,
    &ett_s1ap_E_RABToBeSetupItemCtxtSUReq,
    &ett_s1ap_InitialContextSetupResponse,
    &ett_s1ap_E_RABSetupListCtxtSURes,
    &ett_s1ap_E_RABSetupItemCtxtSURes,
    &ett_s1ap_InitialContextSetupFailure,
    &ett_s1ap_Paging,
    &ett_s1ap_TAIList,
    &ett_s1ap_TAIItem,
    &ett_s1ap_UEContextReleaseRequest,
    &ett_s1ap_UEContextReleaseCommand,
    &ett_s1ap_UEContextReleaseComplete,
    &ett_s1ap_UEContextModificationRequest,
    &ett_s1ap_UEContextModificationResponse,
    &ett_s1ap_UEContextModificationFailure,
    &ett_s1ap_DownlinkNASTransport,
    &ett_s1ap_InitialUEMessage,
    &ett_s1ap_UplinkNASTransport,
    &ett_s1ap_NASNonDeliveryIndication,
    &ett_s1ap_Reset,
    &ett_s1ap_ResetType,
    &ett_s1ap_UE_associatedLogicalS1_ConnectionListRes,
    &ett_s1ap_ResetAcknowledge,
    &ett_s1ap_UE_associatedLogicalS1_ConnectionListResAck,
    &ett_s1ap_ErrorIndication,
    &ett_s1ap_S1SetupRequest,
    &ett_s1ap_S1SetupResponse,
    &ett_s1ap_S1SetupFailure,
    &ett_s1ap_ENBConfigurationUpdate,
    &ett_s1ap_ENBConfigurationUpdateAcknowledge,
    &ett_s1ap_ENBConfigurationUpdateFailure,
    &ett_s1ap_MMEConfigurationUpdate,
    &ett_s1ap_MMEConfigurationUpdateAcknowledge,
    &ett_s1ap_MMEConfigurationUpdateFailure,
    &ett_s1ap_DownlinkS1cdma2000tunneling,
    &ett_s1ap_UplinkS1cdma2000tunneling,
    &ett_s1ap_UECapabilityInfoIndication,
    &ett_s1ap_ENBStatusTransfer,
    &ett_s1ap_MMEStatusTransfer,
    &ett_s1ap_TraceStart,
    &ett_s1ap_TraceFailureIndication,
    &ett_s1ap_DeactivateTrace,
    &ett_s1ap_CellTrafficTrace,
    &ett_s1ap_LocationReportingControl,
    &ett_s1ap_LocationReportingFailureIndication,
    &ett_s1ap_LocationReport,
    &ett_s1ap_OverloadStart,
    &ett_s1ap_OverloadStop,
    &ett_s1ap_WriteReplaceWarningRequest,
    &ett_s1ap_WriteReplaceWarningResponse,
    &ett_s1ap_ENBDirectInformationTransfer,
    &ett_s1ap_Inter_SystemInformationTransferType,
    &ett_s1ap_MMEDirectInformationTransfer,
    &ett_s1ap_ENBConfigurationTransfer,
    &ett_s1ap_MMEConfigurationTransfer,
    &ett_s1ap_PrivateMessage,
    &ett_s1ap_KillRequest,
    &ett_s1ap_KillResponse,
    &ett_s1ap_DownlinkUEAssociatedLPPaTransport,
    &ett_s1ap_UplinkUEAssociatedLPPaTransport,
    &ett_s1ap_DownlinkNonUEAssociatedLPPaTransport,
    &ett_s1ap_UplinkNonUEAssociatedLPPaTransport,
    &ett_s1ap_GroupCallContextSetupRequest,
    &ett_s1ap_TE_RABToBeSetupListGroupCtxtSUReq,
    &ett_s1ap_TE_RABToBeSetupItemGroupCtxtSUReq,
    &ett_s1ap_TransportTypeGroupCtxtSUReq,
    &ett_s1ap_UnicastTransportTypeGroupCtxtSUReq,
    &ett_s1ap_MulticastTransportTypeGroupCtxtSUReq,
    &ett_s1ap_GroupCallContextSetupResponse,
    &ett_s1ap_TE_RABSetupListGroupCtxtSURes,
    &ett_s1ap_TE_RABSetupItemGroupCtxtSURes,
    &ett_s1ap_TransportTypeGroupCtxtSURes,
    &ett_s1ap_UnicastTransportTypeGroupCtxtSURes,
    &ett_s1ap_GroupCallContextSetupFailure,
    &ett_s1ap_GroupCallContextModificationRequest,
    &ett_s1ap_GroupCallContextModificationResponse,
    &ett_s1ap_GroupCallContextReleaseCommand,
    &ett_s1ap_GroupCallContextReleaseComplete,
    &ett_s1ap_GroupCallContextReleaseIndication,
    &ett_s1ap_InstantGroupCallConfigNotify,
    &ett_s1ap_GroupCallContextExpansionRequest,
    &ett_s1ap_GroupCallContextExpansionAccept,
    &ett_s1ap_GroupCallContextExpansionReject,
    &ett_s1ap_TrunkingIndividualPaging,
    &ett_s1ap_ListOfTargetTAIsTrunkingIndividualPaging,
    &ett_s1ap_ListOfTargetTAIsItemTrunkingIndividualPaging,
    &ett_s1ap_GroupDownlinkNASTransport,
    &ett_s1ap_TrunkingErrorIndication,
    &ett_s1ap_GroupReset,
    &ett_s1ap_GroupResetType,
    &ett_s1ap_PartOfS1_TInterfaceGroupReset,
    &ett_s1ap_Group_associatedLogicalS1_ConnectionListGroupReset,
    &ett_s1ap_Group_associatedLogicalS1_ConnectionItemGroupReset,
    &ett_s1ap_GroupResetAcknowledge,
    &ett_s1ap_Group_associatedLogicalS1_ConnectionListGroupResetAck,
    &ett_s1ap_Group_associatedLogicalS1_ConnectionItemGroupResetAck,
    &ett_s1ap_GroupTE_RABSetupRequest,
    &ett_s1ap_TE_RABToBeSetupListGroupBearerSUReq,
    &ett_s1ap_TE_RABToBeSetupItemGroupBearerSUReq,
    &ett_s1ap_TransportTypeGroupBearerSUReq,
    &ett_s1ap_UnicastTransportTypeGroupBearerSUReq,
    &ett_s1ap_MulticastTransportTypeGroupBearerSUReq,
    &ett_s1ap_GroupTE_RABSetupResponse,
    &ett_s1ap_TE_RABSetupListGroupBearerSURes,
    &ett_s1ap_TE_RABSetupItemGroupBearerSURes,
    &ett_s1ap_TransportTypeGroupBearerSURes,
    &ett_s1ap_UnicastTransportTypeGroupBearerSURes,
    &ett_s1ap_GroupTE_RABModifyRequest,
    &ett_s1ap_TE_RABToBeModifiedListGroupBearerModReq,
    &ett_s1ap_TE_RABToBeModifiedItemGroupBearerModReq,
    &ett_s1ap_GroupTE_RABModifyResponse,
    &ett_s1ap_TE_RABModifyListGroupBearerModRes,
    &ett_s1ap_TE_RABModifyItemGroupBearerModRes,
    &ett_s1ap_GroupTE_RABReleaseCommand,
    &ett_s1ap_GroupTE_RABReleaseResponse,
    &ett_s1ap_TE_RABReleaseListGroupBearerRelRes,
    &ett_s1ap_TE_RABReleaseItemGroupBearerRelRes,
    &ett_s1ap_GroupTE_RABReleaseIndication,
    &ett_s1ap_TrunkingMessageTransport,
    &ett_s1ap_TrunkingServingCellUpdateIndication,
    &ett_s1ap_ENBGroupCallConfigurationTransfer,
    &ett_s1ap_MMEGroupCallConfigurationTransfer,
    &ett_s1ap_S1AP_PDU,
    &ett_s1ap_InitiatingMessage,
    &ett_s1ap_SuccessfulOutcome,
    &ett_s1ap_UnsuccessfulOutcome,

/*--- End of included file: packet-s1ap-ettarr.c ---*/
#line 774 "./asn1/s1ap/packet-s1ap-template.c"
  };

  static ei_register_info ei[] = {
    { &ei_s1ap_number_pages_le15, { "s1ap.number_pages_le15", PI_MALFORMED, PI_ERROR, "Number of pages should be <=15", EXPFILL }}
  };

  module_t *s1ap_module;
  expert_module_t* expert_s1ap;

  /* Register protocol */
  proto_s1ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_s1ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_s1ap = expert_register_protocol(proto_s1ap);
  expert_register_field_array(expert_s1ap, ei, array_length(ei));

  /* Register dissector */
  s1ap_handle = register_dissector("s1ap", dissect_s1ap, proto_s1ap);

  /* Register dissector tables */
  s1ap_ies_dissector_table = register_dissector_table("s1ap.ies", "S1AP-PROTOCOL-IES", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_ies_p1_dissector_table = register_dissector_table("s1ap.ies.pair.first", "S1AP-PROTOCOL-IES-PAIR FirstValue", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_ies_p2_dissector_table = register_dissector_table("s1ap.ies.pair.second", "S1AP-PROTOCOL-IES-PAIR SecondValue", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_extension_dissector_table = register_dissector_table("s1ap.extension", "S1AP-PROTOCOL-EXTENSION", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_proc_imsg_dissector_table = register_dissector_table("s1ap.proc.imsg", "S1AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_proc_sout_dissector_table = register_dissector_table("s1ap.proc.sout", "S1AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_proc_uout_dissector_table = register_dissector_table("s1ap.proc.uout", "S1AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_s1ap, FT_UINT32, BASE_DEC);

  /* Register configuration options for ports */
  s1ap_module = prefs_register_protocol(proto_s1ap, proto_reg_handoff_s1ap);

  prefs_register_uint_preference(s1ap_module, "sctp.port",
                                 "S1AP SCTP Port",
                                 "Set the SCTP port for S1AP messages",
                                 10,
                                 &gbl_s1apSctpPort);
  prefs_register_bool_preference(s1ap_module, "dissect_container", "Dissect TransparentContainer", "Dissect TransparentContainers that are opaque to S1AP", &g_s1ap_dissect_container);
  prefs_register_enum_preference(s1ap_module, "dissect_lte_container_as", "Dissect LTE TransparentContainer as",
                                 "Select whether LTE TransparentContainer should be dissected as NB-IOT or legacy LTE",
                                 &g_s1ap_dissect_lte_container_as, s1ap_lte_container_vals, FALSE);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
