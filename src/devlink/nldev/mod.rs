// SPDX-License-Identifier: MIT

use crate::constants::*;
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::mem::size_of_val;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenlDevlinkAttrs {
    BusName(String),
    Location(String),
    PortIndex(u32),
    PortType(u16),
    DesiredType(u16),
    NetdevIndex(u32),
    NetdevName(String),
    PortIbdevName(String),
    PortSplitCount(u32),
    PortSplitGroup(u32),
    SbIndex(u32),
    SbSize(u32),
    SbIngressPoolCount(u16),
    SbEgressPoolCount(u16),
    SbIngressTcCount(u16),
    SbEgressTcCount(u16),
    SbPoolIndex(u16),
    SbPoolType(u8),
    SbPoolSize(u32),
    SbPoolThresholdType(u8),
    SbPoolThreshold(u32),
    SbTcIndex(u16),
    SbOccCur(u32),
    SbOccMax(u32),
    EswitchMode(u16),
    EswitchInlineMode(u8),
    DpipeTables(Vec<GenlDevlinkAttrs>),
    DpipeTable(Vec<GenlDevlinkAttrs>),
    DpipeTableName(String),
    DpipeTableSize(u64),
    DpipeTableMatches(Vec<GenlDevlinkAttrs>),
    DpipeTableActions(Vec<GenlDevlinkAttrs>),
    DpipeTableCountersEnabled(u8),
    DpipeEntries(Vec<GenlDevlinkAttrs>),
    DpipeEntry(Vec<GenlDevlinkAttrs>),
    DpipeEntryIndex(u64),
    DpipeEntryMatchValues(Vec<GenlDevlinkAttrs>),
    DpipeEntryActionValues(Vec<GenlDevlinkAttrs>),
    DpipeEntryCounter(u64),
    DpipeMatch(Vec<GenlDevlinkAttrs>),
    DpipeMatchValue(Vec<GenlDevlinkAttrs>),
    DpipeMatchType(u32),
    DpipeAction(Vec<GenlDevlinkAttrs>),
    DpipeActionValue(Vec<GenlDevlinkAttrs>),
    DpipeActionType(u32),
    DpipeValue(u32),
    DpipeValueMask(u32),
    DpipeValueMapping(u32),
    DpipeHeaders(Vec<GenlDevlinkAttrs>),
    DpipeHader(Vec<GenlDevlinkAttrs>),
    DpipeHeaderName(String),
    DpipeHeaderId(u32),
    DpipeHeaderFields(Vec<GenlDevlinkAttrs>),
    DpipeHeaderGlobal(u8),
    DpipeHeaderIndex(u32),
    DpipeField(Vec<GenlDevlinkAttrs>),
    DpipeFieldName(String),
    DpipeFieldId(u32),
    DpipeFieldBitwidth(u32),
    DpipeFieldMappingType(u32),
    EswitchEncapMode(u8),
    ResourceList(Vec<GenlDevlinkAttrs>),
    Resource(Vec<GenlDevlinkAttrs>),
    ResoureceName(String),
    ResourceId(u64),
    ResourceSize(u64),
    ResourceSizeNew(u64),
    ResourceSizeValid(u8),
    ResourceSizeMin(u64),
    ResourceSizeMax(u64),
    ResourceSizeGran(u64),
    ResourceUnit(u8),
    ResourceOcc(u64),
    DpipeTableResourceId(u64),
    DpipeTableResourceUnit(u64),
    PortFlavour(u16),
    PortNumber(u32),
    Param(Vec<GenlDevlinkAttrs>),
    ParamName(String),
    ParamGeneric(bool),
    ParamType(u8),
    ParamValueList(Vec<GenlDevlinkAttrs>),
    ParamValue(u64),
    ParamValueData(Vec<GenlDevlinkAttrs>),
    ParamValueCmode(u8),
    RegionName(String),
    RegionSize(u64),
    RegionSnapshots(Vec<GenlDevlinkAttrs>),
    RegionSnapshot(Vec<GenlDevlinkAttrs>),
    RegionSnapshotId(u32),
    RegionChunks(Vec<GenlDevlinkAttrs>),
    RegionChunk(Vec<GenlDevlinkAttrs>),
    RegionChunkData(Vec<u8>),
    RegionChunkOffset(u64),
    RegionChunkSize(u64),
    InfoDriverName(String),
    InfoSerialNo(String),
    InfoVersionFixed(Vec<GenlDevlinkAttrs>),
    InfoVersionRunning(Vec<GenlDevlinkAttrs>),
    InfoVersionStored(Vec<GenlDevlinkAttrs>),
    InfoVersionName(String),
    InfoVersionValue(String),
    SbPoolCellSize(u32),
    Fmsg(Vec<GenlDevlinkAttrs>),
    FmsgObjNestStart(bool),
    FmsgPairNestStart(bool),
    FmsgArrNestStart(bool),
    FmsgNestEnd(bool),
    FmsgObjName(String),
    FmsgObjValueType(u8),
    FmsgObjValueData(Vec<GenlDevlinkAttrs>),
    HealthReporter(Vec<GenlDevlinkAttrs>),
    HealthReporterName(String),
    HealthReporterState(u8),
    HealthReporterErrCount(u64),
    HealthReporterRecoverCount(u64),
    HealthReporterDumpTs(u64),
    HealthReporterGracefulPeriod(u64),
    HealthReporterAucoRecover(u8),
    FlashUpdateFileName(String),
    FlashUpdateComponent(String),
    FlashUpdateStatusMsg(String),
    FlashUpdateStatusDone(u64),
    FlashUpdateStatusTotal(u64),
    PortPciPfNumber(u16),
    PortPciVfNumber(u16),
    Stats(Vec<GenlDevlinkAttrs>),
    TrapName(String),
    TrapAction(u8),
    TrapType(u8),
    TrapGeneric(bool),
    TrapMetadata(Vec<GenlDevlinkAttrs>),
    TrapGroupName(String),
    ReloadStatus(u8),
    HealthReporterDumpTsNs(u64),
    NetnsFd(u32),
    NetnsPid(u32),
    NetnsId(u32),
    HealthReporterAutoDump(u8),
    TrapPolicerId(u32),
    TrapPolicerRate(u64),
    TrapPolicerBurst(u64),
    PortFunction(Vec<GenlDevlinkAttrs>),
    InfoBoardSerialNumber(String),
    PortLanes(u32),
    PortSplittable(u8),
    PortExternal(u8),
    PortControllerNo(u32),
    FlashUpdateStatusTimeout(u32),
    FlashUpdateOverWriteMask(u32),
    ReloadAction(u8),
    ReloadActionPerformed(u32),
    ReloadLimits(u32),
    DevStats(Vec<GenlDevlinkAttrs>),
    ReloadStats(Vec<GenlDevlinkAttrs>),
    ReloadStatsEntry(Vec<GenlDevlinkAttrs>),
    ReloadStatsLimit(u8),
    ReloadStatsValue(u32),
    RemoteReloadStats(Vec<GenlDevlinkAttrs>),
    ReloadActionInfo(Vec<GenlDevlinkAttrs>),
    ReloadActionStats(Vec<GenlDevlinkAttrs>),
    PortPciSfNo(u32),
    RateType(u16),
    RateTxShare(u64),
    RateTxMax(u64),
    RateNodeName(String),
    RateParentNodeName(String),
    RegionMaxSnapshots(u32),
}

impl GenlDevlinkAttrs {
    pub fn get_nested_value(&self) -> Option<Vec<GenlDevlinkAttrs>> {
        use GenlDevlinkAttrs::*;
        match self {
            Param(v) => Some(v.clone()),
            ParamValueList(v) => Some(v.clone()),
            RegionSnapshots(v) => Some(v.clone()),
            RegionSnapshot(v) => Some(v.clone()),
            RegionChunks(v) => Some(v.clone()),
            RegionChunk(v) => Some(v.clone()),
            InfoVersionFixed(v) => Some(v.clone()),
            InfoVersionRunning(v) => Some(v.clone()),
            InfoVersionStored(v) => Some(v.clone()),
            DevStats(v) => Some(v.clone()),
            ReloadStats(v) => Some(v.clone()),
            ReloadStatsEntry(v) => Some(v.clone()),
            RemoteReloadStats(v) => Some(v.clone()),
            ReloadActionInfo(v) => Some(v.clone()),
            ReloadActionStats(v) => Some(v.clone()),
            DpipeTables(v) => Some(v.clone()),
            DpipeTable(v) => Some(v.clone()),
            DpipeTableMatches(v) => Some(v.clone()),
            DpipeTableActions(v) => Some(v.clone()),
            DpipeEntries(v) => Some(v.clone()),
            DpipeEntry(v) => Some(v.clone()),
            DpipeEntryMatchValues(v) => Some(v.clone()),
            DpipeEntryActionValues(v) => Some(v.clone()),
            DpipeMatch(v) => Some(v.clone()),
            DpipeMatchValue(v) => Some(v.clone()),
            DpipeAction(v) => Some(v.clone()),
            DpipeActionValue(v) => Some(v.clone()),
            DpipeHeaders(v) => Some(v.clone()),
            DpipeHader(v) => Some(v.clone()),
            DpipeHeaderFields(v) => Some(v.clone()),
            DpipeField(v) => Some(v.clone()),
            ResourceList(v) => Some(v.clone()),
            Resource(v) => Some(v.clone()),
            ParamValueData(v) => Some(v.clone()),
            Fmsg(v) => Some(v.clone()),
            FmsgObjValueData(v) => Some(v.clone()),
            HealthReporter(v) => Some(v.clone()),
            TrapMetadata(v) => Some(v.clone()),
            PortFunction(v) => Some(v.clone()),
            Stats(v) => Some(v  .clone()),
            _ => None,
        }
    }

    pub fn get_attribute_name(&self) -> String {
        use GenlDevlinkAttrs::*;
        match self {
            BusName(_) => "BusName".to_string(),
            Location(_) => "Location".to_string(),
            PortIndex(_) => "PortIndex".to_string(),
            PortType(_) => "PortType".to_string(),
            DesiredType(_) => "DesiredType".to_string(),
            NetdevIndex(_) => "NetdevIndex".to_string(),
            NetdevName(_) => "NetdevName".to_string(),
            PortIbdevName(_) => "PortIbdevName".to_string(),
            PortSplitCount(_) => "PortSplitCount".to_string(),
            PortSplitGroup(_) => "PortSplitGroup".to_string(),
            SbIndex(_) => "SbIndex".to_string(),
            SbSize(_) => "SbSize".to_string(),
            SbIngressPoolCount(_) => "SbIngressPoolCount".to_string(),
            SbEgressPoolCount(_) => "SbEgressPoolCount".to_string(),
            SbIngressTcCount(_) => "SbIngressTcCount".to_string(),
            SbEgressTcCount(_) => "SbEgressTcCount".to_string(),
            SbPoolIndex(_) => "SbPoolIndex".to_string(),
            SbPoolType(_) => "SbPoolType".to_string(),
            SbPoolSize(_) => "SbPoolSize".to_string(),
            SbPoolThresholdType(_) => "SbPoolThresholdType".to_string(),
            SbPoolThreshold(_) => "SbPoolThreshold".to_string(),
            SbTcIndex(_) => "SbTcIndex".to_string(),
            SbOccCur(_) => "SbOccCur".to_string(),
            SbOccMax(_) => "SbOccMax".to_string(),
            EswitchMode(_) => "EswitchMode".to_string(),
            EswitchInlineMode(_) => "EswitchInlineMode".to_string(),
            DpipeTables(_) => "DpipeTables".to_string(),
            DpipeTable(_) => "DpipeTable".to_string(),
            DpipeTableName(_) => "DpipeTableName".to_string(),
            DpipeTableSize(_) => "DpipeTableSize".to_string(),
            DpipeTableMatches(_) => "DpipeTableMatches".to_string(),
            DpipeTableActions(_) => "DpipeTableActions".to_string(),
            DpipeTableCountersEnabled(_) => "DpipeTableCountersEnabled".to_string(),
            DpipeEntries(_) => "DpipeEntries".to_string(),
            DpipeEntry(_) => "DpipeEntry".to_string(),
            DpipeEntryIndex(_) => "DpipeEntryIndex".to_string(),
            DpipeEntryMatchValues(_) => "DpipeEntryMatchValues".to_string(),
            DpipeEntryActionValues(_) => "DpipeEntryActionValues".to_string(),
            DpipeEntryCounter(_) => "DpipeEntryCounter".to_string(),
            DpipeMatch(_) => "DpipeMatch".to_string(),
            DpipeMatchValue(_) => "DpipeMatchValue".to_string(),
            DpipeMatchType(_) => "DpipeMatchType".to_string(),
            DpipeAction(_) => "DpipeAction".to_string(),
            DpipeActionValue(_) => "DpipeActionValue".to_string(),
            DpipeActionType(_) => "DpipeActionType".to_string(),
            DpipeValue(_) => "DpipeValue".to_string(),
            DpipeValueMask(_) => "DpipeValueMask".to_string(),
            DpipeValueMapping(_) => "DpipeValueMapping".to_string(),
            DpipeHeaders(_) => "DpipeHeaders".to_string(),
            DpipeHader(_) => "DpipeHader".to_string(),
            DpipeHeaderName(_) => "DpipeHeaderName".to_string(),
            DpipeHeaderId(_) => "DpipeHeaderId".to_string(),
            DpipeHeaderFields(_) => "DpipeHeaderFields".to_string(),
            DpipeHeaderGlobal(_) => "DpipeHeaderGlobal".to_string(),
            DpipeHeaderIndex(_) => "DpipeHeaderIndex".to_string(),
            DpipeField(_) => "DpipeField".to_string(),
            DpipeFieldName(_) => "DpipeFieldName".to_string(),
            DpipeFieldId(_) => "DpipeFieldId".to_string(),
            DpipeFieldBitwidth(_) => "DpipeFieldBitwidth".to_string(),
            DpipeFieldMappingType(_) => "DpipeFieldMappingType".to_string(),
            EswitchEncapMode(_) => "EswitchEncapMode".to_string(),
            ResourceList(_) => "ResourceList".to_string(),
            Resource(_) => "Resource".to_string(),
            ResoureceName(_) => "ResoureceName".to_string(),
            ResourceId(_) => "ResourceId".to_string(),
            ResourceSize(_) => "ResourceSize".to_string(),
            ResourceSizeNew(_) => "ResourceSizeNew".to_string(),
            ResourceSizeValid(_) => "ResourceSizeValid".to_string(),
            ResourceSizeMin(_) => "ResourceSizeMin".to_string(),
            ResourceSizeMax(_) => "ResourceSizeMax".to_string(),
            ResourceSizeGran(_) => "ResourceSizeGran".to_string(),
            ResourceUnit(_) => "ResourceUnit".to_string(),
            ResourceOcc(_) => "ResourceOcc".to_string(),
            DpipeTableResourceId(_) => "DpipeTableResourceId".to_string(),
            DpipeTableResourceUnit(_) => "DpipeTableResourceUnit".to_string(),
            PortFlavour(_) => "PortFlavour".to_string(),
            PortNumber(_) => "PortNumber".to_string(),
            Param(_) => "Param".to_string(),
            ParamName(_) => "ParamName".to_string(),
            ParamGeneric(_) => "ParamGeneric".to_string(),
            ParamType(_) => "ParamType".to_string(),
            ParamValueList(_) => "ParamValueList".to_string(),
            ParamValue(_) => "ParamValue".to_string(),
            ParamValueData(_) => "ParamValueData".to_string(),
            ParamValueCmode(_) => "ParamValueCmode".to_string(),
            RegionName(_) => "RegionName".to_string(),
            RegionSize(_) => "RegionSize".to_string(),
            RegionSnapshots(_) => "RegionSnapshots".to_string(),
            RegionSnapshot(_) => "RegionSnapshot".to_string(),
            RegionSnapshotId(_) => "RegionSnapshotId".to_string(),
            RegionChunks(_) => "RegionChunks".to_string(),
            RegionChunk(_) => "RegionChunk".to_string(),
            RegionChunkData(_) => "RegionChunkData".to_string(),
            RegionChunkOffset(_) => "RegionChunkOffset".to_string(),
            RegionChunkSize(_) => "RegionChunkSize".to_string(),
            InfoDriverName(_) => "InfoDriverName".to_string(),
            InfoSerialNo(_) => "InfoSerialNo".to_string(),
            InfoVersionFixed(_) => "InfoVersionFixed".to_string(),
            InfoVersionRunning(_) => "InfoVersionRunning".to_string(),
            InfoVersionStored(_) => "InfoVersionStored".to_string(),
            InfoVersionName(_) => "InfoVersionName".to_string(),
            InfoVersionValue(_) => "InfoVersionValue".to_string(),
            SbPoolCellSize(_) => "SbPoolCellSize".to_string(),
            Fmsg(_) => "Fmsg".to_string(),
            FmsgObjNestStart(_) => "FmsgObjNestStart".to_string(),
            FmsgPairNestStart(_) => "FmsgPairNestStart".to_string(),
            FmsgArrNestStart(_) => "FmsgArrNestStart".to_string(),
            FmsgNestEnd(_) => "FmsgNestEnd".to_string(),
            FmsgObjName(_) => "FmsgObjName".to_string(),
            FmsgObjValueType(_) => "FmsgObjValueType".to_string(),
            FmsgObjValueData(_) => "FmsgObjValueData".to_string(),
            HealthReporter(_) => "HealthReporter".to_string(),
            HealthReporterName(_) => "HealthReporterName".to_string(),
            HealthReporterState(_) => "HealthReporterState".to_string(),
            HealthReporterErrCount(_) => "HealthReporterErrCount".to_string(),
            HealthReporterRecoverCount(_) => "HealthReporterRecoverCount".to_string(),
            HealthReporterDumpTs(_) => "HealthReporterDumpTs".to_string(),
            HealthReporterGracefulPeriod(_) => "HealthReporterGracefulPeriod".to_string(),
            HealthReporterAucoRecover(_) => "HealthReporterAucoRecover".to_string(),
            FlashUpdateFileName(_) => "FlashUpdateFileName".to_string(),
            FlashUpdateComponent(_) => "FlashUpdateComponent".to_string(),
            FlashUpdateStatusMsg(_) => "FlashUpdateStatusMsg".to_string(),
            FlashUpdateStatusDone(_) => "FlashUpdateStatusDone".to_string(),
            FlashUpdateStatusTotal(_) => "FlashUpdateStatusTotal".to_string(),
            PortPciPfNumber(_) => "PortPciPfNumber".to_string(),
            PortPciVfNumber(_) => "PortPciVfNumber".to_string(),
            Stats(_) => "Stats".to_string(),
            TrapName(_) => "TrapName".to_string(),
            TrapAction(_) => "TrapAction".to_string(),
            TrapType(_) => "TrapType".to_string(),
            TrapGeneric(_) => "TrapGeneric".to_string(),
            TrapMetadata(_) => "TrapMetadata".to_string(),
            TrapGroupName(_) => "TrapGroupName".to_string(),
            ReloadStatus(_) => "ReloadStatus".to_string(),
            HealthReporterDumpTsNs(_) => "HealthReporterDumpTsNs".to_string(),
            NetnsFd(_) => "NetnsFd".to_string(),
            NetnsPid(_) => "NetnsPid".to_string(),
            NetnsId(_) => "NetnsId".to_string(),
            HealthReporterAutoDump(_) => "HealthReporterAutoDump".to_string(),
            TrapPolicerId(_) => "TrapPolicerId".to_string(),
            TrapPolicerRate(_) => "TrapPolicerRate".to_string(),
            TrapPolicerBurst(_) => "TrapPolicerBurst".to_string(),
            PortFunction(_) => "PortFunction".to_string(),
            InfoBoardSerialNumber(_) => "InfoBoardSerialNumber".to_string(),
            PortLanes(_) => "PortLanes".to_string(),
            PortSplittable(_) => "PortSplittable".to_string(),
            PortExternal(_) => "PortExternal".to_string(),
            PortControllerNo(_) => "PortControllerNo".to_string(),
            FlashUpdateStatusTimeout(_) => "FlashUpdateStatusTimeout".to_string(),
            FlashUpdateOverWriteMask(_) => "FlashUpdateOverWriteMask".to_string(),
            ReloadAction(_) => "ReloadAction".to_string(),
            ReloadActionPerformed(_) => "ReloadActionPerformed".to_string(),
            ReloadLimits(_) => "ReloadLimits".to_string(),
            DevStats(_) => "DevStats".to_string(),
            ReloadStats(_) => "ReloadStats".to_string(),
            ReloadStatsEntry(_) => "ReloadStatsEntry".to_string(),
            ReloadStatsLimit(_) => "ReloadStatsLimit".to_string(),
            ReloadStatsValue(_) => "ReloadStatsValue".to_string(),
            RemoteReloadStats(_) => "RemoteReloadStats".to_string(),
            ReloadActionInfo(_) => "ReloadActionInfo".to_string(),
            ReloadActionStats(_) => "ReloadActionStats".to_string(),
            PortPciSfNo(_) => "PortPciSfNo".to_string(),
            RateType(_) => "RateType".to_string(),
            RateTxShare(_) => "RateTxShare".to_string(),
            RateTxMax(_) => "RateTxMax".to_string(),
            RateNodeName(_) => "RateNodeName".to_string(),
            RateParentNodeName(_) => "RateParentNodeName".to_string(),
            RegionMaxSnapshots(_) => "RegionMaxSnapshots".to_string(),
        }
    }
}

impl fmt::Display for GenlDevlinkAttrs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use GenlDevlinkAttrs::*;
        match self {
            BusName(s) => write!(f, "BusName: {s}"),
            Location(s) => write!(f, "Location: {s}"),
            PortIndex(v) => write!(f, "PortIndex: {v}"),
            PortType(v) => write!(f, "PortType: {v}"),
            DesiredType(v) => write!(f, "DesiredType: {v}"),
            NetdevIndex(v) => write!(f, "NetdevIndex: {v}"),
            NetdevName(s) => write!(f, "NetdevName: {s}"),
            PortIbdevName(s) => write!(f, "PortIbdevName: {s}"),
            PortSplitCount(v) => write!(f, "PortSplitCount: {v}"),
            PortSplitGroup(v) => write!(f, "PortSplitGroup: {v}"),
            SbIndex(v) => write!(f, "SbIndex: {v}"),
            SbSize(v) => write!(f, "SbSize: {v}"),
            SbIngressPoolCount(v) => write!(f, "SbIngressPoolCount: {v}"),
            SbEgressPoolCount(v) => write!(f, "SbEgressPoolCount: {v}"),
            SbIngressTcCount(v) => write!(f, "SbIngressTcCount: {v}"),
            SbEgressTcCount(v) => write!(f, "SbEgressTcCount: {v}"),
            SbPoolIndex(v) => write!(f, "SbPoolIndex: {v}"),
            SbPoolType(v) => write!(f, "SbPoolType: {v}"),
            SbPoolSize(v) => write!(f, "SbPoolSize: {v}"),
            SbPoolThresholdType(v) => write!(f, "SbPoolThresholdType: {v}"),
            SbPoolThreshold(v) => write!(f, "SbPoolThreshold: {v}"),
            SbTcIndex(v) => write!(f, "SbTcIndex: {v}"),
            SbOccCur(v) => write!(f, "SbOccCur: {v}"),
            SbOccMax(v) => write!(f, "SbOccMax: {v}"),
            EswitchMode(v) => write!(f, "EswitchMode: {v}"),
            EswitchInlineMode(v) => write!(f, "EswitchInlineMode: {v}"),
            DpipeTableName(s) => write!(f, "DpipeTableName: {s}"),
            DpipeTableSize(v) => write!(f, "DpipeTableSize: {v}"),
            DpipeTableCountersEnabled(v) => write!(f, "DpipeTableCountersEnabled: {v}"),
            DpipeEntryIndex(v) => write!(f, "DpipeEntryIndex: {v}"),
            DpipeEntryCounter(v) => write!(f, "DpipeEntryCounter: {v}"),
            DpipeMatchType(v) => write!(f, "DpipeMatchType: {v}"),
            DpipeActionType(v) => write!(f, "DpipeActionType: {v}"),
            DpipeValue(v) => write!(f, "DpipeValue: {v}"),
            DpipeValueMask(v) => write!(f, "DpipeValueMask: {v}"),
            DpipeValueMapping(v) => write!(f, "DpipeValueMapping: {v}"),
            DpipeHeaderName(s) => write!(f, "DpipeHeaderName: {s}"),
            DpipeHeaderId(v) => write!(f, "DpipeHeaderId: {v}"),
            DpipeHeaderGlobal(v) => write!(f, "DpipeHeaderGlobal: {v}"),
            DpipeHeaderIndex(v) => write!(f, "DpipeHeaderIndex: {v}"),
            DpipeFieldName(s) => write!(f, "DpipeFieldName: {s}"),
            DpipeFieldId(v) => write!(f, "DpipeFieldId: {v}"),
            DpipeFieldBitwidth(v) => write!(f, "DpipeFieldBitwidth: {v}"),
            DpipeFieldMappingType(v) => write!(f, "DpipeFieldMappingType: {v}"),
            EswitchEncapMode(v) => write!(f, "EswitchEncapMode: {v}"),
            ResoureceName(s) => write!(f, "ResoureceName: {s}"),
            ResourceId(v) => write!(f, "ResourceId: {v}"),
            ResourceSize(v) => write!(f, "ResourceSize: {v}"),
            ResourceSizeNew(v) => write!(f, "ResourceSizeNew: {v}"),
            ResourceSizeValid(v) => write!(f, "ResourceSizeValid: {v}"),
            ResourceSizeMin(v) => write!(f, "ResourceSizeMin: {v}"),
            ResourceSizeMax(v) => write!(f, "ResourceSizeMax: {v}"),
            ResourceSizeGran(v) => write!(f, "ResourceSizeGran: {v}"),
            ResourceUnit(v) => write!(f, "ResourceUnit: {v}"),
            ResourceOcc(v) => write!(f, "ResourceOcc: {v}"),
            DpipeTableResourceId(v) => write!(f, "DpipeTableResourceId: {v}"),
            DpipeTableResourceUnit(v) => write!(f, "DpipeTableResourceUnit: {v}"),
            PortFlavour(v) => write!(f, "PortFlavour: {v}"),
            PortNumber(v) => write!(f, "PortNumber: {v}"),
            ParamName(s) => write!(f, "ParamName: {s}"),
            ParamGeneric(v) => write!(f, "ParamGeneric: {v}"),
            ParamType(v) => write!(f, "ParamType: {v}"),
            ParamValue(v) => write!(f, "ParamValue: {v}"),
            ParamValueCmode(v) => write!(f, "ParamValueCmode: {v}"),
            RegionName(s) => write!(f, "RegionName: {s}"),
            RegionSize(v) => write!(f, "RegionSize: {v}"),
            RegionSnapshotId(v) => write!(f, "RegionSnapshotId: {v}"),
            RegionChunkData(v) => write!(f, "RegionChunkData: {v:?}"),
            RegionChunkOffset(v) => write!(f, "RegionChunkOffset: {v}"),
            RegionChunkSize(v) => write!(f, "RegionChunkSize: {v}"),
            InfoDriverName(s) => write!(f, "InfoDriverName: {s}"),
            InfoSerialNo(s) => write!(f, "InfoSerialNo: {s}"),
            InfoVersionName(s) => write!(f, "InfoVersionName: {s}"),
            InfoVersionValue(s) => write!(f, "InfoVersionValue: {s}"),
            SbPoolCellSize(v) => write!(f, "SbPoolCellSize: {v}"),
            FmsgObjNestStart(v) => write!(f, "FmsgObjNestStart: {v}"),
            FmsgPairNestStart(v) => write!(f, "FmsgPairNestStart: {v}"),
            FmsgArrNestStart(v) => write!(f, "FmsgArrNestStart: {v}"),
            FmsgNestEnd(v) => write!(f, "FmsgNestEnd: {v}"),
            FmsgObjName(s) => write!(f, "FmsgObjName: {s}"),
            FmsgObjValueType(v) => write!(f, "FmsgObjValueType: {v}"),
            HealthReporterName(s) => write!(f, "HealthReporterName: {s}"),
            HealthReporterState(v) => write!(f, "HealthReporterState: {v}"),
            HealthReporterErrCount(v) => write!(f, "HealthReporterErrCount: {v}"),
            HealthReporterRecoverCount(v) => write!(f, "HealthReporterRecoverCount: {v}"),
            HealthReporterDumpTs(v) => write!(f, "HealthReporterDumpTs: {v}"),
            HealthReporterGracefulPeriod(v) => write!(f, "HealthReporterGracefulPeriod: {v}"),
            HealthReporterAucoRecover(v) => write!(f, "HealthReporterAucoRecover: {v}"),
            FlashUpdateFileName(s) => write!(f, "FlashUpdateFileName: {s}"),
            FlashUpdateComponent(s) => write!(f, "FlashUpdateComponent: {s}"),
            FlashUpdateStatusMsg(s) => write!(f, "FlashUpdateStatusMsg: {s}"),
            FlashUpdateStatusTimeout(v) => write!(f, "FlashUpdateStatusTimeout: {v}"),
            FlashUpdateOverWriteMask(v) => write!(f, "FlashUpdateOverWriteMask: {v}"),
            ReloadAction(v) => write!(f, "ReloadAction: {v}"),
            ReloadActionPerformed(v) => write!(f, "ReloadActionPerformed: {v}"),
            ReloadLimits(v) => write!(f, "ReloadLimits: {v}"),
            PortPciSfNo(v) => write!(f, "PortPciSfNo: {v}"),
            RateType(v) => write!(f, "RateType: {v}"),
            RateTxShare(v) => write!(f, "RateTxShare: {v}"),
            RateTxMax(v) => write!(f, "RateTxMax: {v}"),
            RateNodeName(s) => write!(f, "RateNodeName: {s}"),
            RateParentNodeName(s) => write!(f, "RateParentNodeName: {s}"),
            RegionMaxSnapshots(v) => write!(f, "RegionMaxSnapshots: {v}"),
            FlashUpdateStatusDone(v) => write!(f, "FlashUpdateStatusDone: {v}"),
            FlashUpdateStatusTotal(v) => write!(f, "FlashUpdateStatusTotal: {v}"),
            PortPciPfNumber(v) => write!(f, "PortPciPfNumber: {v}"),
            PortPciVfNumber(v) => write!(f, "PortPciVfNumber: {v}"),
            TrapName(s) => write!(f, "TrapName: {s}"),
            TrapAction(v) => write!(f, "TrapAction: {v}"),
            TrapType(v) => write!(f, "TrapType: {v}"),
            TrapGeneric(v) => write!(f, "TrapGeneric: {v}"),
            TrapGroupName(s) => write!(f, "TrapGroupName: {s}"),
            ReloadStatus(v) => write!(f, "ReloadStatus: {v}"),
            HealthReporterDumpTsNs(v) => write!(f, "HealthReporterDumpTsNs: {v}"),
            NetnsFd(v) => write!(f, "NetnsFd: {v}"),
            NetnsPid(v) => write!(f, "NetnsPid: {v}"),
            NetnsId(v) => write!(f, "NetnsId: {v}"),
            HealthReporterAutoDump(v) => write!(f, "HealthReporterAutoDump: {v}"),
            TrapPolicerId(v) => write!(f, "TrapPolicerId: {v}"),
            TrapPolicerRate(v) => write!(f, "TrapPolicerRate: {v}"),
            TrapPolicerBurst(v) => write!(f, "TrapPolicerBurst: {v}"),
            InfoBoardSerialNumber(s) => write!(f, "InfoBoardSerialNumber: {s}"),
            PortLanes(v) => write!(f, "PortLanes: {v}"),
            PortSplittable(v) => write!(f, "PortSplittable: {v}"),
            PortExternal(v) => write!(f, "PortExternal: {v}"),
            PortControllerNo(v) => write!(f, "PortControllerNo: {v}"),
            ReloadStatsLimit(v) => write!(f, "ReloadStatsLimit: {v}"),
            ReloadStatsValue(v) => write!(f, "ReloadStatsValue: {v}"),

            RemoteReloadStats(v) |
            ReloadActionInfo(v) |
            ReloadActionStats(v) |
            DevStats(v) |
            ReloadStats(v) |
            ReloadStatsEntry(v) |
            PortFunction(v) |
            TrapMetadata(v) |
            Stats(v) |
            DpipeEntries(v) |
            DpipeEntry(v) |
            DpipeEntryMatchValues(v) |
            DpipeEntryActionValues(v) |
            DpipeMatch(v) |
            DpipeMatchValue(v) |
            DpipeAction(v) |
            DpipeActionValue(v) |
            DpipeHeaders(v) |
            DpipeHader(v) |
            DpipeHeaderFields(v) |
            DpipeField(v) |
            ResourceList(v) |
            Resource(v) |
            Param(v) |
            ParamValueList(v) |
            ParamValueData(v) |
            RegionSnapshots(v) |
            RegionSnapshot(v) |
            RegionChunks(v) |
            RegionChunk(v) |
            Fmsg(v) |
            InfoVersionFixed(v) |
            InfoVersionRunning(v) |
            InfoVersionStored(v) |
            DpipeTable(v) |
            DpipeTableMatches(v) |
            DpipeTableActions(v) |
            FmsgObjValueData(v) |
            HealthReporter(v) |
            DpipeTables(v) => {
                let attibutes = v
                    .iter()
                    .map(|attr| attr.to_string())
                    .collect::<Vec<String>>()
                    .join(", ");
                write!(f, "{}: {}", self.get_attribute_name(), attibutes)
            }
        }
    }
}

impl Nla for GenlDevlinkAttrs {
    fn value_len(&self) -> usize {
        use GenlDevlinkAttrs::*;
        match self {
            BusName(s) => s.len() + 1,
            Location(s) => s.len() + 1,
            PortIndex(v) => size_of_val(v),
            PortType(v) => size_of_val(v),
            DesiredType(v) => size_of_val(v),
            NetdevIndex(v) => size_of_val(v),
            NetdevName(s) => s.len() + 1,
            PortFlavour(v) => size_of_val(v),
            PortNumber(v) => size_of_val(v),
            Param(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            ParamName(s) => s.len() + 1,
            ParamGeneric(v) => size_of_val(v),
            ParamType(v) => size_of_val(v),
            ParamValueList(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            ParamValue(v) => size_of_val(v),
            ParamValueData(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            ParamValueCmode(v) => size_of_val(v),
            RegionName(s) => s.len() + 1,
            RegionSize(v) => size_of_val(v),
            RegionSnapshots(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            RegionSnapshot(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            RegionSnapshotId(v) => size_of_val(v),
            RegionChunks(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            RegionChunk(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            RegionChunkData(nla) => nla.len(),
            RegionChunkOffset(v) => size_of_val(v),
            RegionChunkSize(v) => size_of_val(v),
            InfoDriverName(s) => s.len() + 1,
            InfoSerialNo(s) => s.len() + 1,
            InfoVersionFixed(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            InfoVersionRunning(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            InfoVersionStored(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            InfoVersionName(s) => s.len() + 1,
            InfoVersionValue(s) => s.len() + 1,
            FlashUpdateFileName(s) => s.len() + 1,
            ReloadStatus(v) => size_of_val(v),
            ReloadAction(v) => size_of_val(v),
            DevStats(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            ReloadStats(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            ReloadStatsEntry(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            ReloadStatsLimit(v) => size_of_val(v),
            ReloadStatsValue(v) => size_of_val(v),
            RemoteReloadStats(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            ReloadActionInfo(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            ReloadActionStats(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            RegionMaxSnapshots(v) => size_of_val(v),
            PortIbdevName(s) => s.len() + 1,
            PortSplitCount(v) => size_of_val(v),
            PortSplitGroup(v) => size_of_val(v),
            SbIndex(v) => size_of_val(v),
            SbSize(v) => size_of_val(v),
            SbIngressPoolCount(v) => size_of_val(v),
            SbEgressPoolCount(v) => size_of_val(v),
            SbIngressTcCount(v) => size_of_val(v),
            SbEgressTcCount(v) => size_of_val(v),
            SbPoolIndex(v) => size_of_val(v),
            SbPoolType(v) => size_of_val(v),
            SbPoolSize(v) => size_of_val(v),
            SbPoolThresholdType(v) => size_of_val(v),
            SbPoolThreshold(v) => size_of_val(v),
            SbTcIndex(v) => size_of_val(v),
            SbOccCur(v) => size_of_val(v),
            SbOccMax(v) => size_of_val(v),
            EswitchMode(v) => size_of_val(v),
            EswitchInlineMode(v) => size_of_val(v),
            DpipeTables(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeTable(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeTableName(s) => s.len() + 1,
            DpipeTableSize(v) => size_of_val(v),
            DpipeTableMatches(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeTableActions(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeTableCountersEnabled(v) => size_of_val(v),
            DpipeEntries(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeEntry(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeEntryIndex(v) => size_of_val(v),
            DpipeEntryMatchValues(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeEntryActionValues(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeEntryCounter(v) => size_of_val(v),
            DpipeMatch(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeMatchValue(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeMatchType(v) => size_of_val(v),
            DpipeAction(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeActionValue(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeActionType(v) => size_of_val(v),
            DpipeValue(v) => size_of_val(v),
            DpipeValueMask(v) => size_of_val(v),
            DpipeValueMapping(v) => size_of_val(v),
            DpipeHeaders(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeHader(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeHeaderName(s) => s.len() + 1,
            DpipeHeaderId(v) => size_of_val(v),
            DpipeHeaderFields(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeHeaderGlobal(v) => size_of_val(v),
            DpipeHeaderIndex(v) => size_of_val(v),
            DpipeField(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            DpipeFieldName(s) => s.len() + 1,
            DpipeFieldId(v) => size_of_val(v),
            DpipeFieldBitwidth(v) => size_of_val(v),
            DpipeFieldMappingType(v) => size_of_val(v),
            EswitchEncapMode(v) => size_of_val(v),
            ResourceList(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            Resource(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            ResoureceName(s) => s.len() + 1,
            ResourceId(v) => size_of_val(v),
            ResourceSize(v) => size_of_val(v),
            ResourceSizeNew(v) => size_of_val(v),
            ResourceSizeValid(v) => size_of_val(v),
            ResourceSizeMin(v) => size_of_val(v),
            ResourceSizeMax(v) => size_of_val(v),
            ResourceSizeGran(v) => size_of_val(v),
            ResourceUnit(v) => size_of_val(v),
            ResourceOcc(v) => size_of_val(v),
            DpipeTableResourceId(v) => size_of_val(v),
            DpipeTableResourceUnit(v) => size_of_val(v),
            PortFunction(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            InfoBoardSerialNumber(s) => s.len() + 1,
            PortLanes(v) => size_of_val(v),
            PortSplittable(v) => size_of_val(v),
            PortExternal(v) => size_of_val(v),
            PortControllerNo(v) => size_of_val(v),
            FlashUpdateStatusTimeout(v) => size_of_val(v),
            FlashUpdateOverWriteMask(v) => size_of_val(v),
            ReloadActionPerformed(v) => size_of_val(v),
            ReloadLimits(v) => size_of_val(v),
            PortPciSfNo(v) => size_of_val(v),
            RateType(v) => size_of_val(v),
            RateTxShare(v) => size_of_val(v),
            RateTxMax(v) => size_of_val(v),
            RateNodeName(s) => s.len() + 1,
            RateParentNodeName(s) => s.len() + 1,
            SbPoolCellSize(v) => size_of_val(v),
            Fmsg(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            FmsgObjNestStart(v) => size_of_val(v),
            FmsgPairNestStart(v) => size_of_val(v),
            FmsgArrNestStart(v) => size_of_val(v),
            FmsgNestEnd(v) => size_of_val(v),
            FmsgObjName(s) => s.len() + 1,
            FmsgObjValueType(v) => size_of_val(v),
            FmsgObjValueData(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            HealthReporter(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            HealthReporterName(s) => s.len() + 1,
            HealthReporterState(v) => size_of_val(v),
            HealthReporterErrCount(v) => size_of_val(v),
            HealthReporterRecoverCount(v) => size_of_val(v),
            HealthReporterDumpTs(v) => size_of_val(v),
            HealthReporterGracefulPeriod(v) => size_of_val(v),
            HealthReporterAucoRecover(v) => size_of_val(v),
            FlashUpdateComponent(s) => s.len() + 1,
            FlashUpdateStatusMsg(s) => s.len() + 1,
            FlashUpdateStatusDone(v) => size_of_val(v),
            FlashUpdateStatusTotal(v) => size_of_val(v),
            PortPciPfNumber(v) => size_of_val(v),
            PortPciVfNumber(v) => size_of_val(v),
            Stats(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            TrapName(s) => s.len() + 1,
            TrapAction(v) => size_of_val(v),
            TrapType(v) => size_of_val(v),
            TrapGeneric(v) => size_of_val(v),
            TrapMetadata(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            TrapGroupName(s) => s.len() + 1,
            HealthReporterDumpTsNs(v) => size_of_val(v),
            NetnsFd(v) => size_of_val(v),
            NetnsPid(v) => size_of_val(v),
            NetnsId(v) => size_of_val(v),
            HealthReporterAutoDump(v) => size_of_val(v),
            TrapPolicerId(v) => size_of_val(v),
            TrapPolicerRate(v) => size_of_val(v),
            TrapPolicerBurst(v) => size_of_val(v),
        }
    }

    fn is_nested(&self) -> bool {
        use GenlDevlinkAttrs::*;
        match self {
            BusName(_) => false,
            Location(_) => false,
            PortIndex(_) => false,
            PortType(_) => false,
            DesiredType(_) => false,
            NetdevIndex(_) => false,
            NetdevName(_) => false,
            PortFlavour(_) => false,
            PortNumber(_) => false,
            Param(_) => true,
            ParamName(_) => false,
            ParamGeneric(_) => false,
            ParamType(_) => false,
            ParamValueList(_) => true,
            ParamValue(_) => true,
            ParamValueData(_) => false,
            ParamValueCmode(_) => false,
            RegionName(_) => false,
            RegionSize(_) => false,
            RegionSnapshots(_) => true,
            RegionSnapshot(_) => true,
            RegionSnapshotId(_) => false,
            RegionChunks(_) => true,
            RegionChunk(_) => true,
            RegionChunkData(_) => false,
            RegionChunkOffset(_) => false,
            RegionChunkSize(_) => false,
            InfoDriverName(_) => false,
            InfoSerialNo(_) => false,
            InfoVersionFixed(_) => true,
            InfoVersionRunning(_) => true,
            InfoVersionStored(_) => true,
            InfoVersionName(_) => false,
            InfoVersionValue(_) => false,
            FlashUpdateFileName(_) => false,
            ReloadStatus(_) => false,
            ReloadAction(_) => false,
            DevStats(_) => true,
            ReloadStats(_) => true,
            ReloadStatsEntry(_) => true,
            ReloadStatsLimit(_) => false,
            ReloadStatsValue(_) => false,
            RemoteReloadStats(_) => true,
            ReloadActionInfo(_) => true,
            ReloadActionStats(_) => true,
            RegionMaxSnapshots(_) => false,
            PortPciPfNumber(_) => false,
            PortPciVfNumber(_) => false,
            Stats(_) => true,
            TrapName(_) => false,
            TrapAction(_) => false,
            TrapType(_) => false,
            TrapGeneric(_) => false,
            TrapMetadata(_) => true,
            TrapGroupName(_) => false,
            HealthReporter(_) => true,
            HealthReporterName(_) => false,
            HealthReporterState(_) => false,
            HealthReporterErrCount(_) => false,
            HealthReporterRecoverCount(_) => false,
            HealthReporterDumpTs(_) => false,
            HealthReporterGracefulPeriod(_) => false,
            HealthReporterAucoRecover(_) => false,
            FlashUpdateComponent(_) => false,
            FlashUpdateStatusMsg(_) => false,
            FlashUpdateStatusDone(_) => false,
            FlashUpdateStatusTotal(_) => false,
            SbPoolCellSize(_) => false,
            Fmsg(_) => true,
            FmsgObjNestStart(_) => false,
            FmsgPairNestStart(_) => false,
            FmsgArrNestStart(_) => false,
            FmsgNestEnd(_) => false,
            FmsgObjName(_) => false,
            FmsgObjValueType(_) => false,
            FmsgObjValueData(_) => false,
            HealthReporterDumpTsNs(_) => false,
            NetnsFd(_) => false,
            NetnsPid(_) => false,
            NetnsId(_) => false,
            HealthReporterAutoDump(_) => false,
            TrapPolicerId(_) => false,
            TrapPolicerRate(_) => false,
            TrapPolicerBurst(_) => false,
            PortFunction(_) => true,
            InfoBoardSerialNumber(_) => false,
            PortLanes(_) => false,
            PortSplittable(_) => false,
            PortExternal(_) => false,
            PortControllerNo(_) => false,
            FlashUpdateStatusTimeout(_) => false,
            FlashUpdateOverWriteMask(_) => false,
            ReloadActionPerformed(_) => false,
            ReloadLimits(_) => false,
            PortPciSfNo(_) => false,
            RateType(_) => false,
            RateTxShare(_) => false,
            RateTxMax(_) => false,
            RateNodeName(_) => false,
            RateParentNodeName(_) => false,
            PortSplitCount(_) => false,
            PortSplitGroup(_) => false,
            SbIndex(_) => false,
            SbSize(_) => false,
            SbIngressPoolCount(_) => false,
            SbEgressPoolCount(_) => false,
            SbIngressTcCount(_) => false,
            SbEgressTcCount(_) => false,
            SbPoolIndex(_) => false,
            SbPoolType(_) => false,
            SbPoolSize(_) => false,
            SbPoolThresholdType(_) => false,
            SbPoolThreshold(_) => false,
            SbTcIndex(_) => false,
            SbOccCur(_) => false,
            SbOccMax(_) => false,
            EswitchMode(_) => false,
            EswitchInlineMode(_) => false,
            DpipeTables(_) => true,
            DpipeTable(_) => true,
            DpipeTableName(_) => false,
            DpipeTableSize(_) => false,
            DpipeTableMatches(_) => true,
            DpipeTableActions(_) => true,
            DpipeTableCountersEnabled(_) => false,
            DpipeEntries(_) => true,
            DpipeEntry(_) => true,
            DpipeEntryIndex(_) => false,
            DpipeEntryMatchValues(_) => true,
            DpipeEntryActionValues(_) => true,
            DpipeEntryCounter(_) => false,
            DpipeMatch(_) => true,
            DpipeMatchValue(_) => true,
            DpipeMatchType(_) => false,
            DpipeAction(_) => true,
            DpipeActionValue(_) => true,
            DpipeActionType(_) => false,
            DpipeValue(_) => false,
            DpipeValueMask(_) => false,
            DpipeValueMapping(_) => false,
            DpipeHeaders(_) => true,
            DpipeHader(_) => true,
            DpipeHeaderName(_) => false,
            DpipeHeaderId(_) => false,
            DpipeHeaderFields(_) => true,
            DpipeHeaderGlobal(_) => false,
            DpipeHeaderIndex(_) => false,
            DpipeField(_) => true,
            DpipeFieldName(_) => false,
            DpipeFieldId(_) => false,
            DpipeFieldBitwidth(_) => false,
            DpipeFieldMappingType(_) => false,
            EswitchEncapMode(_) => false,
            ResourceList(_) => true,
            Resource(_) => true,
            ResoureceName(_) => false,
            ResourceId(_) => false,
            ResourceSize(_) => false,
            ResourceSizeNew(_) => false,
            ResourceSizeValid(_) => false,
            ResourceSizeMin(_) => false,
            ResourceSizeMax(_) => false,
            ResourceSizeGran(_) => false,
            ResourceUnit(_) => false,
            ResourceOcc(_) => false,
            DpipeTableResourceId(_) => false,
            DpipeTableResourceUnit(_) => false,
            PortIbdevName(_) => false,
        }

    }

    fn kind(&self) -> u16 {
        use GenlDevlinkAttrs::*;
        match self {
            BusName(_) => DEVLINK_ATTR_BUS_NAME,
            Location(_) => DEVLINK_ATTR_LOCATION,
            PortIndex(_) => DEVLINK_ATTR_PORT_INDEX,
            PortType(_) => DEVLINK_ATTR_PORT_TYPE,
            DesiredType(_) => DEVLINK_ATTR_DESIRED_TYPE,
            NetdevIndex(_) => DEVLINK_ATTR_NETDEV_IF_INDEX,
            NetdevName(_) => DEVLINK_ATTR_NETDEV_NAME,
            PortFlavour(_) => DEVLINK_ATTR_PORT_FLAVOUR,
            PortNumber(_) => DEVLINK_ATTR_PORT_NUMBER,
            Param(_) => DEVLINK_ATTR_PARAM,
            ParamName(_) => DEVLINK_ATTR_PARAM_NAME,
            ParamGeneric(_) => DEVLINK_ATTR_PARAM_GENERIC,
            ParamType(_) => DEVLINK_ATTR_PARAM_TYPE,
            ParamValueList(_) => DEVLINK_ATTR_PARAM_VALUES_LIST,
            ParamValue(_) => DEVLINK_ATTR_PARAM_VALUE,
            ParamValueData(_) => DEVLINK_ATTR_PARAM_VALUE_DATA,
            ParamValueCmode(_) => DEVLINK_ATTR_PARAM_VALUE_CMODE,
            RegionName(_) => DEVLINK_ATTR_REGION_NAME,
            RegionSize(_) => DEVLINK_ATTR_REGION_SIZE,
            RegionSnapshots(_) => DEVLINK_ATTR_REGION_SNAPSHOTS,
            RegionSnapshot(_) => DEVLINK_ATTR_REGION_SNAPSHOT,
            RegionSnapshotId(_) => DEVLINK_ATTR_REGION_SNAPSHOT_ID,
            RegionChunks(_) => DEVLINK_ATTR_REGION_CHUNKS,
            RegionChunk(_) => DEVLINK_ATTR_REGION_CHUNK,
            RegionChunkData(_) => DEVLINK_ATTR_REGION_CHUNK_DATA,
            RegionChunkOffset(_) => DEVLINK_ATTR_REGION_CHUNK_ADDR,
            RegionChunkSize(_) => DEVLINK_ATTR_REGION_SIZE,
            InfoDriverName(_) => DEVLINK_ATTR_INFO_DRIVER_NAME,
            InfoSerialNo(_) => DEVLINK_ATTR_INFO_SERIAL_NUMBER,
            InfoVersionFixed(_) => DEVLINK_ATTR_INFO_VERSION_FIXED,
            InfoVersionRunning(_) => DEVLINK_ATTR_INFO_VERSION_RUNNING,
            InfoVersionStored(_) => DEVLINK_ATTR_INFO_VERSION_STORED,
            InfoVersionName(_) => DEVLINK_ATTR_INFO_VERSION_NAME,
            InfoVersionValue(_) => DEVLINK_ATTR_INFO_VERSION_VALUE,
            FlashUpdateFileName(_) => DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME,
            ReloadStatus(_) => DEVLINK_ATTR_RELOAD_FAILED,
            ReloadAction(_) => DEVLINK_ATTR_RELOAD_ACTION,
            DevStats(_) => DEVLINK_ATTR_DEV_STATS,
            ReloadStats(_) => DEVLINK_ATTR_RELOAD_STATS,
            ReloadStatsEntry(_) => DEVLINK_ATTR_RELOAD_STATS_ENTRY,
            ReloadStatsLimit(_) => DEVLINK_ATTR_RELOAD_STATS_LIMIT,
            ReloadStatsValue(_) => DEVLINK_ATTR_RELOAD_STATS_VALUE,
            RemoteReloadStats(_) => DEVLINK_ATTR_REMOTE_RELOAD_SATS,
            ReloadActionInfo(_) => DEVLINK_ATTR_RELOAD_ACTION_INFO,
            ReloadActionStats(_) => DEVLINK_ATTR_RELAOD_ACTION_STATS,
            RegionMaxSnapshots(_) => DEVLINK_ATTR_REGION_MAX_SNAPSHOTS,
            PortPciPfNumber(_) => DEVLINK_ATTR_PORT_PCI_PF_NUMBER,
            PortPciVfNumber(_) => DEVLINK_ATTR_PORT_PCI_VF_NUMBER,
            Stats(_) => DEVLINK_ATTR_STATS,
            TrapName(_) => DEVLINK_ATTR_TRAP_NAME,
            TrapAction(_) => DEVLINK_ATTR_TRAP_ACTION,
            TrapType(_) => DEVLINK_ATTR_TRAP_TYPE,
            TrapGeneric(_) => DEVLINK_ATTR_TRAP_GENERIC,
            TrapMetadata(_) => DEVLINK_ATTR_TRAP_METADATA,
            TrapGroupName(_) => DEVLINK_ATTR_TRAP_GROUP_NAME,
            HealthReporter(_) => DEVLINK_ATTR_HEALTH_REPORTER,
            HealthReporterName(_) => DEVLINK_ATTR_HEALTH_REPORTER_NAME,
            HealthReporterState(_) => DEVLINK_ATTR_HEALTH_REPORTER_STATE,
            HealthReporterErrCount(_) => DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT,
            HealthReporterRecoverCount(_) => DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT,
            HealthReporterDumpTs(_) => DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS,
            HealthReporterGracefulPeriod(_) => DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD,
            HealthReporterAucoRecover(_) => DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER,
            FlashUpdateComponent(_) => DEVLINK_ATTR_FLASH_UPDATE_COMPONENT,
            FlashUpdateStatusMsg(_) => DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG,
            FlashUpdateStatusDone(_) => DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE,
            FlashUpdateStatusTotal(_) => DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL,
            SbPoolCellSize(_) => DEVLINK_ATTR_SB_POOL_CELL_SIZE,
            Fmsg(_) => DEVLINK_ATTR_FMSG,
            FmsgObjNestStart(_) => DEVLINK_ATTR_FMSG_OBJ_NEST_START,
            FmsgPairNestStart(_) => DEVLINK_ATTR_FMSG_PAIR_NEST_START,
            FmsgArrNestStart(_) => DEVLINK_ATTR_FMSG_ARR_NEST_START,
            FmsgNestEnd(_) => DEVLINK_ATTR_FMSG_NEST_END,
            FmsgObjName(_) => DEVLINK_ATTR_FMSG_OBJ_NAME,
            FmsgObjValueType(_) => DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE,
            FmsgObjValueData(_) => DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA,
            HealthReporterDumpTsNs(_) => DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS,
            NetnsFd(_) => DEVLINK_ATTR_NETNS_FD,
            NetnsPid(_) => DEVLINK_ATTR_NETNS_PID,
            NetnsId(_) => DEVLINK_ATTR_NETNS_ID,
            HealthReporterAutoDump(_) => DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP,
            TrapPolicerId(_) => DEVLINK_ATTR_TRAP_POLICER_ID,
            TrapPolicerRate(_) => DEVLINK_ATTR_TRAP_POLICER_RATE,
            TrapPolicerBurst(_) => DEVLINK_ATTR_TRAP_POLICER_BURST,
            PortFunction(_) => DEVLINK_ATTR_PORT_FUNCTION,
            InfoBoardSerialNumber(_) => DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER,
            PortLanes(_) => DEVLINK_ATTR_PORT_LANES,
            PortSplittable(_) => DEVLINK_ATTR_PORT_SPLITTABLE,
            PortExternal(_) => DEVLINK_ATTR_PORT_EXTERNAL,
            PortControllerNo(_) => DEVLINK_ATTR_PORT_CONTROLLER_NUMBER,
            FlashUpdateStatusTimeout(_) => DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT,
            FlashUpdateOverWriteMask(_) => DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK,
            ReloadActionPerformed(_) => DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED,
            ReloadLimits(_) => DEVLINK_ATTR_RELOAD_LIMITS,
            PortPciSfNo(_) => DEVLINK_ATTR_PORT_PCI_SF_NUMBER,
            RateType(_) => DEVLINK_ATTR_RATE_TYPE,
            RateTxShare(_) => DEVLINK_ATTR_RATE_TX_SHARE,
            RateTxMax(_) => DEVLINK_ATTR_RATE_TX_MAX,
            RateNodeName(_) => DEVLINK_ATTR_RATE_NODE_NAME,
            RateParentNodeName(_) => DEVLINK_ATTR_RATE_PARENT_NODE_NAME,
            PortSplitCount(_) => DEVLINK_ATTR_PORT_SPLIT_COUNT,
            PortSplitGroup(_) => DEVLINK_ATTR_PORT_SPLIT_GROUP,
            SbIndex(_) => DEVLINK_ATTR_SB_INDEX,
            SbSize(_) => DEVLINK_ATTR_SB_SIZE,
            SbIngressPoolCount(_) => DEVLINK_ATTR_SB_INGRESS_POOL_COUNT,
            SbEgressPoolCount(_) => DEVLINK_ATTR_SB_EGRESS_POOL_COUNT,
            SbIngressTcCount(_) => DEVLINK_ATTR_SB_INGRESS_TC_COUNT,
            SbEgressTcCount(_) => DEVLINK_ATTR_SB_EGRESS_TC_COUNT,
            SbPoolIndex(_) => DEVLINK_ATTR_SB_POOL_INDEX,
            SbPoolType(_) => DEVLINK_ATTR_SB_POOL_TYPE,
            SbPoolSize(_) => DEVLINK_ATTR_SB_POOL_SIZE,
            SbPoolThresholdType(_) => DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE,
            SbPoolThreshold(_) => DEVLINK_ATTR_SB_THRESHOLD,
            SbTcIndex(_) => DEVLINK_ATTR_SB_TC_INDEX,
            SbOccCur(_) => DEVLINK_ATTR_SB_OCC_CUR,
            SbOccMax(_) => DEVLINK_ATTR_SB_OCC_MAX,
            EswitchMode(_) => DEVLINK_ATTR_ESWITCH_MODE,
            EswitchInlineMode(_) => DEVLINK_ATTR_ESWITCH_INLINE_MODE,
            DpipeTables(_) => DEVLINK_ATTR_DPIPE_TABLES,
            DpipeTable(_) => DEVLINK_ATTR_DPIPE_TABLE,
            DpipeTableName(_) => DEVLINK_ATTR_DPIPE_TABLE_NAME,
            DpipeTableSize(_) => DEVLINK_ATTR_DPIPE_TABLE_SIZE,
            DpipeTableMatches(_) => DEVLINK_ATTR_DPIPE_TABLE_MATCHES,
            DpipeTableActions(_) => DEVLINK_ATTR_DPIPE_TABLE_ACTIONS,
            DpipeTableCountersEnabled(_) => DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED,
            DpipeEntries(_) => DEVLINK_ATTR_DPIPE_ENTRIES,
            DpipeEntry(_) => DEVLINK_ATTR_DPIPE_ENTRY,
            DpipeEntryIndex(_) => DEVLINK_ATTR_DPIPE_ENTRY_INDEX,
            DpipeEntryMatchValues(_) => DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES,
            DpipeEntryActionValues(_) => DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES,
            DpipeEntryCounter(_) => DEVLINK_ATTR_DPIPE_ENTRY_COUNTER,
            DpipeMatch(_) => DEVLINK_ATTR_DPIPE_MATCH,
            DpipeMatchValue(_) => DEVLINK_ATTR_DPIPE_MATCH_VALUE,
            DpipeMatchType(_) => DEVLINK_ATTR_DPIPE_MATCH_TYPE,
            DpipeAction(_) => DEVLINK_ATTR_DPIPE_ACTION,
            DpipeActionValue(_) => DEVLINK_ATTR_DPIPE_ACTION_VALUE,
            DpipeActionType(_) => DEVLINK_ATTR_DPIPE_ACTION_TYPE,
            DpipeValue(_) => DEVLINK_ATTR_DPIPE_VALUE,
            DpipeValueMask(_) => DEVLINK_ATTR_DPIPE_VALUE_MASK,
            DpipeValueMapping(_) => DEVLINK_ATTR_DPIPE_VALUE_MAPPING,
            DpipeHeaders(_) => DEVLINK_ATTR_DPIPE_HEADERS,
            DpipeHader(_) => DEVLINK_ATTR_DPIPE_HEADER,
            DpipeHeaderName(_) => DEVLINK_ATTR_DPIPE_HEADER_NAME,
            DpipeHeaderId(_) => DEVLINK_ATTR_DPIPE_HEADER_ID,
            DpipeHeaderFields(_) => DEVLINK_ATTR_DPIPE_HEADER_FIELDS,
            DpipeHeaderGlobal(_) => DEVLINK_ATTR_DPIPE_HEADER_GLOBAL,
            DpipeHeaderIndex(_) => DEVLINK_ATTR_DPIPE_HEADER_INDEX,
            DpipeField(_) => DEVLINK_ATTR_DPIPE_FIELD,
            DpipeFieldName(_) => DEVLINK_ATTR_DPIPE_FIELD_NAME,
            DpipeFieldId(_) => DEVLINK_ATTR_DPIPE_FIELD_ID,
            DpipeFieldBitwidth(_) => DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH,
            DpipeFieldMappingType(_) => DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE,
            EswitchEncapMode(_) => DEVLINK_ATTR_ESWITCH_ENCAP_MODE,
            ResourceList(_) => DEVLINK_ATTR_RESOURCE_LIST,
            Resource(_) => DEVLINK_ATTR_RESOURCE,
            ResoureceName(_) => DEVLINK_ATTR_RESOURCE_NAME,
            ResourceId(_) => DEVLINK_ATTR_RESOURCE_ID,
            ResourceSize(_) => DEVLINK_ATTR_RESOURCE_SIZE,
            ResourceSizeNew(_) => DEVLINK_ATTR_RESOURCE_SIZE_NEW,
            ResourceSizeValid(_) => DEVLINK_ATTR_RESOURCE_SIZE_VALID,
            ResourceSizeMin(_) => DEVLINK_ATTR_RESOURCE_SIZE_MIN,
            ResourceSizeMax(_) => DEVLINK_ATTR_RESOURCE_SIZE_MAX,
            ResourceSizeGran(_) => DEVLINK_ATTR_RESOURCE_SIZE_GRAN,
            ResourceUnit(_) => DEVLINK_ATTR_RESOURCE_UNIT,
            ResourceOcc(_) => DEVLINK_ATTR_RESOURCE_OCC,
            DpipeTableResourceId(_) => DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID,
            DpipeTableResourceUnit(_) => DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS,
            PortIbdevName(_) => DEVLINK_ATTR_PORT_IBDEV_NAME,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use GenlDevlinkAttrs::*;
        match self {
            BusName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Location(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            PortIndex(v) => NativeEndian::write_u32(buffer, *v),
            PortType(v) => NativeEndian::write_u16(buffer, *v),
            DesiredType(v) => NativeEndian::write_u16(buffer, *v),
            NetdevIndex(v) => NativeEndian::write_u32(buffer, *v),
            NetdevName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            PortFlavour(v) => NativeEndian::write_u16(buffer, *v),
            PortNumber(v) => NativeEndian::write_u32(buffer, *v),
            Param(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            ParamName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            ParamGeneric(v) => buffer[0] = *v as u8,
            ParamType(v) => buffer[0] = *v,
            ParamValueList(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            ParamValue(v) => NativeEndian::write_u64(buffer, *v),
            ParamValueData(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            ParamValueCmode(v) => buffer[0] = *v,
            RegionName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            RegionSize(v) => NativeEndian::write_u64(buffer, *v),
            RegionSnapshots(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            RegionSnapshot(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            RegionSnapshotId(v) => NativeEndian::write_u32(buffer, *v),
            RegionChunks(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            RegionChunk(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            RegionChunkData(s) => {
                buffer[..s.len()].copy_from_slice(s);
            }
            RegionChunkOffset(v) => NativeEndian::write_u64(buffer, *v),
            RegionChunkSize(v) => NativeEndian::write_u64(buffer, *v),
            InfoDriverName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            InfoSerialNo(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            InfoVersionFixed(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            InfoVersionRunning(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            InfoVersionStored(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            InfoVersionName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            InfoVersionValue(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            FlashUpdateFileName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            ReloadStatus(v) => buffer[0] = *v,
            ReloadAction(v) => buffer[0] = *v,
            DevStats(v) => {
                v.iter().for_each(|val| val.emit_value(buffer));
            }
            ReloadStats(v) => {
                v.iter().for_each(|val| val.emit_value(buffer));
            }
            ReloadStatsEntry(v) => {
                v.iter().for_each(|val| val.emit_value(buffer));
            }
            ReloadStatsLimit(v) => buffer[0] = *v,
            ReloadStatsValue(v) => NativeEndian::write_u32(buffer, *v),
            RemoteReloadStats(v) => {
                v.iter().for_each(|val| val.emit_value(buffer));
            }
            ReloadActionInfo(v) => {
                v.iter().for_each(|val| val.emit_value(buffer));
            }
            ReloadActionStats(v) => {
                v.iter().for_each(|val| val.emit_value(buffer));
            }
            RegionMaxSnapshots(v) => NativeEndian::write_u32(buffer, *v),
            PortPciPfNumber(v) => NativeEndian::write_u16(buffer, *v),
            PortPciVfNumber(v) => NativeEndian::write_u16(buffer, *v),
            Stats(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            TrapName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            TrapAction(v) => buffer[0] = *v,
            TrapType(v) => buffer[0] = *v,
            TrapGeneric(v) => buffer[0] = *v as u8,
            TrapMetadata(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            TrapGroupName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            HealthReporter(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            HealthReporterName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            HealthReporterState(v) => buffer[0] = *v,
            HealthReporterErrCount(v) => NativeEndian::write_u64(buffer, *v),
            HealthReporterRecoverCount(v) => NativeEndian::write_u64(buffer, *v),
            HealthReporterDumpTs(v) => NativeEndian::write_u64(buffer, *v),
            HealthReporterGracefulPeriod(v) => NativeEndian::write_u64(buffer, *v),
            HealthReporterAucoRecover(v) => buffer[0] = *v,
            FlashUpdateComponent(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            FlashUpdateStatusMsg(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            FlashUpdateStatusDone(v) => NativeEndian::write_u64(buffer, *v),
            FlashUpdateStatusTotal(v) => NativeEndian::write_u64(buffer, *v),
            SbPoolCellSize(v) => NativeEndian::write_u32(buffer, *v),
            Fmsg(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            FmsgObjNestStart(v) => buffer[0] = *v as u8,
            FmsgPairNestStart(v) => buffer[0] = *v as u8,
            FmsgArrNestStart(v) => buffer[0] = *v as u8,
            FmsgNestEnd(v) => buffer[0] = *v as u8,
            FmsgObjName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            FmsgObjValueType(v) => buffer[0] = *v,
            FmsgObjValueData(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            HealthReporterDumpTsNs(v) => NativeEndian::write_u64(buffer, *v),
            NetnsFd(v) => NativeEndian::write_u32(buffer, *v),
            NetnsPid(v) => NativeEndian::write_u32(buffer, *v),
            NetnsId(v) => NativeEndian::write_u32(buffer, *v),
            HealthReporterAutoDump(v) => buffer[0] = *v,
            TrapPolicerId(v) => NativeEndian::write_u32(buffer, *v),
            TrapPolicerRate(v) => NativeEndian::write_u64(buffer, *v),
            TrapPolicerBurst(v) => NativeEndian::write_u64(buffer, *v),
            PortFunction(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            InfoBoardSerialNumber(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            PortLanes(v) => NativeEndian::write_u32(buffer, *v),
            PortSplittable(v) => buffer[0] = *v,
            PortExternal(v) => buffer[0] = *v,
            PortControllerNo(v) => NativeEndian::write_u32(buffer, *v),
            FlashUpdateStatusTimeout(v) => NativeEndian::write_u32(buffer, *v),
            FlashUpdateOverWriteMask(v) => NativeEndian::write_u32(buffer, *v),
            ReloadActionPerformed(v) => NativeEndian::write_u32(buffer, *v),
            ReloadLimits(v) => NativeEndian::write_u32(buffer, *v),
            PortPciSfNo(v) => NativeEndian::write_u32(buffer, *v),
            RateType(v) => NativeEndian::write_u16(buffer, *v),
            RateTxShare(v) => NativeEndian::write_u64(buffer, *v),
            RateTxMax(v) => NativeEndian::write_u64(buffer, *v),
            RateNodeName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            RateParentNodeName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            PortIbdevName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            PortSplitCount(v) => NativeEndian::write_u32(buffer, *v),
            PortSplitGroup(v) => NativeEndian::write_u32(buffer, *v),
            SbIndex(v) => NativeEndian::write_u32(buffer, *v),
            SbSize(v) => NativeEndian::write_u32(buffer, *v),
            SbIngressPoolCount(v) => NativeEndian::write_u16(buffer, *v),
            SbEgressPoolCount(v) => NativeEndian::write_u16(buffer, *v),
            SbIngressTcCount(v) => NativeEndian::write_u16(buffer, *v),
            SbEgressTcCount(v) => NativeEndian::write_u16(buffer, *v),
            SbPoolIndex(v) => NativeEndian::write_u16(buffer, *v),
            SbPoolType(v) => buffer[0] = *v,
            SbPoolSize(v) => NativeEndian::write_u32(buffer, *v),
            SbPoolThresholdType(v) => buffer[0] = *v,
            SbPoolThreshold(v) => NativeEndian::write_u32(buffer, *v),
            SbTcIndex(v) => NativeEndian::write_u16(buffer, *v),
            SbOccCur(v) => NativeEndian::write_u32(buffer, *v),
            SbOccMax(v) => NativeEndian::write_u32(buffer, *v),
            EswitchMode(v) => NativeEndian::write_u16(buffer, *v),
            EswitchInlineMode(v) => buffer[0] = *v,
            DpipeTables(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeTable(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeTableName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            DpipeTableSize(v) => NativeEndian::write_u64(buffer, *v),
            DpipeTableMatches(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeTableActions(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeTableCountersEnabled(v) => buffer[0] = *v,
            DpipeEntries(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeEntry(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeEntryIndex(v) => NativeEndian::write_u64(buffer, *v),
            DpipeEntryMatchValues(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeEntryActionValues(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeEntryCounter(v) => NativeEndian::write_u64(buffer, *v),
            DpipeMatch(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeMatchValue(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeMatchType(v) => NativeEndian::write_u32(buffer, *v),
            DpipeAction(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeActionValue(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeActionType(v) => NativeEndian::write_u32(buffer, *v),
            DpipeValue(v) => NativeEndian::write_u32(buffer, *v),
            DpipeValueMask(v) => NativeEndian::write_u32(buffer, *v),
            DpipeValueMapping(v) => NativeEndian::write_u32(buffer, *v),
            DpipeHeaders(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeHader(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeHeaderName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            DpipeHeaderId(v) => NativeEndian::write_u32(buffer, *v),
            DpipeHeaderFields(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeHeaderGlobal(v) => buffer[0] = *v,
            DpipeHeaderIndex(v) => NativeEndian::write_u32(buffer, *v),
            DpipeField(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            DpipeFieldName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            DpipeFieldId(v) => NativeEndian::write_u32(buffer, *v),
            DpipeFieldBitwidth(v) => NativeEndian::write_u32(buffer, *v),
            DpipeFieldMappingType(v) => NativeEndian::write_u32(buffer, *v),
            EswitchEncapMode(v) => buffer[0] = *v,
            ResourceList(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            Resource(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            ResoureceName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            ResourceId(v) => NativeEndian::write_u64(buffer, *v),
            ResourceSize(v) => NativeEndian::write_u64(buffer, *v),
            ResourceSizeNew(v) => NativeEndian::write_u64(buffer, *v),
            ResourceSizeValid(v) => buffer[0] = *v,
            ResourceSizeMin(v) => NativeEndian::write_u64(buffer, *v),
            ResourceSizeMax(v) => NativeEndian::write_u64(buffer, *v),
            ResourceSizeGran(v) => NativeEndian::write_u64(buffer, *v),
            ResourceUnit(v) => buffer[0] = *v,
            ResourceOcc(v) => NativeEndian::write_u64(buffer, *v),
            DpipeTableResourceId(v) => NativeEndian::write_u64(buffer, *v),
            DpipeTableResourceUnit(v) => NativeEndian::write_u64(buffer, *v),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for GenlDevlinkAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            DEVLINK_ATTR_BUS_NAME => Self::BusName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_BUS_NAME value")?,
            ),
            DEVLINK_ATTR_LOCATION => Self::Location(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_LOCATION value")?,
            ),
            DEVLINK_ATTR_PORT_INDEX => Self::PortIndex(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_INDEX value")?,
            ),
            DEVLINK_ATTR_PORT_TYPE => Self::PortType(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_PORT_TYPE value")?,
            ),
            DEVLINK_ATTR_DESIRED_TYPE => Self::DesiredType(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_DESIRED_TYPE value")?,
            ),
            DEVLINK_ATTR_NETDEV_IF_INDEX => Self::NetdevIndex(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_NETDEV_IF_INDEX value")?,
            ),
            DEVLINK_ATTR_NETDEV_NAME => Self::NetdevName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_NETDEV_NAME value")?,
            ),
            DEVLINK_ATTR_PORT_FLAVOUR => Self::PortFlavour(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_PORT_FLAVOUR value")?,
            ),
            DEVLINK_ATTR_PORT_NUMBER => Self::PortNumber(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_NUMBER value")?,
            ),
            DEVLINK_ATTR_PARAM => Self::Param({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_PARAM")?
            }),
            DEVLINK_ATTR_PARAM_NAME => Self::ParamName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_NAME value")?,
            ),
            DEVLINK_ATTR_PARAM_GENERIC => Self::ParamGeneric({
                let val = parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_GENERIC value")?;
                val != 0
            }),
            DEVLINK_ATTR_PARAM_TYPE => Self::ParamType(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_TYPE value")?,
            ),
            DEVLINK_ATTR_PARAM_VALUES_LIST => Self::ParamValueList({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_PARAM_VALUE_LIST")?
            }),
            DEVLINK_ATTR_PARAM_VALUE => Self::ParamValue(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_VALUE value")?,
            ),
            DEVLINK_ATTR_PARAM_VALUE_DATA => Self::ParamValueData({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_REGION_CHUNK")?
            }),
            DEVLINK_ATTR_PARAM_VALUE_CMODE => Self::ParamValueCmode(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_VALUE_CMODE value")?,
            ),
            DEVLINK_ATTR_REGION_NAME => Self::RegionName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_REGION_NAME value")?,
            ),
            DEVLINK_ATTR_REGION_SIZE => Self::RegionSize(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_REGION_SIZE value")?,
            ),
            DEVLINK_ATTR_REGION_SNAPSHOTS => Self::RegionSnapshots({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_REGION_SNAPSHOTS")?
            }),
            DEVLINK_ATTR_REGION_SNAPSHOT => Self::RegionSnapshot({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_REGION_CHUNK")?
            }),
            DEVLINK_ATTR_REGION_SNAPSHOT_ID => Self::RegionSnapshotId(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_REGION_SNAPSHOT_ID value")?,
            ),
            DEVLINK_ATTR_REGION_CHUNKS => Self::RegionChunks({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_REGION_CHUNKS")?
            }),
            DEVLINK_ATTR_REGION_CHUNK => Self::RegionChunk({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_REGION_CHUNK")?
            }),
            // DEVLINK_ATTR_REGION_CHUNK_DATA => Self::RegionChunkData(_),
            DEVLINK_ATTR_REGION_CHUNK_ADDR => Self::RegionChunkOffset(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_REGION_CHUNK_ADDR value")?,
            ),
            DEVLINK_ATTR_INFO_DRIVER_NAME => Self::InfoDriverName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_INFO_DRIVER_NAME value")?,
            ),
            DEVLINK_ATTR_INFO_SERIAL_NUMBER => Self::InfoSerialNo(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_INFO_SERIAL_NUMBER value")?,
            ),
            DEVLINK_ATTR_INFO_VERSION_FIXED => Self::InfoVersionFixed({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_INFO_VERSION_FIXED",
                    )?
            }),
            DEVLINK_ATTR_INFO_VERSION_RUNNING => Self::InfoVersionRunning({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_INFO_VERSION_RUNNING",
                    )?
            }),
            DEVLINK_ATTR_INFO_VERSION_STORED => Self::InfoVersionStored({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_INFO_VERSION_STORED",
                    )?
            }),
            DEVLINK_ATTR_INFO_VERSION_NAME => Self::InfoVersionName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_INFO_VERSION_NAME value")?,
            ),
            DEVLINK_ATTR_INFO_VERSION_VALUE => Self::InfoVersionValue(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_INFO_VERSION_VALUE value")?,
            ),
            DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME => {
                Self::FlashUpdateFileName(parse_string(payload).context(
                    "invalid DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME value",
                )?)
            }
            DEVLINK_ATTR_RELOAD_FAILED => Self::ReloadStatus(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_RELOAD_FAILED value")?,
            ),
            DEVLINK_ATTR_RELOAD_ACTION => Self::ReloadAction(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_RELOAD_ACTION value")?,
            ),
            DEVLINK_ATTR_DEV_STATS => Self::DevStats({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_DEV_STATS",
                    )?
            }),
            DEVLINK_ATTR_RELOAD_STATS => Self::ReloadStats({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_RELOAD_STATS",
                    )?
            }),
            DEVLINK_ATTR_RELOAD_STATS_ENTRY => Self::ReloadStatsEntry({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_RELOAD_STATS_ENTRY",
                    )?
            }),
            DEVLINK_ATTR_RELOAD_STATS_LIMIT => Self::ReloadStatsLimit(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_RELOAD_STATS_LIMIT value")?,
            ),
            DEVLINK_ATTR_RELOAD_STATS_VALUE => Self::ReloadStatsValue(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_RELOAD_STATS_VALUE value")?,
            ),
            DEVLINK_ATTR_REMOTE_RELOAD_SATS => Self::RemoteReloadStats({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_REMOTE_RELOAD_SATS",
                    )?
            }),
            DEVLINK_ATTR_RELOAD_ACTION_INFO => Self::ReloadActionInfo({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_RELOAD_ACTION_INFO",
                    )?
            }),
            DEVLINK_ATTR_RELAOD_ACTION_STATS => Self::ReloadActionStats({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_RELAOD_ACTION_STATS",
                    )?
            }),
            DEVLINK_ATTR_REGION_MAX_SNAPSHOTS => Self::RegionMaxSnapshots(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_REGION_MAX_SNAPSHOTS value")?,
            ),
            DEVLINK_ATTR_PORT_PCI_PF_NUMBER => Self::PortPciPfNumber(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_PORT_PCI_PF_NUMBER value")?,
            ),
            DEVLINK_ATTR_PORT_PCI_VF_NUMBER => Self::PortPciVfNumber(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_PORT_PCI_VF_NUMBER value")?,
            ),
            DEVLINK_ATTR_STATS => Self::Stats({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_STATS")?
            }),
            DEVLINK_ATTR_TRAP_NAME => Self::TrapName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_TRAP_NAME value")?,
            ),
            DEVLINK_ATTR_TRAP_ACTION => Self::TrapAction(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_TRAP_ACTION value")?,
            ),
            DEVLINK_ATTR_TRAP_TYPE => Self::TrapType(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_TRAP_TYPE value")?,
            ),
            DEVLINK_ATTR_TRAP_GENERIC => Self::TrapGeneric({
                let val = parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_TRAP_GENERIC value")?;
                val != 0
            }),
            DEVLINK_ATTR_TRAP_METADATA => Self::TrapMetadata({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_TRAP_METADATA")?
            }),
            DEVLINK_ATTR_TRAP_GROUP_NAME => Self::TrapGroupName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_TRAP_GROUP_NAME value")?,
            ),
            DEVLINK_ATTR_HEALTH_REPORTER => Self::HealthReporter({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_HEALTH_REPORTER")?
            }),
            DEVLINK_ATTR_HEALTH_REPORTER_NAME => Self::HealthReporterName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_HEALTH_REPORTER_NAME value")?,
            ),
            DEVLINK_ATTR_HEALTH_REPORTER_STATE => Self::HealthReporterState(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_HEALTH_REPORTER_STATE value")?,
            ),
            DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT => Self::HealthReporterErrCount(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT value")?,
            ),
            DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT => Self::HealthReporterRecoverCount(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT value")?,
            ),
            DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS => Self::HealthReporterDumpTs(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS value")?,
            ),
            DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD => Self::HealthReporterGracefulPeriod(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD value")?,
            ),
            DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER => Self::HealthReporterAucoRecover(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER value")?,
            ),
            DEVLINK_ATTR_FLASH_UPDATE_COMPONENT => Self::FlashUpdateComponent(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_FLASH_UPDATE_COMPONENT value")?,
            ),
            DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG => Self::FlashUpdateStatusMsg(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG value")?,
            ),
            DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE => Self::FlashUpdateStatusDone(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE value")?,
            ),
            DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL => Self::FlashUpdateStatusTotal(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL value")?,
            ),
            DEVLINK_ATTR_SB_POOL_CELL_SIZE => Self::SbPoolCellSize(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_SB_POOL_CELL_SIZE value")?,
            ),
            DEVLINK_ATTR_FMSG => Self::Fmsg({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_FMSG")?
            }),
            DEVLINK_ATTR_FMSG_OBJ_NEST_START => Self::FmsgObjNestStart(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_FMSG_OBJ_NEST_START value")? != 0,
            ),
            DEVLINK_ATTR_FMSG_PAIR_NEST_START => Self::FmsgPairNestStart(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_FMSG_PAIR_NEST_START value")? != 0,
            ),
            DEVLINK_ATTR_FMSG_ARR_NEST_START => Self::FmsgArrNestStart(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_FMSG_ARR_NEST_START value")? != 0,
            ),
            DEVLINK_ATTR_FMSG_NEST_END => Self::FmsgNestEnd(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_FMSG_NEST_END value")? != 0,
            ),
            DEVLINK_ATTR_FMSG_OBJ_NAME => Self::FmsgObjName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_FMSG_OBJ_NAME value")?,
            ),
            DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE => Self::FmsgObjValueType(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE value")?,
            ),
            DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA => Self::FmsgObjValueData({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA")?
            }),
            DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS => Self::HealthReporterDumpTsNs(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS value")?,
            ),
            DEVLINK_ATTR_NETNS_FD => Self::NetnsFd(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_NETNS_FD value")?,
            ),
            DEVLINK_ATTR_NETNS_PID => Self::NetnsPid(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_NETNS_PID value")?,
            ),
            DEVLINK_ATTR_NETNS_ID => Self::NetnsId(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_NETNS_ID value")?,
            ),
            DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP => Self::HealthReporterAutoDump(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP value")?,
            ),
            DEVLINK_ATTR_TRAP_POLICER_ID => Self::TrapPolicerId(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_TRAP_POLICER_ID value")?,
            ),
            DEVLINK_ATTR_TRAP_POLICER_RATE => Self::TrapPolicerRate(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_TRAP_POLICER_RATE value")?,
            ),
            DEVLINK_ATTR_TRAP_POLICER_BURST => Self::TrapPolicerBurst(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_TRAP_POLICER_BURST value")?,
            ),
            DEVLINK_ATTR_PORT_FUNCTION => Self::PortFunction({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_PORT_FUNCTION")?
            }),
            DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER => Self::InfoBoardSerialNumber(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER value")?,
            ),
            DEVLINK_ATTR_PORT_LANES => Self::PortLanes(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_LANES value")?,
            ),
            DEVLINK_ATTR_PORT_SPLITTABLE => Self::PortSplittable(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_PORT_SPLITTABLE value")?,
            ),
            DEVLINK_ATTR_PORT_EXTERNAL => Self::PortExternal(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_PORT_EXTERNAL value")?,
            ),
            DEVLINK_ATTR_PORT_CONTROLLER_NUMBER => Self::PortControllerNo(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_CONTROLLER_NUMBER value")?,
            ),
            DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT => Self::FlashUpdateStatusTimeout(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT value")?,
            ),
            DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK => Self::FlashUpdateOverWriteMask(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK value")?,
            ),
            DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED => Self::ReloadActionPerformed(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED value")?,
            ),
            DEVLINK_ATTR_RELOAD_LIMITS => Self::ReloadLimits(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_RELOAD_LIMITS value")?,
            ),
            DEVLINK_ATTR_PORT_PCI_SF_NUMBER => Self::PortPciSfNo(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_PCI_SF_NUMBER value")?,
            ),
            DEVLINK_ATTR_RATE_TYPE => Self::RateType(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_RATE_TYPE value")?,
            ),
            DEVLINK_ATTR_RATE_TX_SHARE => Self::RateTxShare(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_RATE_TX_SHARE value")?,
            ),
            DEVLINK_ATTR_RATE_TX_MAX => Self::RateTxMax(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_RATE_TX_MAX value")?,
            ),
            DEVLINK_ATTR_RATE_NODE_NAME => Self::RateNodeName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_RATE_NODE_NAME value")?,
            ),
            DEVLINK_ATTR_RATE_PARENT_NODE_NAME => Self::RateParentNodeName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_RATE_PARENT_NODE_NAME value")?,
            ),
            DEVLINK_ATTR_PORT_SPLIT_COUNT => Self::PortSplitCount(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_SPLIT_COUNT value")?,
            ),
            DEVLINK_ATTR_PORT_SPLIT_GROUP => Self::PortSplitGroup(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_SPLIT_GROUP value")?,
            ),
            DEVLINK_ATTR_SB_INDEX => Self::SbIndex(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_SB_INDEX value")?,
            ),
            DEVLINK_ATTR_SB_SIZE => Self::SbSize(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_SB_SIZE value")?,
            ),
            DEVLINK_ATTR_SB_INGRESS_POOL_COUNT => Self::SbIngressPoolCount(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_SB_INGRESS_POOL_COUNT value")?,
            ),
            DEVLINK_ATTR_SB_EGRESS_POOL_COUNT => Self::SbEgressPoolCount(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_SB_EGRESS_POOL_COUNT value")?,
            ),
            DEVLINK_ATTR_SB_INGRESS_TC_COUNT => Self::SbIngressTcCount(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_SB_INGRESS_TC_COUNT value")?,
            ),
            DEVLINK_ATTR_SB_EGRESS_TC_COUNT => Self::SbEgressTcCount(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_SB_EGRESS_TC_COUNT value")?,
            ),
            DEVLINK_ATTR_SB_POOL_INDEX => Self::SbPoolIndex(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_SB_POOL_INDEX value")?,
            ),
            DEVLINK_ATTR_SB_POOL_TYPE => Self::SbPoolType(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_SB_POOL_TYPE value")?,
            ),
            DEVLINK_ATTR_SB_POOL_SIZE => Self::SbPoolSize(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_SB_POOL_SIZE value")?,
            ),
            DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE => Self::SbPoolThresholdType(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE value")?,
            ),
            DEVLINK_ATTR_SB_THRESHOLD => Self::SbPoolThreshold(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_SB_POOL_THRESHOLD value")?,
            ),
            DEVLINK_ATTR_SB_TC_INDEX => Self::SbTcIndex(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_SB_TC_INDEX value")?,
            ),
            DEVLINK_ATTR_SB_OCC_CUR => Self::SbOccCur(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_SB_OCC_CUR value")?,
            ),
            DEVLINK_ATTR_SB_OCC_MAX => Self::SbOccMax(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_SB_OCC_MAX value")?,
            ),
            DEVLINK_ATTR_ESWITCH_MODE => Self::EswitchMode(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_ESWITCH_MODE value")?,
            ),
            DEVLINK_ATTR_ESWITCH_INLINE_MODE => Self::EswitchInlineMode(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_ESWITCH_INLINE_MODE value")?,
            ),
            DEVLINK_ATTR_DPIPE_TABLES => Self::DpipeTables({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_TABLES")?
            }),
            DEVLINK_ATTR_DPIPE_TABLE => Self::DpipeTable({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_TABLE")?
            }),
            DEVLINK_ATTR_DPIPE_TABLE_NAME => Self::DpipeTableName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_TABLE_NAME value")?,
            ),
            DEVLINK_ATTR_DPIPE_TABLE_SIZE => Self::DpipeTableSize(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_TABLE_SIZE value")?,
            ),
            DEVLINK_ATTR_DPIPE_TABLE_MATCHES => Self::DpipeTableMatches({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_TABLE_MATCHES")?
            }),
            DEVLINK_ATTR_DPIPE_TABLE_ACTIONS => Self::DpipeTableActions({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_TABLE_ACTIONS")?
            }),
            DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED => Self::DpipeTableCountersEnabled(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED value")?,
            ),
            DEVLINK_ATTR_DPIPE_ENTRIES => Self::DpipeEntries({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_ENTRIES")?
            }),
            DEVLINK_ATTR_DPIPE_ENTRY => Self::DpipeEntry({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_ENTRY")?
            }),
            DEVLINK_ATTR_DPIPE_ENTRY_INDEX => Self::DpipeEntryIndex(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_ENTRY_INDEX value")?,
            ),
            DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES => Self::DpipeEntryMatchValues({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES")?
            }),
            DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES => Self::DpipeEntryActionValues({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES")?
            }),
            DEVLINK_ATTR_DPIPE_ENTRY_COUNTER => Self::DpipeEntryCounter(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_ENTRY_COUNTER value")?,
            ),
            DEVLINK_ATTR_DPIPE_MATCH_TYPE => Self::DpipeMatchType(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_MATCH_TYPE value")?,
            ),
            DEVLINK_ATTR_DPIPE_MATCH_VALUE => Self::DpipeMatchValue({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_MATCH_VALUE")?
            }),
            DEVLINK_ATTR_DPIPE_ACTION => Self::DpipeAction({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_ACTION")?
            }),
            DEVLINK_ATTR_DPIPE_ACTION_TYPE => Self::DpipeActionType(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_ACTION_TYPE value")?,
            ),
            DEVLINK_ATTR_DPIPE_ACTION_VALUE => Self::DpipeActionValue({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_DPIPE_TABLE_COUNTERS",
                    )?
            }),
            DEVLINK_ATTR_PORT_IBDEV_NAME => Self::PortIbdevName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_PORT_IBDEV_NAME value")?,
            ),
            DEVLINK_ATTR_DPIPE_MATCH => Self::DpipeMatch({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_MATCH")?
            }),
            DEVLINK_ATTR_DPIPE_VALUE => Self::DpipeValue(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_VALUE value")?,
            ),
            DEVLINK_ATTR_DPIPE_VALUE_MASK => Self::DpipeValueMask(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_VALUE_MASK value")?,
            ),
            DEVLINK_ATTR_DPIPE_VALUE_MAPPING => Self::DpipeValueMapping(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_VALUE_MAPPING value")?,
            ),
            DEVLINK_ATTR_DPIPE_HEADERS => Self::DpipeHeaders({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_HEADERS")?
            }),
            DEVLINK_ATTR_DPIPE_HEADER => Self::DpipeHader({
                NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_HEADER")?
            }),
            DEVLINK_ATTR_DPIPE_HEADER_NAME => Self::DpipeHeaderName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_HEADER_NAME value")?,
            ),
            DEVLINK_ATTR_DPIPE_HEADER_ID => Self::DpipeHeaderId(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_HEADER_ID value")?,
            ),
            DEVLINK_ATTR_DPIPE_HEADER_FIELDS => Self::DpipeHeaderFields({
                NlasIterator::new(payload)
                    .map(|nla| nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla)))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_HEADER_FIELDS")?
            }),
            DEVLINK_ATTR_DPIPE_HEADER_GLOBAL => Self::DpipeHeaderGlobal(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_HEADER_GLOBAL value")?,
            ),
            DEVLINK_ATTR_DPIPE_HEADER_INDEX => Self::DpipeHeaderIndex(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_HEADER_INDEX value")?,
            ),
            DEVLINK_ATTR_DPIPE_FIELD => Self::DpipeField({
                NlasIterator::new(payload)
                    .map(|nla| nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla)))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_DPIPE_FIELD")?
            }),
            DEVLINK_ATTR_DPIPE_FIELD_NAME => Self::DpipeFieldName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_FIELD_NAME value")?,
            ),
            DEVLINK_ATTR_DPIPE_FIELD_ID => Self::DpipeFieldId(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_FIELD_ID value")?,
            ),
            DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH => Self::DpipeFieldBitwidth(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH value")?,
            ),
            DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE => Self::DpipeFieldMappingType(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE value")?,
            ),
            DEVLINK_ATTR_ESWITCH_ENCAP_MODE => Self::EswitchEncapMode(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_ESWITCH_ENCAP_MODE value")?,
            ),
            DEVLINK_ATTR_RESOURCE_LIST => Self::ResourceList({
                NlasIterator::new(payload)
                    .map(|nla| nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla)))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_RESOURCE_LIST")?
            }),
            DEVLINK_ATTR_RESOURCE => Self::Resource({
                NlasIterator::new(payload)
                    .map(|nla| nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla)))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse DEVLINK_ATTR_RESOURCE")?
            }),
            DEVLINK_ATTR_RESOURCE_NAME => Self::ResoureceName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_NAME value")?,
            ),
            DEVLINK_ATTR_RESOURCE_ID => Self::ResourceId(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_ID value")?,
            ),
            DEVLINK_ATTR_RESOURCE_SIZE => Self::ResourceSize(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_SIZE value")?,
            ),
            DEVLINK_ATTR_RESOURCE_SIZE_NEW => Self::ResourceSizeNew(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_SIZE_NEW value")?,
            ),
            DEVLINK_ATTR_RESOURCE_SIZE_VALID => Self::ResourceSizeValid(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_SIZE_VALID value")?,
            ),
            DEVLINK_ATTR_RESOURCE_SIZE_MIN => Self::ResourceSizeMin(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_SIZE_MIN value")?,
            ),
            DEVLINK_ATTR_RESOURCE_SIZE_MAX => Self::ResourceSizeMax(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_SIZE_MAX value")?,
            ),
            DEVLINK_ATTR_RESOURCE_SIZE_GRAN => Self::ResourceSizeGran(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_SIZE_GRAN value")?,
            ),
            DEVLINK_ATTR_RESOURCE_UNIT => Self::ResourceUnit(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_UNIT value")?,
            ),
            DEVLINK_ATTR_RESOURCE_OCC => Self::ResourceOcc(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_RESOURCE_OCC value")?,
            ),
            DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID => Self::DpipeTableResourceId(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID value")?,
            ),
            DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS => Self::DpipeTableResourceUnit(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS value")?,
            ),
            DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER => Self::PortSplitCount(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER value")?,
            ),
            _ => {
                return Err(DecodeError::from(format!(
                    "Unknown NLA type: {}",
                    buf.kind()
                )))
            }
        })
    }
}
