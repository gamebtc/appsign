package mach

import (
	"encoding/binary"
)

const (
	FileTypeObject = 0x00000001              // MH_OBJECT
	FileTypeExecutable = 0x00000002          // MH_EXECUTE
	FileTypeFixedVMLibrary = 0x00000003      // MH_FVMLIB
	FileTypeCoreFile = 0x00000004            // MH_CORE
	FileTypePreloadedExecutable = 0x00000005 // MH_PRELOAD
	FileTypeDynamicLibrary = 0x00000006      // MH_DYLIB
	FileTypeDynamicLinkEditor = 0x0000007    // MH_DYLINKER
	FileTypeBundle = 0x00000008              // MH_BUNDLE
	FileTypeDynamicLibraryStub = 0x00000009  // MH_DYLIB_STUB
	FileTypeDebugSymbols = 0x0000000A 		 // MH_DSYM
	FileTypeKExtBundle = 0x0000000B          // MH_KEXT_BUNDLE
)

const(
	CpuTypeVax = 1
	CpuTypeRomp = 2
	CpuTypeNS32032 = 4
	CpuTypeNS32332 = 5
	CpuTypeMC680x0 = 6
	CpuTypeI386 = 7
	CpuTypeMIPS = 8
	CpuTypeNS32532 = 9
	CpuTypeHPPA = 11
	CpuTypeArm = 12
	CpuTypeMC88000 = 13
	CpuTypeSparc = 14
	CpuTypeI860BigEndian = 15
	CpuTypeI860LittleEndian = 16
	CpuTypeRS6000 = 17
	CpuTypeMC98000 = 18
	CpuTypePowerPC = 18
	CpuTypeVeo = 255
	CpuTypeCPU_TYPE_X86_64 = 0x01000007
	CpuTypeArm64 = 0x0100000C
	CpuTypePowerPC64 = 0x01000012
)

const (
	Length32Bit = 28
	Length64Bit = 32
	MachO32BitLittleEndianSignature = 0xcefaedfe
	MachO64BitLittleEndianSignature = 0xcffaedfe
	MachO32BitBigEndianSignature = 0xfeedface
	MachO64BitBigEndianSignature = 0xfeedfacf
	CpuArchitecture64BitFlag = 0x01000000 // CPU_ARCH_ABI64
)

const(
	MH_NoUndefinedReferences = 0x00000001 // MH_NOUNDEFS
	MH_IncrementalLink = 0x00000002       // MH_INCRLINK
	MH_DynamicLink = 0x00000004           // MH_DYLDLINK
	MH_BindAtLoad = 0x00000008            // MH_BINDATLOAD
	MH_Prebound = 0x00000010              // MH_PREBOUND
	MH_SplitSegments = 0x00000020         // MH_SPLIT_SEGS
	MH_LazyInit = 0x00000040              // MH_LAZY_INIT
	MH_TwoLevelNamespace = 0x00000080     // MH_TWOLEVEL
	MH_ForceFlatNamespace = 0x00000100    // MH_FORCE_FLAT
	MH_NoMultipleDefinitions = 0x00000200 // MH_NOMULTIDEFS
	MH_NoFixPrebinding = 0x00000400       // MH_NOFIXPREBINDING
	MH_Prebindable = 0x00000800           // MH_PREBINDABLE
	MH_AllModsBound = 0x00001000          // MH_ALLMODSBOUND
	MH_SubsectionsViaSymbols = 0x00002000 // MH_SUBSECTIONS_VIA_SYMBOLS
	MH_Canonical = 0x00004000             // MH_CANONICAL
	MH_WeakDefines = 0x00008000           // MH_WEAK_DEFINES
	MH_BindsToWeak = 0x00010000           // MH_BINDS_TO_WEAK
	MH_AllowStackExecution = 0x00020000   // MH_ALLOW_STACK_EXECUTION
	MH_LoadAtRandomAddress = 0x00200000   // MH_PIE
)

const(
	LC_Segment = 0x00000001                // LC_SEGMENT
	LC_SymbolTable = 0x00000002            // LC_SYMTAB
	LC_Thread = 0x00000004                 // LC_THREAD
	LC_UnixThread = 0x00000005             // LC_UNIXTHREAD
	LC_LoadFixedVMLibrary = 0x00000006     // LC_LOADFVMLIB
	LC_DynamicSymbolTable = 0x0000000B     // LC_DYSYMTAB
	LC_LoadDynamicLibrary = 0x0000000C     // LC_LOAD_DYLIB
	LC_IDDynamicLibrary = 0x0000000D       // LC_ID_DYLIB
	LC_LoadDynamicLinker = 0x0000000E      // LC_LOAD_DYLINKER
	LC_IDDynamicLinker = 0x0000000F        // LC_ID_DYLINKER
	LC_PreboundDynamicLibrary = 0x00000010 // LC_PREBOUND_DYLIB
	LC_Routines = 0x00000011               // LC_ROUTINES
	LC_SubFramework = 0x00000012           // LC_SUB_FRAMEWORK
	LC_SubUmbrella = 0x00000013            // LC_SUB_UMBRELLA
	LC_SubClient = 0x00000014              // LC_SUB_CLIENT
	LC_SubLibrary = 0x00000015             // LC_SUB_LIBRARY
	LC_TwoLevelHints = 0x00000016          // LC_TWOLEVEL_HINTS
	LC_Segment64 = 0x00000019              // LC_SEGMENT_64
	LC_Routines64 = 0x0000001A             // LC_ROUTINES_64
	LC_UUID = 0x0000001B                   // LC_UUID
	LC_CodeSignature = 0x0000001D          // LC_CODE_SIGNATURE
	LC_FunctionStarts = 0x00000026         // LC_FUNCTION_STARTS
	LC_EncryptionInfo = 0x00000021         // LC_ENCRYPTION_INFO
	LC_VersionMinIPhoneOS = 0x00000025     // LC_VERSION_MIN_IPHONEOS
	LC_DataInCode = 0x00000029             // LC_DATA_IN_CODE
	LC_SourceVersion = 0x0000002A          // LC_SOURCE_VERSION
	LC_EncryptionInfo64 = 0x0000002C       // LC_ENCRYPTION_INFO_64
	LC_LoadWeakDynamicLibrary = 0x80000018 // LC_LOAD_WEAK_DYLIB
	LC_DynamicLinkerInfoOnly = 0x80000022  // LC_DYLD_INFO_ONLY
	LC_MainEntryPoint = 0x80000028         // LC_MAIN
)

type MachHeader struct {
	Is64BitHeader        bool
	CpuType              uint32
	CpuSubType           uint32
	FileType             uint32
	NumberOfLoadCommands uint32
	SizeOfLoadCommands   uint32
	Flags                uint32
	Reserved             uint32  // 64-Bit only
}

func (h *MachHeader)Load(buffer []byte) int {
	magic := binary.BigEndian.Uint32(buffer)
	if magic == MachO64BitLittleEndianSignature {
		h.Is64BitHeader = true
	} else if magic == MachO32BitLittleEndianSignature {
		h.Is64BitHeader = false
	} else {
		return 0
	}
	h.CpuType = binary.LittleEndian.Uint32(buffer[4:])
	h.CpuSubType = binary.LittleEndian.Uint32(buffer[8:])
	h.FileType = binary.LittleEndian.Uint32(buffer[12:])
	h.NumberOfLoadCommands = binary.LittleEndian.Uint32(buffer[16:])
	h.SizeOfLoadCommands = binary.LittleEndian.Uint32(buffer[20:])
	h.Flags = binary.LittleEndian.Uint32(buffer[24:])
	if h.Is64BitHeader {
		h.Reserved = binary.LittleEndian.Uint32(buffer[28:])
		return Length64Bit
	}
	return Length32Bit
}

func(h *MachHeader) WriteBytes(buffer []byte) int{
	if h.Is64BitHeader {
		binary.BigEndian.PutUint32(buffer, MachO64BitLittleEndianSignature)
	} else {
		binary.BigEndian.PutUint32(buffer, MachO32BitLittleEndianSignature)
	}
	binary.LittleEndian.PutUint32(buffer[4:], h.CpuType)
	binary.LittleEndian.PutUint32(buffer[8:], h.CpuSubType)
	binary.LittleEndian.PutUint32(buffer[12:], h.FileType)
	binary.LittleEndian.PutUint32(buffer[16:], h.NumberOfLoadCommands)
	binary.LittleEndian.PutUint32(buffer[20:], h.SizeOfLoadCommands)
	binary.LittleEndian.PutUint32(buffer[24:], h.Flags)
	if h.Is64BitHeader {
		binary.LittleEndian.PutUint32(buffer[28:], h.Reserved)
	}
	return h.Length()
}

func(h *MachHeader) GetBytes()[]byte {
	buffer := make([]byte, h.Length())
	h.WriteBytes(buffer)
	return buffer
}

func(h *MachHeader) Length()int {
	if h.Is64BitHeader {
		return Length64Bit
	}
	return Length32Bit
}

func IsMachHeader(buffer []byte) bool {
	magic := binary.BigEndian.Uint32(buffer)
	return magic == MachO32BitLittleEndianSignature || magic == MachO64BitLittleEndianSignature
}

const FatHeaderSize = 8
const FatSignature = 0xcafebabe
type FatHeader struct {
	//FatSignature          uint32
	NumberOfArchitectures uint32
}

func (f *FatHeader)Load(buffer []byte) int {
	f.NumberOfArchitectures = binary.BigEndian.Uint32(buffer[4:])
	return FatHeaderSize
}

func(f *FatHeader) WriteBytes(buffer []byte)[]byte {
	binary.BigEndian.PutUint32(buffer, FatSignature)
	binary.BigEndian.PutUint32(buffer[4:], f.NumberOfArchitectures)
	return buffer
}

func(f *FatHeader) GetBytes()[]byte {
	buffer := make([]byte, FatHeaderSize)
	return f.WriteBytes(buffer)
}

func(f *FatHeader) Length()int {
	return  FatHeaderSize
}

func IsFatHeader(buffer []byte)bool {
	magic := binary.BigEndian.Uint32(buffer)
	return magic == FatSignature
}

func IsUniversalBinaryFile(buffer []byte)bool{
	return IsFatHeader(buffer)
}