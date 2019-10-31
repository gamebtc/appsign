package mach

import (
	"encoding/binary"
)

const Section32Size = 68
type Section32 struct {
	SectionName               [16]byte
	SegmentName               [16]byte
	Address                   uint32
	Size                      uint32
	Offset                    uint32
	Align                     uint32
	RelocationOffset          uint32 // reloff
	NumberOfRelocationOffsets uint32
	Flags                     uint32
	Reserved1                 uint32
	Reserved2                 uint32
}

func(s *Section32)Load(buffer []byte) int{
	copy(s.SectionName[:], buffer[:16])
	copy(s.SegmentName[:], buffer[16:32])
	s.Address = binary.LittleEndian.Uint32(buffer[32:])
	s.Size = binary.LittleEndian.Uint32(buffer[36:])
	s.Offset = binary.LittleEndian.Uint32(buffer[40:])
	s.Align = binary.LittleEndian.Uint32(buffer[44:])
	s.RelocationOffset = binary.LittleEndian.Uint32(buffer[48:])
	s.NumberOfRelocationOffsets = binary.LittleEndian.Uint32(buffer[52:])
	s.Flags = binary.LittleEndian.Uint32(buffer[56:])
	s.Reserved1 = binary.LittleEndian.Uint32(buffer[60:])
	s.Reserved2 = binary.LittleEndian.Uint32(buffer[64:])
	return Section32Size
}

func(s *Section32) GetBytes()[]byte {
	buffer := make([]byte, Section32Size)
	copy(buffer[:16], s.SectionName[:])
	copy(buffer[16:32], s.SegmentName[:])
	binary.LittleEndian.PutUint32(buffer[32:], s.Address)
	binary.LittleEndian.PutUint32(buffer[36:], s.Size)
	binary.LittleEndian.PutUint32(buffer[40:], s.Offset)
	binary.LittleEndian.PutUint32(buffer[44:], s.Align)
	binary.LittleEndian.PutUint32(buffer[48:], s.RelocationOffset)
	binary.LittleEndian.PutUint32(buffer[52:], s.NumberOfRelocationOffsets)
	binary.LittleEndian.PutUint32(buffer[56:], s.Flags)
	binary.LittleEndian.PutUint32(buffer[60:], s.Reserved1)
	binary.LittleEndian.PutUint32(buffer[64:], s.Reserved2)
	return buffer
}

const Section64Size = 80
type Section64 struct {
	SectionName               [16]byte
	SegmentName               [16]byte
	Address                   uint64
	Size                      uint64
	Offset                    uint32
	Align                     uint32
	RelocationOffset          uint32 // reloff
	NumberOfRelocationOffsets uint32
	Flags                     uint32
	Reserved1                 uint32
	Reserved2                 uint32
	Reserved3                 uint32
}

func(s *Section64)Load(buffer []byte) int {
	copy(s.SectionName[:], buffer[:16])
	copy(s.SegmentName[:], buffer[16:32])
	s.Address = binary.LittleEndian.Uint64(buffer[32:])
	s.Size = binary.LittleEndian.Uint64(buffer[40:])
	s.Offset = binary.LittleEndian.Uint32(buffer[48:])
	s.Align = binary.LittleEndian.Uint32(buffer[52:])
	s.RelocationOffset = binary.LittleEndian.Uint32(buffer[56:])
	s.NumberOfRelocationOffsets = binary.LittleEndian.Uint32(buffer[60:])
	s.Flags = binary.LittleEndian.Uint32(buffer[64:])
	s.Reserved1 = binary.LittleEndian.Uint32(buffer[68:])
	s.Reserved2 = binary.LittleEndian.Uint32(buffer[72:])
	s.Reserved3 = binary.LittleEndian.Uint32(buffer[76:])
	return Section64Size
}

func(s *Section64) GetBytes()[]byte {
	buffer := make([]byte, Section64Size)
	copy(buffer[:16], s.SectionName[:])
	copy(buffer[16:32], s.SegmentName[:])
	binary.LittleEndian.PutUint64(buffer[32:], s.Address)
	binary.LittleEndian.PutUint64(buffer[40:], s.Size)
	binary.LittleEndian.PutUint32(buffer[48:], s.Offset)
	binary.LittleEndian.PutUint32(buffer[52:], s.Align)
	binary.LittleEndian.PutUint32(buffer[56:], s.RelocationOffset)
	binary.LittleEndian.PutUint32(buffer[60:], s.NumberOfRelocationOffsets)
	binary.LittleEndian.PutUint32(buffer[64:], s.Flags)
	binary.LittleEndian.PutUint32(buffer[68:], s.Reserved1)
	binary.LittleEndian.PutUint32(buffer[72:], s.Reserved2)
	binary.LittleEndian.PutUint32(buffer[76:], s.Reserved3)
	return buffer
}

type LoadCommand struct {
	commandType uint32
	CommandSize uint32
	Data        []byte
}

func(l *LoadCommand)Load(buffer []byte) int {
	l.commandType = binary.LittleEndian.Uint32(buffer)
	l.CommandSize = binary.LittleEndian.Uint32(buffer[4:])
	l.Data = make([]byte, l.CommandSize-8)
	copy(l.Data, buffer[8:])
	return int(l.CommandSize)
}

func(l *LoadCommand) WriteBytes(buffer []byte)int {
	binary.LittleEndian.PutUint32(buffer, l.commandType)
	binary.LittleEndian.PutUint32(buffer[4:], l.CommandSize)
	copy(buffer[8:], l.Data)
	return 8 + len(l.Data)
}

func(l *LoadCommand) GetBytes()[]byte {
	buffer := make([]byte, 8+len(l.Data))
	l.WriteBytes(buffer)
	return buffer
}

func(l *LoadCommand) Length()int {
	return int(l.CommandSize)
}

func(l *LoadCommand) Type()int {
	return int(l.commandType)
}

const SegmentCommand32Size = 56
type SegmentCommand32 struct {
	// Type uint32
	CommandSize uint32
	SegmentName [16]byte // segname, 16 bytes
	VMAddress   uint32
	VMSize      uint32
	FileOffset  uint32
	FileSize    uint32 // The number of bytes occupied by this segment on disk
	MaxProt     uint32
	InitProt    uint32
	//NumberOfSections uint32 // nsects
	Flags    uint32
	Sections []*Section32
}

func(s *SegmentCommand32)Load(buffer []byte) int {
	//s.Type = binary.LittleEndian.Uint32(buffer)
	s.CommandSize = binary.LittleEndian.Uint32(buffer[4:])
	copy(s.SegmentName[:], buffer[8:24])
	s.VMAddress = binary.LittleEndian.Uint32(buffer[24:])
	s.VMSize = binary.LittleEndian.Uint32(buffer[28:])
	s.FileOffset = binary.LittleEndian.Uint32(buffer[32:])
	s.FileSize = binary.LittleEndian.Uint32(buffer[36:])
	s.MaxProt = binary.LittleEndian.Uint32(buffer[40:])
	s.InitProt = binary.LittleEndian.Uint32(buffer[44:])
	n := int(binary.LittleEndian.Uint32(buffer[48:]))
	//s.NumberOfSections = uint32(n)
	s.Flags = binary.LittleEndian.Uint32(buffer[52:])
	for i := 0; i < n; i++ {
		se := &Section32{}
		se.Load(buffer[SegmentCommand32Size+i*Section32Size:])
		s.Sections = append(s.Sections, se)
	}
	return SegmentCommand32Size + n*Section32Size
}

func(s *SegmentCommand32) WriteBytes(buffer []byte)int {
	n := len(s.Sections)
	binary.LittleEndian.PutUint32(buffer, LC_Segment)
	binary.LittleEndian.PutUint32(buffer[4:], s.CommandSize)
	copy(buffer[8:24], s.SegmentName[:])
	binary.LittleEndian.PutUint32(buffer[24:], s.VMAddress)
	binary.LittleEndian.PutUint32(buffer[28:], s.VMSize)
	binary.LittleEndian.PutUint32(buffer[32:], s.FileOffset)
	binary.LittleEndian.PutUint32(buffer[36:], s.FileSize)
	binary.LittleEndian.PutUint32(buffer[40:], s.MaxProt)
	binary.LittleEndian.PutUint32(buffer[44:], s.InitProt)
	binary.LittleEndian.PutUint32(buffer[48:], uint32(n))
	binary.LittleEndian.PutUint32(buffer[52:], s.Flags)
	for i := 0; i < n; i++ {
		subBuffer := s.Sections[i].GetBytes()
		copy(buffer[SegmentCommand32Size+i*Section32Size:], subBuffer)
	}
	return s.Length()
}

func(s *SegmentCommand32) GetBytes()[]byte {
	buffer := make([]byte, s.Length())
	s.WriteBytes(buffer)
	return buffer
}

func(s *SegmentCommand32) Length() int {
	return SegmentCommand32Size + len(s.Sections)*Section32Size
}

func(s *SegmentCommand32) Type()int {
	return LC_Segment
}

const SegmentCommand64Size = 72
type SegmentCommand64 struct {
	//Type uint32
	CommandSize uint32
	SegmentName [16]byte // segname, 16 bytes
	VMAddress   uint64
	VMSize      uint64
	FileOffset  uint64
	FileSize    uint64 // The number of bytes occupied by this segment on disk
	MaxProt     uint32
	InitProt    uint32
	//NumberOfSections uint32 // nsects
	Flags     uint32
	Reserved1 uint32
	Reserved2 uint32
	Sections  []*Section64
}

func(s *SegmentCommand64)Load(buffer []byte) int {
	//s.Type = binary.LittleEndian.Uint32(buffer)
	s.CommandSize = binary.LittleEndian.Uint32(buffer[4:])
	copy(s.SegmentName[:], buffer[8:24])
	s.VMAddress = binary.LittleEndian.Uint64(buffer[24:])
	s.VMSize = binary.LittleEndian.Uint64(buffer[32:])
	s.FileOffset = binary.LittleEndian.Uint64(buffer[40:])
	s.FileSize = binary.LittleEndian.Uint64(buffer[48:])
	s.MaxProt = binary.LittleEndian.Uint32(buffer[56:])
	s.InitProt = binary.LittleEndian.Uint32(buffer[60:])
	n := int(binary.LittleEndian.Uint32(buffer[64:]))
	//s.NumberOfSections = uint32(n)
	s.Flags = binary.LittleEndian.Uint32(buffer[68:])
	for i := 0; i < n; i++ {
		se := &Section64{}
		se.Load(buffer[SegmentCommand64Size+i*Section64Size:])
		s.Sections = append(s.Sections, se)
	}
	return SegmentCommand64Size + n*Section64Size
}

func(s *SegmentCommand64) WriteBytes(buffer []byte)int {
	n := len(s.Sections)
	binary.LittleEndian.PutUint32(buffer, LC_Segment64)
	binary.LittleEndian.PutUint32(buffer[4:], s.CommandSize)
	copy(buffer[8:24], s.SegmentName[:])
	binary.LittleEndian.PutUint64(buffer[24:], s.VMAddress)
	binary.LittleEndian.PutUint64(buffer[32:], s.VMSize)
	binary.LittleEndian.PutUint64(buffer[40:], s.FileOffset)
	binary.LittleEndian.PutUint64(buffer[48:], s.FileSize)
	binary.LittleEndian.PutUint32(buffer[56:], s.MaxProt)
	binary.LittleEndian.PutUint32(buffer[60:], s.InitProt)
	binary.LittleEndian.PutUint32(buffer[64:], uint32(n))
	binary.LittleEndian.PutUint32(buffer[68:], s.Flags)
	for i := 0; i < n; i++ {
		subBuffer := s.Sections[i].GetBytes()
		copy(buffer[SegmentCommand64Size+i*Section64Size:], subBuffer)
	}
	return s.Length()
}

func(s *SegmentCommand64) GetBytes()[]byte {
	buffer := make([]byte, s.Length())
	s.WriteBytes(buffer)
	return buffer
}

func(s *SegmentCommand64) Length() int {
	return SegmentCommand64Size + len(s.Sections)*Section64Size
}

func(s *SegmentCommand64) Type() int {
	return LC_Segment64
}

const CodeSignatureCommandSize = 16
type CodeSignatureCommand struct {
	//Type uint32
	//CommandSize uint32
	DataOffset  uint32
	DataSize    uint32
}

func(c *CodeSignatureCommand)Load(buffer []byte) int {
	//c.Type = binary.LittleEndian.Uint32(buffer)
	//c.CommandSize = binary.LittleEndian.Uint32(buffer[4:])
	c.DataOffset = binary.LittleEndian.Uint32(buffer[8:])
	c.DataSize = binary.LittleEndian.Uint32(buffer[12:])
	return CodeSignatureCommandSize
}

func(c *CodeSignatureCommand) WriteBytes(buffer []byte)int {
	binary.LittleEndian.PutUint32(buffer, LC_CodeSignature)
	binary.LittleEndian.PutUint32(buffer[4:], CodeSignatureCommandSize)
	binary.LittleEndian.PutUint32(buffer[8:], c.DataOffset)
	binary.LittleEndian.PutUint32(buffer[12:], c.DataSize)
	return c.Length()
}

func(c *CodeSignatureCommand) GetBytes()[]byte {
	buffer := make([]byte, CodeSignatureCommandSize)
	c.WriteBytes(buffer)
	return buffer
}

func(c *CodeSignatureCommand) Length()int {
	return CodeSignatureCommandSize
}

func(c *CodeSignatureCommand) Type()int {
	return LC_CodeSignature
}

func NewCommand(buffer []byte) Entity {
	commandType := binary.LittleEndian.Uint32(buffer)
	//commandLen := binary.LittleEndian.Uint32(buffer[4:])
	var comm Entity
	switch commandType {
	case LC_Segment:
		comm = new(SegmentCommand32)
	case LC_Segment64:
		comm = new(SegmentCommand64)
	case LC_CodeSignature:
		comm = new(CodeSignatureCommand)
	default:
		comm = new(LoadCommand)
	}
	//comm.Load(buffer[:commandLen])
	return comm
}

var LinkEditSegmentName = []byte{'_','_','L','I','N','K','E','D','I','T', 0}
func isLinkEditSegmentName(name [16]byte )bool {
	for i, v := range LinkEditSegmentName {
		if name[i] != v {
			return false
		}
	}
	return true
}

func FindLinkEditSegment(loadCommands[]Entity) Entity {
     for _,loadCommand :=range loadCommands{
		 switch loadCommand:=loadCommand.(type) {
		 case *SegmentCommand32:
		 	if isLinkEditSegmentName(loadCommand.SegmentName){
		 		return loadCommand
			}
		 case *SegmentCommand64:
			 if isLinkEditSegmentName(loadCommand.SegmentName){
				 return loadCommand
			 }
		 }
	 }
     return nil
}

func SegmentSetEndOffset(command Entity, endOffset uint32) {
	switch segment := command.(type) {
	case *SegmentCommand32:
		segment.FileSize = endOffset - segment.FileOffset
	case *SegmentCommand64:
		segment.FileSize = uint64(endOffset) - segment.FileOffset
	}
}