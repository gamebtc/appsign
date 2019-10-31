package mach

import (
	"encoding/binary"
	"log"
	"math"
)

type Entity interface {
	Load(buffer []byte) int
	WriteBytes(buffer []byte) int
	Length() int
	Type() int
}

type MachObjectFile struct {
	Header       *MachHeader
	LoadCommands []Entity
	DataOffset   int
	Data         []byte
}

func(m *MachObjectFile)Load(buffer []byte)int {
	m.Header = new(MachHeader)
	offset := m.Header.Load(buffer)

	for i := uint32(0); i < m.Header.NumberOfLoadCommands; i++ {
		command := NewCommand(buffer[offset:])
		commandLen := int(binary.LittleEndian.Uint32(buffer[offset+4:]))
		commandLen2 := command.Load(buffer[offset : offset+commandLen])
		if commandLen != commandLen2 {
			panic("error exec file")
			return 0
		}
		offset += commandLen
		m.LoadCommands = append(m.LoadCommands, command)
	}
	m.DataOffset = m.Header.Length() + int(m.Header.SizeOfLoadCommands)
	dataLength := len(buffer) - m.DataOffset
	m.Data = buffer[offset : offset+dataLength]
	return offset + dataLength
}

func(m *MachObjectFile) WriteBytes(buffer []byte)int {
	m.Header.WriteBytes(buffer)
	offset := m.Header.Length()
	for _, command := range m.LoadCommands {
		command.WriteBytes(buffer[offset:])
		offset += command.Length()
	}
	copy(buffer[offset:], m.Data)
	offset += len(m.Data)
	return offset
}

func(m *MachObjectFile) GetBytes()[]byte {
	buffer := make([]byte, m.Length())
	m.WriteBytes(buffer)
	return buffer
}

func(m *MachObjectFile) Length()int {
	length := m.Header.Length()
	for _, command := range m.LoadCommands {
		length += command.Length()
	}
	length += len(m.Data)
	return length
}

func(m *MachObjectFile)GetLoadCommand(commandType int) Entity {
	for _, item := range m.LoadCommands {
		if item.Type() == commandType {
			return item
		}
	}
	return nil
}

func(m *MachObjectFile)GetCodeSignatureBytes()[]byte {
	var sign []byte
	command := m.GetLoadCommand(LC_CodeSignature).(*CodeSignatureCommand)
	if command != nil {
		offset := int(command.DataOffset) - m.DataOffset
		sign = m.Data[offset : offset+int(command.DataSize)]
	}
	return sign
}

func IsMachObjectFile(buffer []byte)bool{
	return IsMachHeader(buffer)
}

const FatArchSize = 20
type FatArch struct {
	CpuType    uint32
	CpuSubType uint32
	Offset     uint32
	Size       uint32
	Align      uint32
}

func(f *FatArch)Length() int{
	return FatArchSize
}

func(f *FatArch)Load(buffer []byte) int{
	f.CpuType = binary.BigEndian.Uint32(buffer)
	f.CpuSubType = binary.BigEndian.Uint32(buffer[4:])
	f.Offset = binary.BigEndian.Uint32(buffer[8:])
	f.Size = binary.BigEndian.Uint32(buffer[12:])
	f.Align = 1 << binary.BigEndian.Uint32(buffer[16:])
	return FatArchSize
}

func(f *FatArch) WriteBytes(buffer []byte) int{
	binary.BigEndian.PutUint32(buffer, f.CpuType)
	binary.BigEndian.PutUint32(buffer[4:], f.CpuSubType)
	binary.BigEndian.PutUint32(buffer[8:], f.Offset)
	binary.BigEndian.PutUint32(buffer[12:], f.Size)
	binary.BigEndian.PutUint32(buffer[16:], uint32(math.Log2(float64(f.Align))))
	return FatArchSize
}

func(f *FatArch) GetBytes()[]byte {
	buffer := make([]byte, FatArchSize)
	f.WriteBytes(buffer)
	return buffer
}

const DefaultAlignment = 16384
type UniversalBinaryFile struct {
	Header        FatHeader
	fatArchs      []*FatArch
	machObjects   []*MachObjectFile
}

func(u *UniversalBinaryFile)MachObjects()[]*MachObjectFile {
	return u.machObjects
}

func(u *UniversalBinaryFile)Load(buffer []byte) {
	offset := u.Header.Load(buffer)
	count := int(u.Header.NumberOfArchitectures)
	machObjects := make([]*MachObjectFile, count)
	fatArchs := make([]*FatArch, count)
	for i := 0; i < count; i++ {
		arch := new(FatArch)
		offset += arch.Load(buffer[offset:])
		fatArchs[i] = arch
	}

	for i := 0; i < count; i++ {
		arch := fatArchs[i]
		machObject := new(MachObjectFile)
		machObject.Load(buffer[arch.Offset : arch.Offset+arch.Size])
		machObjects[i] = machObject
	}
	u.fatArchs, u.machObjects = fatArchs, machObjects
	log.Printf("UniversalBinaryFile:%v", count)
}

func(u *UniversalBinaryFile)Length( )int {
	length := FatHeaderSize + len(u.fatArchs)*FatArchSize
	for i := 0; i < len(u.fatArchs); i++ {
		fatArch := u.fatArchs[i]
		file := u.machObjects[i]
		align := int(fatArch.Align)
		if align == 0 {
			align = DefaultAlignment
		}
		padding := (align - (length % align)) % align
		length += padding
		length += file.Length()
	}
	return length
}

func(u *UniversalBinaryFile) WriteBytes(buffer []byte) int {
	u.Header.WriteBytes(buffer)
	offset := FatHeaderSize + len(u.fatArchs)*FatArchSize
	for i := 0; i < len(u.fatArchs); i++ {
		fatArch := u.fatArchs[i]
		file := u.machObjects[i]
		fileLen := file.Length()
		align := int(fatArch.Align)
		if align == 0 {
			align = DefaultAlignment
		}
		padding := (align - (offset % align)) % align
		offset += padding
		fatArch.Offset = uint32(offset)
		fatArch.Size = uint32(fileLen)

		fatArch.WriteBytes(buffer[FatHeaderSize+i*FatArchSize:])
		file.WriteBytes(buffer[offset:])
		offset += fileLen
	}
	return offset
}

func(u *UniversalBinaryFile)GetBytes( )[]byte {
	buffer := make([]byte, u.Length())
	u.WriteBytes(buffer)
	return buffer
}