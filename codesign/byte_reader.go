package codesign

import (
	"encoding/binary"
	"io"
)

func ReadNullTerminatedAnsiString(buffer []byte)string {
	for i := 0; i < len(buffer); i++ {
		if buffer[i] == 0 {
			return string(buffer[:i])
		}
	}
	return ""
}

func LittleEndianUint32(reader io.Reader) uint32 {
	buf := [4]byte{}
	n, _ := reader.Read(buf[:])
	return binary.LittleEndian.Uint32(buf[:n])
}

func LittleEndianUint64(reader io.Reader) uint64 {
	buf := [8]byte{}
	n, _ := reader.Read(buf[:])
	return binary.LittleEndian.Uint64(buf[:n])
}

func BigEndianUint32(reader io.Reader) uint32 {
	buf := [4]byte{}
	n, _ := reader.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:n])
}

func BigEndianUint64(reader io.Reader) uint64 {
	buf := [8]byte{}
	n, _ := reader.Read(buf[:])
	return binary.BigEndian.Uint64(buf[:n])
}