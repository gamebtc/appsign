package codesign

import "encoding/binary"

type CodeDirectoryHash struct {
	Hash []byte
}

func(v *CodeDirectoryHash)Length() int {
	return 4 + ExprDataLen(len(v.Hash))
}

func(v *CodeDirectoryHash)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprCodeDirectoryHash {
		return 0
	}
	data, n := ExprReadData(buffer[4:])
	v.Hash = data
	return 4 + n
}

func(v *CodeDirectoryHash)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprCodeDirectoryHash)
	n := ExprWriteData(buffer[4:], v.Hash)
	return 4 + n
}

func(v *CodeDirectoryHash)GetBytes()[]byte {
	buffer := make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}