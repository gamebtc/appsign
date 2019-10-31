package codesign

import "encoding/binary"

type AnchorHash struct {
	Slot uint32
	Hash []byte
}

func(v *AnchorHash)Length() int {
	return 4 + 4 + ExprDataLen(len(v.Hash))
}

func(v *AnchorHash)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprAnchorHash {
		return 0
	}
	v.Slot = binary.BigEndian.Uint32(buffer[4:])
	hash, n := ExprReadData(buffer[8:])
	v.Hash = hash
	return 4 + 4 + n
}

func(v *AnchorHash)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprAnchorHash)
	binary.BigEndian.PutUint32(buffer[4:], v.Slot)
	n := ExprWriteData(buffer[8:], v.Hash)
	return 4 + 4 + n
}

func(v *AnchorHash)GetBytes()[]byte{
	buffer:= make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}