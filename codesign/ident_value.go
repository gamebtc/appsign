package codesign

import "encoding/binary"

type IdentValue struct {
	Value []byte
}

func(v *IdentValue)Length() int {
	return 4 + ExprDataLen(len(v.Value))
}

func(v *IdentValue)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprIdent {
		return 0
	}
	data, n := ExprReadData(buffer[4:])
	v.Value = data
	return 4 + n
}

func(v *IdentValue)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprIdent)
	n := ExprWriteData(buffer[4:], v.Value)
	return 4 + n
}

func(v *IdentValue)GetBytes()[]byte {
	buffer := make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}
