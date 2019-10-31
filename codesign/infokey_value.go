package codesign

import "encoding/binary"

type InfoKeyValue struct {
	Key []byte
	Value []byte
}

func(v *InfoKeyValue)Length() int {
	return 4 + ExprDataLen(len(v.Key)) + ExprDataLen(len(v.Value))
}

func(v *InfoKeyValue)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprInfoKeyValue {
		return 0
	}
	key, n1 := ExprReadData(buffer[4:])
	val, n2 := ExprReadData(buffer[4+n1:])
	v.Key, v.Value = key, val
	return 4 + n1 + n2
}

func(v *InfoKeyValue)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprInfoKeyValue)
	n1 := ExprWriteData(buffer[4:], v.Key)
	n2 := ExprWriteData(buffer[4+n1:], v.Value)
	return 4 + n1 + n2
}

func(v *InfoKeyValue)GetBytes()[]byte {
	buffer := make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}