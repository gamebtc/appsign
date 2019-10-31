package codesign

import "encoding/binary"

type InfoKeyField struct {
	Key   []byte
	Match MatchSuffix
}

func(v *InfoKeyField)Length() int {
	return 4 + ExprDataLen(len(v.Key)) + v.Match.Length()
}

func(v *InfoKeyField)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprInfoKeyField {
		return 0
	}
	key, n1 := ExprReadData(buffer[4:])
	v.Key = key
	n2 := v.Match.Load(buffer[4+n1:])
	return 4 + n1 + n2
}

func(v *InfoKeyField)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprInfoKeyField)
	n1 := ExprWriteData(buffer[4:], v.Key)
	n2 := v.Match.WriteBytes(buffer[4+n1:])
	return 4 + n1 + n2
}

func(v *InfoKeyField)GetBytes()[]byte {
	buffer := make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}