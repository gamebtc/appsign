package codesign

import "encoding/binary"

type BooleanFalse struct {
}

func(v *BooleanFalse)Length() int{
	return 4
}

func(v *BooleanFalse)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprFalse {
		return 0
	}
	return v.Length()
}

func(v *BooleanFalse)WriteBytes(buffer []byte)int{
	binary.BigEndian.PutUint32(buffer, ExprFalse)
	return v.Length()
}

func(v *BooleanFalse)GetBytes()[]byte{
	buffer:= make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}

type BooleanTrue struct {
}

func(v *BooleanTrue)Length() int{
	return 4
}

func(v *BooleanTrue)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprTrue {
		return 0
	}
	return v.Length()
}

func(v *BooleanTrue)WriteBytes(buffer []byte)int{
	binary.BigEndian.PutUint32(buffer, ExprTrue)
	return v.Length()
}

func(v *BooleanTrue)GetBytes()[]byte{
	buffer:= make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}