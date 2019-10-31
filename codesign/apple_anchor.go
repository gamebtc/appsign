package codesign

import "encoding/binary"

type AppleAnchor struct {
}

func(v *AppleAnchor)Length() int{
	return 4
}

func(v *AppleAnchor)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprAppleAnchor {
		return 0
	}
	return 4
}

func(v *AppleAnchor)WriteBytes(buffer []byte)int{
	binary.BigEndian.PutUint32(buffer, ExprAppleAnchor)
	return 4
}

func(v *AppleAnchor)GetBytes()[]byte{
	buffer:= make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}


type AppleGenericAnchor struct {
}

func(v *AppleGenericAnchor)Length() int{
	return 4
}

func(v *AppleGenericAnchor)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprAppleGenericAnchor {
		return 0
	}
	return 4
}

func(v *AppleGenericAnchor)WriteBytes(buffer []byte)int{
	binary.BigEndian.PutUint32(buffer, ExprAppleGenericAnchor)
	return 4
}

func(v *AppleGenericAnchor)GetBytes()[]byte{
	buffer:= make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}