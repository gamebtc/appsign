package codesign

import "encoding/binary"

type ExpressionNot struct {
	Exp1 RequirementExpression
}

func(v *ExpressionNot)Length() int {
	return 4 + v.Exp1.Length()
}

func(v *ExpressionNot)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprNot{
		return 0
	}
	key, n1 := ReadExpression(buffer[4:])
	v.Exp1 = key
	return 4 + n1
}

func(v *ExpressionNot)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprNot)
	n1 := v.Exp1.WriteBytes(buffer[4:])
	return 4 + n1
}

func(v *ExpressionNot)GetBytes()[]byte {
	buffer := make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}