package codesign

import "encoding/binary"

type ExpressionAnd struct {
	Exp1 RequirementExpression
	Exp2 RequirementExpression
}

func(v *ExpressionAnd)Length() int {
	return 4 + v.Exp1.Length() + v.Exp2.Length()
}

func(v *ExpressionAnd)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprAnd {
		return 0
	}
	key, n1 := ReadExpression(buffer[4:])
	val, n2 := ReadExpression(buffer[4+n1:])
	v.Exp1, v.Exp2 = key, val
	return 4 + n1 + n2
}

func(v *ExpressionAnd)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprAnd)
	n1 := v.Exp1.WriteBytes(buffer[4:])
	n2 := v.Exp2.WriteBytes(buffer[4+n1:])
	return 4 + n1 + n2
}

func(v *ExpressionAnd)GetBytes()[]byte{
	buffer:= make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}