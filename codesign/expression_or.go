package codesign

import "encoding/binary"

type ExpressionOr struct {
	Exp1 RequirementExpression
	Exp2 RequirementExpression
}

func(v *ExpressionOr)Length() int {
	return 4 + v.Exp1.Length() + v.Exp2.Length()
}

func(v *ExpressionOr)Load(buffer []byte)int {
	if binary.BigEndian.Uint32(buffer) != ExprOr {
		return 0
	}
	key, n1 := ReadExpression(buffer[4:])
	val, n2 := ReadExpression(buffer[4+n1:])
	v.Exp1, v.Exp2 = key, val
	return 4 + n1 + n2
}

func(v *ExpressionOr)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, ExprOr)
	n1 := v.Exp1.WriteBytes(buffer[4:])
	n2 := v.Exp2.WriteBytes(buffer[4+n1:])
	return 4 + n1 + n2
}
