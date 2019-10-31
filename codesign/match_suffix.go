package codesign

import "encoding/binary"

const(
	MatchExists = 0
	MatchEqual = 1
	MatchContains = 2
	MatchBeginsWith = 3
	MatchEndsWith = 4
	MatchLessThan = 5
	MatchGreaterThan = 6
	MatchLessThanOrEqual = 7
	MatchGreaterThanOrEqual = 8
)

type MatchSuffix struct {
	MatchOperation uint32
	MatchValue     []byte
}

func(v *MatchSuffix)Length() int {
	if v.MatchOperation == MatchExists{
		return 4
	}
	return  4 + ExprDataLen(len(v.MatchValue))
}

func(v *MatchSuffix)Load(buffer []byte)int {
	v.MatchOperation = binary.BigEndian.Uint32(buffer)
	if v.MatchOperation == MatchExists {
		return 4
	}
	hash, n := ExprReadData(buffer[4:])
	v.MatchValue = hash
	return 4 + n
}

func(v *MatchSuffix)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, v.MatchOperation)
	if v.MatchOperation == MatchExists {
		return 4
	}
	n := ExprWriteData(buffer[4:], v.MatchValue)
	return   4 + n
}

func(v *MatchSuffix)GetBytes()[]byte {
	buffer := make([]byte, v.Length())
	v.WriteBytes(buffer)
	return buffer
}