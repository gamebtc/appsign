package codesign

import "encoding/binary"

const(
	HostRequirementType = 0x00000001       // kSecHostRequirementType
	GuestRequirementType = 0x00000002      // kSecGuestRequirementType
	DesignatedRequirementType = 0x00000003 // kSecDesignatedRequirementType
	LibraryRequirementType = 0x00000004    // kSecLibraryRequirementType
	PluginRequirementType = 0x00000005     // kSecPluginRequirementType
)

const RequirementKind = 1
type Requirement struct {
	// uint Magic;
	// uint Length;
	Kind uint32
	Expression RequirementExpression
}

func(c *Requirement)Load(buffer []byte)int {
	//length := binary.BigEndian.Uint32(buffer[4:])
	c.Kind = binary.BigEndian.Uint32(buffer[8:])
	exp, n := ReadExpression(buffer[12:])
	c.Expression = exp
	return 12 + n
}

func (c *Requirement)Length()int {
	return 12 + c.Expression.Length()
}

func (c *Requirement)WriteBytes(buffer []byte)int {
	binary.BigEndian.PutUint32(buffer, CSMAGIC_REQUIREMENT)
	binary.BigEndian.PutUint32(buffer[8:], c.Kind)
	n := 12
	n += c.Expression.WriteBytes(buffer[12:])
	binary.BigEndian.PutUint32(buffer[4:], uint32(n))
	return n
}

func (c *Requirement)GetBytes()[]byte {
	buffer := make([]byte, c.Length())
	c.WriteBytes(buffer)
	return buffer
}

func ReadRequirement(buffer []byte)(*Requirement,int) {
	magic := binary.BigEndian.Uint32(buffer)
	switch magic {
	case CSMAGIC_REQUIREMENT:
		b := new(Requirement)
		n := b.Load(buffer)
		return b, n
	}
	return nil, 0
}

const RequirementsSize = 12
type Requirements struct {
	// Magic  uint32
	// Length uint32
	// Count  uint32
	Keys   []uint32
	Values []*Requirement
}

func(c *Requirements)Load(buffer []byte)int {
	// length := int(binary.BigEndian.Uint32(buffer[4:]))
	count := int(binary.BigEndian.Uint32(buffer[8:]))
	length := RequirementsSize + count*8
	for i := 0; i < count; i++ {
		offset := RequirementsSize + i*8
		entryType := binary.BigEndian.Uint32(buffer[offset:])
		entryOffset := binary.BigEndian.Uint32(buffer[offset+4:])
		blob, n := ReadRequirement(buffer[entryOffset:])
		c.Keys = append(c.Keys, entryType)
		c.Values = append(c.Values, blob)
		length += n
	}
	return length
}

func(c *Requirements)WriteBytes(buffer []byte)int {
	count := len(c.Keys)
	binary.BigEndian.PutUint32(buffer, CSMAGIC_REQUIREMENTS)
	binary.BigEndian.PutUint32(buffer[8:], uint32(count))
	length := RequirementsSize + count*8
	for i := 0; i < count; i++ {
		binary.BigEndian.PutUint32(buffer[RequirementsSize+i*8:], c.Keys[i])
		binary.BigEndian.PutUint32(buffer[RequirementsSize+i*8+4:], uint32(length))
		length += c.Values[i].WriteBytes(buffer[length:])
	}
	binary.BigEndian.PutUint32(buffer[4:], uint32(length))
	return length
}

func(c *Requirements)GetBytes( )[]byte {
	buffer := make([]byte, c.Length())
	c.WriteBytes(buffer)
	return buffer
}

func(c *Requirements)Length()int {
	count := len(c.Keys)
	length := RequirementsSize + count*8
	for i := 0; i < count; i++ {
		length += c.Values[i].Length()
	}
	return length
}

func(c *Requirements)Add(k uint32, v *Requirement) {
	c.Keys = append(c.Keys, k)
	c.Values = append(c.Values, v)
}