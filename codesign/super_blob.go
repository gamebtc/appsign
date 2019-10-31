package codesign

import "encoding/binary"

const(
	CSSLOT_REQUIREMENTS              = 0x00000002 // The signature of this entry type will be CSMAGIC_REQUIREMENTS
	CSSLOT_ENTITLEMENTS              = 0x00000005 // The signature of this entry type will be CSMAGIC_EMBEDDED_ENTITLEMENTS
	CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x00001000 // The signature of this entry type will be CSMAGIC_CODEDIRECTORY
	CSSLOT_SIGNATURESLOT             = 0x00010000 // The signature of this entry type will be CSMAGIC_BLOBWRAPPER
)

// https://opensource.apple.com/source/Security/Security-55471/sec/Security/Tool/codesign.c

const CodeSignatureSuperBlobSign = 0xfade0cc0
const CodeSignatureSuperBlobSize = 12
type CodeSignatureSuperBlob struct {
	// uint Magic;
	// uint Length;
	// uint Count;
	Keys []uint32
	Values []CodeSignatureBlob
}

func(c *CodeSignatureSuperBlob )Load(buffer []byte)int {
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

func(c *CodeSignatureSuperBlob)WriteBytes(buffer []byte)int {
	count := len(c.Keys)
	binary.BigEndian.PutUint32(buffer, CodeSignatureSuperBlobSign)
	binary.BigEndian.PutUint32(buffer[4:], CodeSignatureSuperBlobSize)
	binary.BigEndian.PutUint32(buffer[8:], uint32(count))
	blobOffset := CodeSignatureSuperBlobSign + count*8
	for i := 0; i < count; i++ {
		binary.BigEndian.PutUint32(buffer[ 12+i*8:], c.Keys[i])
		binary.BigEndian.PutUint32(buffer[ 12+i*8+4:], uint32(blobOffset))
		c.Values[i].WriteBytes(buffer[blobOffset:])
		blobOffset += c.Values[i].Length()
	}
	return blobOffset
}

func(c *CodeSignatureSuperBlob)GetBytes()[]byte {
	buffer := make([]byte, c.Length())
	c.WriteBytes(buffer)
	return buffer
}

func(c *CodeSignatureSuperBlob)Length()int {
	count := len(c.Keys)
	length := RequirementsSize + count*8
	for i := 0; i < count; i++ {
		l := c.Values[i].Length()
		length += l
	}
	return length
}

func(c *CodeSignatureSuperBlob )Add(k uint32, v CodeSignatureBlob ) {
	c.Keys = append(c.Keys, k)
	c.Values = append(c.Values, v)
}
