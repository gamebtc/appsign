package codesign

import "encoding/binary"

type CodeSignatureGenericBlob struct {
	Magic uint32
	//Length uint32
	Data []byte
}

func(c *CodeSignatureGenericBlob)Load(buffer []byte)int {
	c.Magic = binary.BigEndian.Uint32(buffer)
	length := int(binary.BigEndian.Uint32(buffer[4:]))
	c.Data = make([]byte, length-8)
	copy(c.Data, buffer[8:])
	return length
}

func(c *CodeSignatureGenericBlob)WriteBytes(buffer []byte)int {
	length := c.Length()
	binary.BigEndian.PutUint32(buffer, c.Magic)
	binary.BigEndian.PutUint32(buffer[4:], uint32(length))
	copy(buffer[8:], c.Data)
	return length
}

func(c *CodeSignatureGenericBlob)GetBytes()[]byte {
	buffer := make([]byte, c.Length())
	c.WriteBytes(buffer)
	return buffer
}

func(c *CodeSignatureGenericBlob)Length() int {
	return 8 + len(c.Data)
}