package codesign

import (
	"encoding/binary"
	"math"
)

const(
	CDB_ScatterMinimumVersion     = 0x20100
	CDB_TeamIDMinimumVersion      = 0x20200
	CDB_CodeLimit64MinimumVersion = 0x20300
	CDB_ExecSegMinimumVersion     = 0x20400

	CDB_FixedLengthV20001 = 44
	CDB_FixedLengthV20100 = 48
	CDB_FixedLengthV20200 = 52

	CDB_InfoFileHashOffset = 1
	CDB_RequirementsHashOffset = 2
	CDB_CodeResourcesFileHashOffset = 3
	CDB_ApplicationSpecificHashOffset = 4
	CDB_EntitlementsHashOffset = 5
)

const(
	CSMAGIC_REQUIREMENT	= 0xfade0c00		//single Requirement blob
	CSMAGIC_REQUIREMENTS = 0xfade0c01		//Requirements vector (internal requirements)
	CSMAGIC_CODEDIRECTORY = 0xfade0c02		//CodeDirectory blob
	CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0 //embedded form of signature data
	CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1 //multi-arch collection of embedded signatures
	CSSLOT_CODEDIRECTORY = 0				//slot index for CodeDirectory
)

type BlobIndex struct {
	Type uint32     //type of entry
	Offset uint32   //offset of entry
}

type SuperBlob struct {
	Magic uint32      //magic number
	Len   uint32      //total length of SuperBlob
	Count uint32      //number of index entries following
	Index []BlobIndex //(count) entries
}

type CodeDirectory struct {
	//Magic         uint32 // magic number (CSMAGIC_CODEDIRECTORY)
	//Len           uint32 // total length of CodeDirectory blob
	Version uint32 // compatibility version
	Flags   uint32 // setup and mode flags
	//HashOffset    uint32 // offset of hash slot element at index zero
	//IdentOffset   uint32 // offset of identifier string
	//SpecialSlots  uint32 // number of special hash slots
	//CodeSlots     uint32 // number of ordinary (code) hash slots
	CodeLimit    uint32 // limit to main image signature range
	HashSize     uint8  // size of each hash in bytes
	HashType     uint8  // type of hash (cdHashType* constants)
	Spare1       uint8  // unused (must be zero)
	PageSizeLog2 uint8  // log2(page size in bytes); 0 => infinite
	Spare2       uint32 // unused (must be zero)
	//ScatterOffset uint32 // offset of optional scatter vector (zero if absent)
	//TeamIDOffset  uint32 // Version 0x20200
	Spare3        uint32 // Version 0x20300
	CodeLimit64   uint64 // Version 0x20300
	ExecSegBase   uint64 // Version 0x20400
	ExecSegLimit  uint64 // Version 0x20400
	ExecSegFlags  uint64 // Version 0x20400
	Ident         string
	TeamID        string // Version 0x20200
	SpecialHashes [][]byte
	CodeHashes    [][]byte
}

func(c *CodeDirectory)GetPageSize()int {
	return 1 << c.PageSizeLog2
}

func(c *CodeDirectory) SetPageSize(v uint32) {
	c.PageSizeLog2 = byte(math.Log2(float64(v)))
}

func(c *CodeDirectory)Load(buffer []byte)int {
	//c.Version = 0x00020200
	//_ = binary.BigEndian.Uint32(buffer[4:])
	c.Version = binary.BigEndian.Uint32(buffer[8:])
	c.Flags = binary.BigEndian.Uint32(buffer[12:])
	hashOffset := int(binary.BigEndian.Uint32(buffer[16:]))
	identOffset := int(binary.BigEndian.Uint32(buffer[20:]))
	numberOfSpecialSlots := int(binary.BigEndian.Uint32(buffer[24:]))
	numberOfCodeSlots := int(binary.BigEndian.Uint32(buffer[28:]))
	c.CodeLimit = binary.BigEndian.Uint32(buffer[32:])
	c.HashSize = buffer[36]
	c.HashType = buffer[37]
	c.Spare1 = buffer[38]
	c.PageSizeLog2 = buffer[39]
	c.Spare2 = binary.BigEndian.Uint32(buffer[40:])

	teamIDOffset := uint32(0)
	if c.Version >= CDB_ScatterMinimumVersion {
		_  =  binary.BigEndian.Uint32(buffer[44:])  //scatterOffset
		if c.Version >= CDB_TeamIDMinimumVersion {
			teamIDOffset = binary.BigEndian.Uint32(buffer[48:])
			if c.Version >= CDB_CodeLimit64MinimumVersion {
				c.Spare3 = binary.BigEndian.Uint32(buffer[52:])
				c.CodeLimit64 = binary.BigEndian.Uint64(buffer[56:])
				if c.Version >= CDB_ExecSegMinimumVersion {
					c.ExecSegBase = binary.BigEndian.Uint64(buffer[64:])
					c.ExecSegLimit = binary.BigEndian.Uint64(buffer[72:])
					c.ExecSegFlags = binary.BigEndian.Uint64(buffer[80:])
				}
			}
		}
	}
	hashSize := int(c.HashSize)
	if identOffset != 0 {
		c.Ident = ReadNullTerminatedAnsiString(buffer[identOffset:])
	}
	if teamIDOffset != 0 {
		c.TeamID = ReadNullTerminatedAnsiString(buffer[teamIDOffset:])
	}
	specialHashesOffset := hashOffset - numberOfSpecialSlots*hashSize
	for i := 0; i < numberOfSpecialSlots; i++ {
		start := specialHashesOffset + i*hashSize
		hash := buffer[start : start+hashSize]
		c.SpecialHashes = append(c.SpecialHashes, hash)
	}

	for i := 0; i < numberOfCodeSlots; i++ {
		start := hashOffset + i*hashSize
		hash := buffer[start : start+hashSize]
		c.CodeHashes = append(c.CodeHashes, hash)
	}

	return 0
}

func(c *CodeDirectory)Length()int {
	length := c.fixedLength()
	if c.Ident != "" {
		length += len(c.Ident) + 1
	}
	if c.Version >= CDB_TeamIDMinimumVersion && c.TeamID != "" {
		length += len(c.TeamID) + 1
	}
	hashSize := int(c.HashSize)
	length += len(c.SpecialHashes) * hashSize
	length += len(c.CodeHashes) * hashSize
	return length
}

func (c *CodeDirectory) fixedLength()int {
	l := CDB_FixedLengthV20001
	if c.Version >= CDB_ExecSegMinimumVersion {
		l += 24 + 20
	} else if c.Version >= CDB_CodeLimit64MinimumVersion {
		l += 12 + 8
	} else if c.Version >= CDB_TeamIDMinimumVersion {
		l += 4 + 4
	} else if c.Version >= CDB_ScatterMinimumVersion {
		l += 4
	}
	return l
}

func(c *CodeDirectory)write(buffer []byte, length int) {
	nextOffset := c.fixedLength()
	identOffset := 0
	if c.Ident != "" {
		identOffset = nextOffset
		nextOffset += len(c.Ident) + 1
	}

	teamIDOffset := 0
	if c.Version >= CDB_TeamIDMinimumVersion && c.TeamID != "" {
		teamIDOffset = nextOffset
		nextOffset += len(c.TeamID) + 1
	}

	hashSize := int(c.HashSize)
	specialHashesOffset := nextOffset
	hashOffset := specialHashesOffset + len(c.SpecialHashes)*hashSize

	binary.BigEndian.PutUint32(buffer, CSMAGIC_CODEDIRECTORY)
	binary.BigEndian.PutUint32(buffer[4:], uint32(length))
	binary.BigEndian.PutUint32(buffer[8:], c.Version)
	binary.BigEndian.PutUint32(buffer[12:], c.Flags)
	binary.BigEndian.PutUint32(buffer[16:], uint32(hashOffset))
	binary.BigEndian.PutUint32(buffer[20:], uint32(identOffset))
	binary.BigEndian.PutUint32(buffer[24:], uint32(len(c.SpecialHashes)))
	binary.BigEndian.PutUint32(buffer[28:], uint32(len(c.CodeHashes)))
	binary.BigEndian.PutUint32(buffer[32:], c.CodeLimit)
	buffer[36] = c.HashSize
	buffer[37] = c.HashType
	buffer[38] = c.Spare1
	buffer[39] = c.PageSizeLog2
	binary.BigEndian.PutUint32(buffer[40:], c.Spare2)

	if c.Version >= CDB_ScatterMinimumVersion {
		binary.BigEndian.PutUint32(buffer[44:], 0)
		if c.Version >= CDB_TeamIDMinimumVersion {
			binary.BigEndian.PutUint32(buffer[48:], uint32(teamIDOffset))
			if c.Version >= CDB_CodeLimit64MinimumVersion {
				binary.BigEndian.PutUint32(buffer[52:], c.Spare3)
				binary.BigEndian.PutUint64(buffer[56:], c.CodeLimit64)
				if c.Version >= CDB_ExecSegMinimumVersion {
					binary.BigEndian.PutUint64(buffer[64:], c.ExecSegBase)
					binary.BigEndian.PutUint64(buffer[72:], c.ExecSegLimit)
					binary.BigEndian.PutUint64(buffer[80:], c.ExecSegFlags)
				}
			}
		}
	}

	if c.Ident != "" {
		copy(buffer[identOffset:], c.Ident)
		buffer[identOffset+1+len(c.Ident)] = 0
	}

	if c.Version >= CDB_TeamIDMinimumVersion && c.TeamID != "" {
		copy(buffer[teamIDOffset:], c.TeamID)
		buffer[teamIDOffset+1+len(c.TeamID)] = 0
	}

	if len(c.SpecialHashes) > 0 {
		for i, hash := range c.SpecialHashes {
			if len(hash) != hashSize {
				panic("Hash length does not match declared HashSize")
			}
			start := specialHashesOffset + i*hashSize
			copy(buffer[start:start+hashSize], hash)
		}
	}

	if len(c.CodeHashes) > 0 {
		for i, hash := range c.CodeHashes {
			if len(hash) != hashSize {
				panic("Hash length does not match declared HashSize")
			}
			start := hashOffset + i*hashSize
			copy(buffer[start:], hash)
		}
	}
}

func(c *CodeDirectory)WriteBytes(buffer []byte) int {
	length := c.Length()
	c.write(buffer, length)
	return length
}

func(c *CodeDirectory)GetBytes()[]byte {
	length := c.Length()
	buffer := make([]byte, length)
	c.write(buffer, length)
	return buffer
}

func IsCodeDirectory(buffer []byte)bool {
	magic := binary.BigEndian.Uint32(buffer)
	return magic == CSMAGIC_CODEDIRECTORY
}

func CreateCodeDirectory(codeLength uint32 , ident string , teamID string , hashType byte )*CodeDirectory {
	const pageSize = 4096
	hashSize := GetHashLength(hashType)
	codeDirectory := &CodeDirectory{
		Version:   CDB_TeamIDMinimumVersion,
		CodeLimit: codeLength,
		HashType:  hashType,
		HashSize:  hashSize,
		PageSizeLog2: uint8(math.Log2(pageSize)),
		Ident:     ident,
		TeamID:    teamID,
	}
	codeDirectory.SpecialHashes = make([][]byte, SpecialHashCount)
	for i := 0; i < SpecialHashCount; i++ {
		codeDirectory.SpecialHashes[i] = make([]byte, hashSize)
	}

	codeHashEntries := int(math.Ceil(float64(codeLength) / pageSize))
	codeDirectory.CodeHashes = make([][]byte, codeHashEntries)
	for i := 0; i < codeHashEntries; i++ {
		codeDirectory.CodeHashes[i] = make([]byte, hashSize)
	}

	return codeDirectory
}