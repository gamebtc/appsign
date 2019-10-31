package mach

func ReadMachObjects(buffer []byte)[]*MachObjectFile {
	if IsUniversalBinaryFile(buffer) {
		file := new(UniversalBinaryFile)
		file.Load(buffer)
		return file.machObjects
	} else if IsMachObjectFile(buffer) {
		mach := new(MachObjectFile)
		mach.Load(buffer)
		return []*MachObjectFile{mach}
	}
	return nil
}

func PackMachObjects(files []*MachObjectFile)[]byte {
	if len(files) == 1 {
		return files[0].GetBytes()
	}
	universalBinaryFile := new(UniversalBinaryFile)
	universalBinaryFile.Header.NumberOfArchitectures = uint32(len(files))
	for _, machObject := range files {
		fatArch := new(FatArch)
		fatArch.CpuType = machObject.Header.CpuType
		fatArch.CpuSubType = machObject.Header.CpuSubType
		fatArch.Align = DefaultAlignment
		universalBinaryFile.fatArchs = append(universalBinaryFile.fatArchs, fatArch)
		universalBinaryFile.machObjects = append(universalBinaryFile.machObjects, machObject)
	}
	return universalBinaryFile.GetBytes()
}

