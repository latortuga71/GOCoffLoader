package coff

/*

 credits: COFFLoader (by Kevin Haubris/@kev169)
 ported to golang. For sektor 7 advanced malware course @rez0h

*/
import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoCoffLdr/pkg/winapi"
)

const (
	MEM_SYMNAME_MAX                  = 100
	IMAGE_SCN_MEM_WRITE              = 0x80000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
	IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
	IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
	IMAGE_SCN_MEM_SHARED             = 0x10000000
	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
)

type COFF_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint16
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// 40 bytes
type COFF_SECTION struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

// 10 bytes
type COFF_RELOCATION struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

// 18 bytes
type COFF_SYMBOL struct {
	/*
		union {
			char ShortName[8]
			struct {
				uint32_t Zeros;
				uint32_t Offset;
			};
		}
	*/
	ShortName          [8]byte
	Value              uint32
	SectionNumber      uint16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

type COFF_MEM_SECTION struct {
	Counter              uint32
	Name                 [10]byte
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	NumberOfRelocations  uint16
	Characteristics      uint32
	InMemoryAddress      uintptr
	InMemorySize         uint32
}

type COFF_SYM_ADDRESS struct {
	Counter         uint32
	Name            [MEM_SYMNAME_MAX]byte
	SectionNumber   uint16
	Value           uint32
	StorageClass    uint8
	InMemoryAddress uint64
	GOTAddress      uint64
}

var debugging bool = true

func DebugPrint(args ...interface{}) {
	if !debugging {
		return
	}
	arg1 := args[0]
	arg1Str := "DEBUG " + arg1.(string)
	fmt.Printf(arg1Str, args[1:]...)
}

func ParseCoff(coff []byte) {
	// parse header
	coffHdrPtr := (*COFF_FILE_HEADER)(unsafe.Pointer(&coff[0]))
	headerOffset := unsafe.Sizeof(COFF_FILE_HEADER{})
	sectionSize := unsafe.Sizeof(COFF_SECTION{})
	totalSectionSize := sectionSize * uintptr(coffHdrPtr.NumberOfSections)
	var coffRelocPtr *COFF_RELOCATION
	var coffSymbolPtr *COFF_SYMBOL
	var baseAddressOfMemory uintptr
	var err error
	DebugPrint("[+] Machine Header: 0x%x\n", coffHdrPtr.Machine)
	DebugPrint("[+] Machine Header: 0x%x\n", coffHdrPtr.Machine)
	DebugPrint("[+] Number Of Sections: %d\n", coffHdrPtr.NumberOfSections)
	DebugPrint("[+] TimeDate Stamp 0x%x\n", coffHdrPtr.TimeDateStamp)
	DebugPrint("[+] Pointer To Symbol Table: 0x%x\n", coffHdrPtr.PointerToSymbolTable)
	DebugPrint("[+] Number Of Symbols %d\n", coffHdrPtr.NumberOfSymbols)
	DebugPrint("[+] Size Of Optional Header %d\n", coffHdrPtr.SizeOfOptionalHeader)
	DebugPrint("[+] Characteristcs 0x%x\n", coffHdrPtr.Characteristics)
	// allocate memory for all sections here
	baseAddressOfMemory, err = winapi.VirtualAlloc(0, uint32(totalSectionSize), winapi.MEM_COMMIT|winapi.MEM_RESERVE, winapi.PAGE_READWRITE)
	if err != nil {
		log.Fatal(err)
	}
	memorySections := (*COFF_MEM_SECTION)(unsafe.Pointer(baseAddressOfMemory))
	// parse sections
	for x := 0; x < int(coffHdrPtr.NumberOfSections); x++ {
		coffSectionPtr := (*COFF_SECTION)(unsafe.Pointer(&coff[headerOffset+sectionSize*uintptr(x)]))
		if coffSectionPtr.SizeOfRawData < 0 {
			// no data to save in this section.
		}
		// debug
		DebugPrint("[+] Section %d\n", x)
		DebugPrint("[+] Name %s\n", coffSectionPtr.Name)
		DebugPrint("[+] VirtualSize 0x%x\n", coffSectionPtr.VirtualSize)
		DebugPrint("[+] VirtualAddress 0x%x\n", coffSectionPtr.VirtualAddress)
		DebugPrint("[+] Size of raw data %d\n", coffSectionPtr.SizeOfRawData)
		DebugPrint("[+] Pointer to raw data 0x%x\n", coffSectionPtr.PointerToRawData)
		DebugPrint("[+] Pointer to relocations 0x%x\n", coffSectionPtr.PointerToRelocations)
		DebugPrint("[+] Pointer to line numbers 0x%x\n", coffSectionPtr.PointerToLineNumbers)
		// copy section to memory
		memorySections.Counter = uint32(x)
		copy(memorySections.Name[:], coffSectionPtr.Name[:])
		memorySections.SizeOfRawData = coffSectionPtr.SizeOfRawData
		memorySections.PointerToRawData = coffSectionPtr.PointerToRawData
		memorySections.PointerToRelocations = coffSectionPtr.PointerToRelocations
		memorySections.NumberOfRelocations = coffSectionPtr.NumberOfRelocations
		memorySections.Characteristics = coffSectionPtr.Characteristics
		memorySections.InMemorySize = memorySections.SizeOfRawData + (0x1000 - memorySections.SizeOfRawData%0x1000)
		// check if needs to be executable
		if memorySections.Characteristics&IMAGE_SCN_CNT_CODE != 0 {
			memorySections.InMemoryAddress, err = winapi.VirtualAlloc(0, memorySections.InMemorySize, winapi.MEM_COMMIT|winapi.MEM_TOP_DOWN, winapi.PAGE_READWRITE)
			if err != nil {
				log.Fatal(err)
			}
		}
		memorySections.InMemoryAddress, err = winapi.VirtualAlloc(0, memorySections.InMemorySize, winapi.MEM_COMMIT|winapi.MEM_TOP_DOWN, winapi.PAGE_EXECUTE_READWRITE)
		if err != nil {
			log.Fatal(err)
		}
		var wrote uint32
		success, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), memorySections.InMemoryAddress, uintptr(unsafe.Pointer(&coff[0]))+uintptr(coffSectionPtr.PointerToRawData), coffSectionPtr.SizeOfRawData, &wrote)
		if !success {
			log.Fatal(err)
		}
		if memorySections.NumberOfRelocations != 0 {
			// print relocation table
			for i := 0; i < int(memorySections.NumberOfRelocations); i++ {
				coffRelocPtr = (*COFF_RELOCATION)(unsafe.Pointer(&coff[memorySections.PointerToRelocations+uint32(10*i)]))
				DebugPrint("Reloc %d\n", i)
				DebugPrint("VADdress 0x%.9x\n", coffRelocPtr.VirtualAddress)
				DebugPrint("SymTab ins %5.d\n", coffRelocPtr.SymbolTableIndex)
				DebugPrint("Type 0x%.5x\n", coffRelocPtr.Type)
			}
		}
		// increase memory sections pointer
		memorySections = (*COFF_MEM_SECTION)(unsafe.Pointer(uintptr(unsafe.Pointer(memorySections)) + unsafe.Sizeof(COFF_MEM_SECTION{})))
	}
	/// allocate memory for symbol table
	numSymbols := coffHdrPtr.NumberOfSymbols
	symAddrSize := uint32(unsafe.Sizeof(COFF_SYM_ADDRESS{}))
	memSymbolsBaseAddress, err := winapi.VirtualAlloc(0, symAddrSize*numSymbols, winapi.MEM_COMMIT|winapi.MEM_RESERVE, winapi.PAGE_READWRITE)
	if err != nil {
		log.Fatal(err)
	}
	memSymbols := (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress))
	// got start of symbol table
	coffSymbolPtr = (*COFF_SYMBOL)(unsafe.Pointer(&coff[coffHdrPtr.PointerToSymbolTable]))
	coffStringsPtr := (*byte)(unsafe.Pointer(&coff[coffHdrPtr.PointerToSymbolTable+numSymbols*18]))
	// print symbols table
	for i := 0; i < int(numSymbols); i++ {
		DebugPrint("%d\n", i)
		DebugPrint("0x%.12x\n", coffSymbolPtr.Value)
		DebugPrint("0x%.9x\n", coffSymbolPtr.SectionNumber)
		DebugPrint("%6.4d\n", coffSymbolPtr.Type)
		DebugPrint("%.13d\n", coffSymbolPtr.StorageClass)
		if coffSymbolPtr.SectionNumber == 0 && coffSymbolPtr.StorageClass == 0 {
			copy(memSymbols.Name[:], "__UNDEFINED")
		} else {
			if coffSymbolPtr.ShortName[3] != 0 || coffSymbolPtr.ShortName[0] != 0 {
				n := make([]byte, 10)
				copy(n, coffSymbolPtr.ShortName[0:8])
				copy(memSymbols.Name[:], n)
			} else {
				strLoc := (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(coffStringsPtr)) + uintptr(uint32(binary.LittleEndian.Uint32(coffSymbolPtr.ShortName[4:])))))
				// copy string to our memory.
				var counter = 0
				for {
					if *strLoc == 0 {
						break
					}
					memSymbols.Name[counter] = *strLoc
					counter++
					strLoc = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(strLoc)) + 1))
				}
			}
		}
		// save data in internal symbols table that we allocated
		memSymbols.Counter = uint32(i)
		memSymbols.SectionNumber = coffSymbolPtr.SectionNumber
		memSymbols.Value = coffSymbolPtr.Value
		memSymbols.StorageClass = coffSymbolPtr.StorageClass
		memSymbols.InMemoryAddress = 0
		// increase both pointers
		coffSymbolPtr = (*COFF_SYMBOL)(unsafe.Pointer(uintptr(unsafe.Pointer(coffSymbolPtr)) + 18))
		memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})))

	}
	got, err := winapi.VirtualAlloc(0, 2048, winapi.MEM_COMMIT|winapi.MEM_RESERVE|winapi.MEM_TOP_DOWN, winapi.PAGE_READWRITE)
	if err != nil {
		log.Fatal(err)
	}

	// resolve symbols
	entryPoint := ResolveSymbols(got, memSymbolsBaseAddress, numSymbols, baseAddressOfMemory)
	DebugPrint("resolved symbols %x\n", entryPoint)
	for i := 0; i < int(numSymbols); i++ {
		memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbolsBaseAddress)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(i)))
		DebugPrint("%4d ", i)
		DebugPrint("VALUE 0x%x ", memSymbols.Value)
		DebugPrint("SECTION 0x%x ", memSymbols.SectionNumber)
		DebugPrint("STORAGE CLASS 0x%x ", memSymbols.StorageClass)
		DebugPrint("InMemAddress 0x%x ", memSymbols.InMemoryAddress)
		DebugPrint("GOT Address 0x%x ", memSymbols.GOTAddress)
		DebugPrint("NAME %s\n", memSymbols.Name)
	}
	//time.Sleep(time.Hour * 1)
	//fix relocations.
	memorySections = (*COFF_MEM_SECTION)(unsafe.Pointer(baseAddressOfMemory))
	for i := 0; i < int(coffHdrPtr.NumberOfSections); i++ {
		memorySectionPtr := (*COFF_MEM_SECTION)(unsafe.Pointer(uintptr(unsafe.Pointer(memorySections)) + uintptr(unsafe.Sizeof(COFF_MEM_SECTION{})*uintptr(i))))
		if memorySectionPtr.NumberOfRelocations == 0 {
			continue
		}
		for j := 0; j < int(memorySectionPtr.NumberOfRelocations); j++ {
			coffRelocPtr = (*COFF_RELOCATION)(unsafe.Pointer(&coff[memorySectionPtr.PointerToRelocations+uint32(10*j)]))
			switch coffRelocPtr.Type {
			case 0x1:
				// untested
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				offset64 := uint64(where)
				what64 := (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress + offset64
				ok, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&what64)), 8, nil)
				if !ok {
					log.Fatal(err)
				}
				break
			case 0x3:
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				var offset32 [4]byte
				ok, err := winapi.ReadProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&offset32[0])), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				offset32Num := binary.LittleEndian.Uint32(offset32[:])
				var what3232 uint32
				what32 := uint32(offset32Num) + uint32((*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress) - uint32(where+4)
				what3232 = uint32(what32)
				ok, err = winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&what3232)), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				DebugPrint("0x%x\n", where)
				DebugPrint("offset32 %d\n", binary.LittleEndian.Uint32(offset32[:]))
				DebugPrint("what32 0x%x\n", what3232)
				break
			case 0x4:
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				var offset32 [4]byte
				ok, err := winapi.ReadProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&offset32[0])), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				offset32Num := binary.LittleEndian.Uint32(offset32[:])
				var what3232 uint32
				if (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).GOTAddress != 0 {
					DebugPrint("GOT addres\n")
					DebugPrint("where 0x%x\n", memSymbolsBaseAddress)
					DebugPrint("where 0x%x\n", memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))
					//time.Sleep(time.Hour * 1)
					what32 := (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).GOTAddress - uint64(where+4)
					what3232 = uint32(what32)
				} else {
					what32 := uint64(offset32Num) + (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress - uint64(where+4)
					what3232 = uint32(what32)
				}
				DebugPrint("where 0x%x\n", where)
				DebugPrint("offset32 %d\n", binary.LittleEndian.Uint32(offset32[:]))
				DebugPrint("what32 0x%x\n", what3232)
				ok, err = winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&what3232)), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				break
			case 0x8:
				//untested
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				var offset32 [4]byte
				ok, err := winapi.ReadProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&offset32[0])), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				offset32Num := binary.LittleEndian.Uint32(offset32[:])
				var what3232 uint32
				what32 := uint32(offset32Num) + uint32((*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress) - uint32(where+4+4)
				what3232 = uint32(what32)
				ok, err = winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&what3232)), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				DebugPrint("0x%x\n", where)
				DebugPrint("offset32 %d\n", binary.LittleEndian.Uint32(offset32[:]))
				DebugPrint("what32 0x%x\n", what3232)
				break
			default:
				DebugPrint("Reloc is not supported!\n")
				log.Fatal(fmt.Errorf("Relocation Type Not Supported"))
			}
			//time.Sleep(time.Second * 1000)
		}
	}
	//time.Sleep(time.Second * 10)
	fmt.Println("Relocations done")
	syscall.Syscall(entryPoint, 0, 0, 0, 0)
	/*_, err = winapi.CreateThread(0, 0, entryPoint, 0, 0, nil)
	if err != nil {
		log.Fatal(err)
	}
	*/
	//fmt.Println("TEST")
}

func trimstr(old string) string {
	var new = ""
	for _, c := range old {
		if c == 0 {
			break
		}
		new += string(c)
	}
	return new
}

func ResolveSymbols(GOT uintptr, memSymbolsBaseAddress uintptr, nSymbols uint32, memSectionsBaseAddress uintptr) uintptr {
	GOTIdx := 0
	memSymbols := (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress))
	memorySections := (*COFF_MEM_SECTION)(unsafe.Pointer(memSectionsBaseAddress))
	var symbol [256]byte
	var strSymbol string
	var dllName string
	var funcName string
	var entryPoint uintptr
	section := 0
	DebugPrint("%d symbols\n", nSymbols)
	for i := 0; i < int(nSymbols); i++ {
		copy(symbol[:], memSymbols.Name[:])
		strSymbol = trimstr(string(symbol[:]))
		DebugPrint("SYMBOL -> %s\n", strSymbol)
		memSymbols.GOTAddress = 0
		if memSymbols.SectionNumber > 0xff {
			memSymbols.InMemoryAddress = 0
			memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})))
			continue
		}
		if strings.Contains(strSymbol, "__UNDEFINED") {
			memSymbols.InMemoryAddress = 0
			memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})))
			continue
		}
		if strings.Contains(strSymbol, "imp_") {
			if !strings.Contains(strSymbol, "$") {
				dllName = "kernel32"
				funcName = strings.Split(strSymbol, "__imp_")[1]
			} else {
				dllName = strings.Split(strSymbol, "__imp_")[1]
				dllName = strings.Split(dllName, "$")[0]
				funcName = strings.Split(strSymbol, "$")[1]
			}
			DebugPrint("DLL %s\nFUNC %s\n", dllName, funcName)
			//lib := winapi.LoadLibrary(string(dllName))
			lib, err := syscall.LoadLibrary(dllName + ".dll")
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Library Handle 0x%x\n", lib)
			if lib != 0 {
				funcAddress, err := syscall.GetProcAddress(lib, funcName)
				if funcAddress == 0 {
					log.Fatal(err)
				}
				//funcAddress := winapi.GetProcAddress(lib, funcName)
				if funcAddress == 0 {
					log.Fatal(fmt.Errorf("failed to get proc address"))
				}
				DebugPrint("0x%x\n", uint64(funcAddress))
				memSymbols.InMemoryAddress = uint64(funcAddress)
				DebugPrint("0x%x\n", memSymbols.InMemoryAddress)
				var wrote uint32
				ok, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), GOT+(uintptr(GOTIdx)*8), uintptr(unsafe.Pointer(&memSymbols.InMemoryAddress)), 8, &wrote)
				if !ok {
					log.Fatal(err, wrote)
				}
				memSymbols.GOTAddress = uint64(GOT + (uintptr(GOTIdx * 8))) //uint64((GOT + (uintptr(GOTIdx) * 8)))
				DebugPrint("0x%x\n", memSymbols.GOTAddress)
				GOTIdx++
			}
		} else {
			section = int(memSymbols.SectionNumber) - 1
			movedPtr := (*COFF_MEM_SECTION)(unsafe.Pointer(uintptr(unsafe.Pointer(memorySections)) + uintptr((unsafe.Sizeof(COFF_MEM_SECTION{}) * uintptr(section)))))
			memSymbols.InMemoryAddress = uint64(movedPtr.InMemoryAddress + uintptr(memSymbols.Value))
			if strSymbol == "go" {
				DebugPrint("Entry -> 0x%x\n", memSymbols.InMemoryAddress)
				entryPoint = uintptr(memSymbols.InMemoryAddress)
			}
		}
		// move pointer
		memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})))
	}
	return entryPoint
}

func ReadMemUntilNull(start *byte) []byte {
	out := make([]byte, 0)
	var x = 0
	for {
		if *start == 0 {
			break
		}
		out = append(out, *start)
		x++
		start = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(start)) + uintptr(x)))
	}
	return out
}
