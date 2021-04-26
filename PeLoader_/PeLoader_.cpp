#include <Windows.h>
#include <stdio.h>

#define VA(imageBase, RVA) ((ULONG)imageBase + (ULONG)RVA)


typedef struct
{
	WORD pointerOffset : 12;
	WORD flag : 4;
} FIX_UP, *PFIX_UP;

#pragma comment(linker, "/section:.rdata,RWE")

#pragma pack(push, 1)
struct TRUMP
{
	BYTE body[0x10];
	BYTE jmp = 0xe8;
	ULONG oldFunc = 0x11223344;
} *PTRUMP;
#pragma pack(pop)

/*
#pragma pack(push, 1)
typedef struct _EXCEPTION_REGISTRATION_RECORD
{
PEXCEPTION_REGISTRATION_RECORD Next;
//PEXCEPTION_DISPOSITION Handler;
LPVOID Handler;
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;
#pragma pack(pop)
*/

HMODULE destImageBase = NULL;
TRUMP trump;
/*
1. Вычитать PE-шник в память и проверить загловки: наличие релоков, [убедиться, что это exe-шник]
2. Вычитать таблицу секций и скопировать сами секии в память
3. Обработать импорты
4. Релоки
*/


// Вычитает PE-шник в память
// Возвращает адрес PE-шнка в памяти
PIMAGE_DOS_HEADER readPe(LPSTR fileName, DWORD &peSize)
{
	PIMAGE_DOS_HEADER memPE = NULL;
	DWORD fileSize = 0, readed = 0;
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	peSize = 0;
	if (hFile != INVALID_HANDLE_VALUE)
	{
		fileSize = GetFileSize(hFile, NULL);
		peSize = fileSize;
		memPE = (PIMAGE_DOS_HEADER)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
		destImageBase = (HMODULE)memPE;
		if (memPE)
			ReadFile(hFile, memPE, fileSize, &readed, NULL);
	}

	CloseHandle(hFile);
	return memPE;
}

// Выделяет ImageSize байт и копирует заголокки
// Возвращает указатель на Pe-шник в памяти
PIMAGE_DOS_HEADER preareImage(PIMAGE_DOS_HEADER sourceDosHeader)
{
	PIMAGE_DOS_HEADER memoryDosHeader = NULL;
	PIMAGE_NT_HEADERS sourcePeHeader = (PIMAGE_NT_HEADERS)((ULONG)sourceDosHeader + sourceDosHeader->e_lfanew);

	DWORD imageSize = sourcePeHeader->OptionalHeader.SizeOfImage;
	memoryDosHeader = (PIMAGE_DOS_HEADER)VirtualAlloc(NULL, imageSize, MEM_COMMIT, PAGE_READWRITE);

	//Скопировали заголовок
	MoveMemory(memoryDosHeader, sourceDosHeader, sourcePeHeader->OptionalHeader.SizeOfHeaders);
	return memoryDosHeader;
}

DWORD getPerm(DWORD flags)
{
	DWORD result = 0;
	switch (flags)
	{
	case 0xC0000040:
		result = PAGE_READWRITE;
		break;
	case 0x42000040:
		result = PAGE_READONLY;
		break;

	default:
		result = PAGE_EXECUTE_READWRITE;
		break;
	}
	return result;
}

// Обновляет imageBase и права на секции
void update(PIMAGE_DOS_HEADER destImage)
{
	PIMAGE_NT_HEADERS destPeHeader = (PIMAGE_NT_HEADERS)((ULONG)destImage + destImage->e_lfanew);
	destPeHeader->OptionalHeader.ImageBase = (ULONG)destImage;
	DWORD lastSectionNumber = destPeHeader->FileHeader.NumberOfSections;

	int i = 0;
	PIMAGE_SECTION_HEADER section;

	for (section = IMAGE_FIRST_SECTION(destPeHeader), i = 0; i < lastSectionNumber; i++, section++)
	{
		DWORD old = 0;
		LPVOID dest = (LPVOID)VA(destImage, section->VirtualAddress);
		DWORD perm = getPerm(section->Characteristics);
		DWORD status = VirtualProtect(dest, section->Misc.VirtualSize, perm, &old);
	}

}


void processSections(PIMAGE_DOS_HEADER sourceDosHeader, PIMAGE_DOS_HEADER memoryDosHeader)
{
	PIMAGE_NT_HEADERS sourcePeHeader = (PIMAGE_NT_HEADERS)((ULONG)sourceDosHeader + sourceDosHeader->e_lfanew);
	PIMAGE_NT_HEADERS destPeHeader = (PIMAGE_NT_HEADERS)((ULONG)memoryDosHeader + memoryDosHeader->e_lfanew);
	DWORD lastSectionNumber = sourcePeHeader->FileHeader.NumberOfSections;

	int i = 0;
	PIMAGE_SECTION_HEADER section;
	PIMAGE_SECTION_HEADER dstSections = IMAGE_FIRST_SECTION(destPeHeader);

	for (section = IMAGE_FIRST_SECTION(sourcePeHeader), i = 0; i < lastSectionNumber; i++, section++, dstSections++)
	{
		LPVOID src = (LPVOID)VA(sourceDosHeader, section->PointerToRawData);
		LPVOID dest = (LPVOID)VA(memoryDosHeader, dstSections->VirtualAddress);

		MoveMemory(dest, src, section->Misc.VirtualSize);
	}
}

// Подгрузить нужные DLL-ки и заполнить массив THUNK_DATA
void processIAT(PIMAGE_DOS_HEADER destImage)
{
	PIMAGE_NT_HEADERS destPeHeader = (PIMAGE_NT_HEADERS)((ULONG)destImage + destImage->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDir = (PIMAGE_DATA_DIRECTORY)(destImage + destPeHeader->FileHeader.SizeOfOptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR iat = (PIMAGE_IMPORT_DESCRIPTOR)((VA(destImage, destPeHeader->OptionalHeader.DataDirectory[1].VirtualAddress)));

	while (iat->OriginalFirstThunk)
	{
		LPSTR dllName = (LPSTR)VA(destImage, iat->Name);
		HMODULE dll = LoadLibraryA(dllName);

		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)VA(destImage, iat->FirstThunk);

		while (thunk->u1.Function)
		{
			LPSTR funcName = (LPSTR)VA(destImage, thunk->u1.Function + 2);
			printf("%s: %s\n", dllName, funcName);
			thunk->u1.Function = (ULONG)GetProcAddress(dll, funcName);
			thunk++;
		}
		iat++;
	}
}

void processRelocations(PIMAGE_DOS_HEADER destImage)
{
	PIMAGE_NT_HEADERS destPeHeader = (PIMAGE_NT_HEADERS)((ULONG)destImage + destImage->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDir = (PIMAGE_DATA_DIRECTORY)(destImage + destPeHeader->FileHeader.SizeOfOptionalHeader);
	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(VA(destImage, destPeHeader->OptionalHeader.DataDirectory[5].VirtualAddress));
	ULONG oldImageBase = destPeHeader->OptionalHeader.ImageBase;

	while (reloc->VirtualAddress)
	{

		PFIX_UP fixup = (PFIX_UP)((ULONG)reloc + sizeof(IMAGE_BASE_RELOCATION));
		int n = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(FIX_UP);

		for (int i = 0; i < n; fixup++, i++)
		{
			if (fixup->flag == 3)
			{
				PULONG hardcodedPointer = (PULONG)VA(destImage, reloc->VirtualAddress + fixup->pointerOffset);
				ULONG pointerRVA = *hardcodedPointer - oldImageBase;
				ULONG newPointer = (ULONG)destImage + pointerRVA;
				*hardcodedPointer = newPointer;
			}

			printf("0x08x, 0x08x\n", fixup->pointerOffset, fixup->flag);
		}
		reloc += reloc->SizeOfBlock;
	}
}

HMODULE NewGetModuleHandleA(LPCSTR lpModuleName)
{
	if (!lpModuleName)
	{
		return destImageBase;
	}
}

void HookGetModuleHandle()
{

	ULONG getModuleHandleFunc = (ULONG)GetModuleHandleA;

	MoveMemory((LPVOID)trump.body, (LPVOID)getModuleHandleFunc, sizeof(trump.body));

	trump.jmp = 0xE8;
	trump.oldFunc = (ULONG)NewGetModuleHandleA - (ULONG)GetModuleHandleA - 5;


	DWORD r;
	DWORD status = VirtualProtect((LPVOID)getModuleHandleFunc, 4096, PAGE_EXECUTE_READWRITE, &r);
	DWORD err = GetLastError();

	*(BYTE *)getModuleHandleFunc = 0xE8;
	*(ULONG*)(getModuleHandleFunc + 1) = (ULONG)((ULONG)getModuleHandleFunc - (ULONG)&trump - 5);

	status = VirtualProtect((LPVOID)getModuleHandleFunc, 4096, r, &r);

}

void fixPeb()
{

}

void LoadIt(PIMAGE_DOS_HEADER destImage)
{
	PIMAGE_NT_HEADERS destPeHeader = (PIMAGE_NT_HEADERS)((ULONG)destImage + destImage->e_lfanew);
	ULONG entryPoint = VA(destImage, destPeHeader->OptionalHeader.AddressOfEntryPoint);
	HANDLE hThread;// = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);

	__asm
	{
		mov eax, entryPoint
		jmp eax
	}



	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	printf("Executed!\n");

}
/*
typedef
_IRQL_requires_same_
_Function_class_(EXCEPTION_ROUTINE)
EXCEPTION_DISPOSITION
NTAPI
EXCEPTION_ROUTINE(
_Inout_ struct _EXCEPTION_RECORD *ExceptionRecord,
_In_ PVOID EstablisherFrame,
_Inout_ struct _CONTEXT *ContextRecord,
_In_ PVOID DispatcherContext
);

typedef EXCEPTION_ROUTINE *PEXCEPTION_ROUTINE;
*/

void mySeh(_Inout_ struct _EXCEPTION_RECORD *ExceptionRecord, _In_ PVOID EstablisherFrame, _Inout_ struct _CONTEXT *ContextRecord, _In_ PVOID DispatcherContext)
{
	printf("mySeh\n");
	MessageBoxA(GetForegroundWindow(), "mySeh", "mySeh", 0);
}

void setSeh()
{
	PEXCEPTION_REGISTRATION_RECORD secend = (PEXCEPTION_REGISTRATION_RECORD)__readfsdword(0);

	__asm
	{
		mov eax, fs:[0]
		mov ecx, mySeh
		add eax, 4
		mov[eax], ecx

		xor eax, eax
		mov eax, [eax]
	}

}

void processSEH()
{
	PEXCEPTION_REGISTRATION_RECORD seh = (PEXCEPTION_REGISTRATION_RECORD)__readfsdword(0);

	while ((DWORD)seh->Next != 0xFFFFFFFF)
	{
		printf("seh: 0x%08x\n", seh);
		printf("Handler: 0x%08x\nNext: 0x%08x\n", seh->Handler, seh->Next);
		seh = seh->Next;
	}
}

int main()
{
	//setSeh();
	//processSEH();
	//return 0;

	PIMAGE_DOS_HEADER sourceImage = NULL;
	PIMAGE_DOS_HEADER destImage = NULL;
	DWORD sourcePeSize = 0;
	LPSTR sourcePePath = "D:\\fasm\\programs\\HELLO_R.EXE";

	sourceImage = readPe(sourcePePath, sourcePeSize);
	destImage = preareImage(sourceImage);
	processSections(sourceImage, destImage);
	processIAT(destImage);
	processRelocations(destImage);

	update(destImage);
	//HookGetModuleHandle();

	//GetModuleHandleA(NULL);

	VirtualFree(sourceImage, sourcePeSize, MEM_RELEASE);

	LoadIt(destImage);

	VirtualFree(destImage, sourcePeSize, MEM_RELEASE);

	system("pause");
	return 0;
}

