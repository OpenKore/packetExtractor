#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <fstream>

using namespace std;

# if defined(_MSC_VER)
# ifndef _CRT_SECURE_NO_DEPRECATE
# define _CRT_SECURE_NO_DEPRECATE (1)
# endif
# pragma warning(disable : 4996)
# endif

#define RO_EXE_NAME "ragexe.exe"
#define MAX_PACKET 0x1000
#define MAX_SHUFFLE_PACKET 29

#define EXIT(msg, ...) \
	do { \
		printf((msg), ##__VA_ARGS__); \
		system("PAUSE"); \
		exit(EXIT_FAILURE); \
	} while (false)

DWORD GetPid(const char* ProcessName);
size_t ReadSessionMemory(HANDLE process, vector<char> *vec);
size_t ScanMem(vector<char> *vec, const char *data, size_t start, size_t end, size_t len, bool backwards);

int main(void) {
	vector<char> vec;
	DWORD pid;
	HANDLE process;
	int i, c;
	short pktlen[MAX_PACKET] = { 0 };
	WORD shuffle_pkt[MAX_SHUFFLE_PACKET] = { 0 };
	size_t session_base_addr, offset, offset2, refOffset, ret, pktcall1, pktcall2, last, next;
	byte g_PacketLenMap[] = "\x0\x0\x0\x0\x0\xE8\xAB\xAB\xAB\xAB\x68\xAB\xAB\xAB\x00\xE8\xAB\xAB\xAB\xAB\x59\xC3";
	char ClientDate[9] = { 0 };
	ofstream file;
	char str[32];

	while (!(pid = GetPid(RO_EXE_NAME))) {
		system("CLS");
		printf("Please run RO clinet.\n");
		system("PAUSE");
	}
	system("CLS");

	if (!(process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid)))
		EXIT("OpenProcess failed.\n");

	printf("Step 1 - Read process memory to vector\n");
	if (!(session_base_addr = ReadSessionMemory(process, &vec)))
		EXIT("Read memory failed.\n");
	printf("Done.\n");

	printf("Step 2a - Find the GetPacketSize function call\n");
	if ((refOffset = ScanMem(&vec, "\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x50\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x6A\x01\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x6A\x06", 0, 0, 41, false)) == 0xFFFFFFFF)
		EXIT("GetPacketSize function call not found.\n");
	printf("Address: %08X\n", session_base_addr + refOffset - 1);

	printf("Step 2b - Go Inside the GetPacketSize function\n");
	offset = refOffset + *(DWORD*)&vec[refOffset + 8] + 12;
	printf("Address: %08X\n", session_base_addr + offset);

	printf("Step 2c - Look for g_PacketLenMap reference and the pktLen function call following it\n");
	if ((offset = ScanMem(&vec, "\xB9\xAB\xAB\xAB\x00\xE8\xAB\xAB\xAB\xAB\x8B\xAB\x04", offset, 0, 13, false)) == 0xFFFFFFFF)
		EXIT("g_PacketLenMap reference not found.\n");
	printf("Address: %08X\n", session_base_addr + offset);

	printf("Step 2d - Extract the g_PacketLenMap assignment\n");
	memcpy(g_PacketLenMap, &vec[offset], 5);
	printf("g_PacketLenMap reference: %02X:%02X:%02X:%02X:%02X\n", g_PacketLenMap[0], g_PacketLenMap[1], g_PacketLenMap[2], g_PacketLenMap[3], g_PacketLenMap[4]);

	printf("Step 3a - Find the InitPacketMap function call using g_PacketLenMap\n");
	if ((offset = ScanMem(&vec, (char*)g_PacketLenMap, 0, 0, 22, false)) == 0xFFFFFFFF)
		EXIT("InitPacketMap function call not found.\n");
	printf("Address: %08X\n", session_base_addr + offset + 5);

	printf("Step 3b - Go inside InitPacketMap\n");
	offset += *(DWORD*)&vec[offset + 6] + 10;
	printf("Address: %08X\n", session_base_addr + offset);

	printf("Step 3c - Look for InitPacketLenWithClient call\n");
	if ((offset = ScanMem(&vec, "\x8B\xCE\xE8\xAB\xAB\xAB\xAB\xC7", offset, 0, 8, false)) == 0xFFFFFFFF)
		EXIT("InitPacketLenWithClient call not found.\n");
	printf("Address: %08X\n", session_base_addr + offset + 2);

	printf("Step 3d - Go inside InitPacketLenWithClient\n");
	offset += *(DWORD*)&vec[offset + 3] + 7;
	printf("Address: %08X\n", session_base_addr + offset);

	printf("Step 4a - Look for the first call\n");
	if ((offset = ScanMem(&vec, "\x8B\xF1\xE8\xAB\xAB\xAB\xAB", offset, 0, 7, false)) == 0xFFFFFFFF)
		EXIT("InitPacketLenWithClient call not found.\n");
	printf("Address: %08X\n", session_base_addr + offset + 2);

	printf("Step 4b - Go inside\n");
	offset2 = offset + *(DWORD*)&vec[offset + 3] + 7;
	printf("Address: %08X\n", session_base_addr + offset2);

	printf("Step 4c - Look for ret\n");
	if ((ret = ScanMem(&vec, "\xC3\xCC", offset2, 0, 2, false)) == 0xFFFFFFFF)
		EXIT("InitPacketLenWithClient call not found.\n");
	printf("Address: %08X\n", session_base_addr + ret);

	printf("Step 4d - Look for call pattern 1\n");
	if ((pktcall1 = ScanMem(&vec, "\x6A\xAB\x6A\xAB\x6A\xAB\x68\xAB\xAB\x00\x00\x8B\xCE\xE8", offset2, ret, 14, false)) == 0xFFFFFFFF)
		EXIT("call pattern 1 not found.\n");
	pktcall1 += *(DWORD*)&vec[pktcall1 + 14] + 18;
	printf("Pattern 1: %08X\n", session_base_addr + pktcall1);

	printf("Step 4e - Look for call pattern 2\n");
	if ((pktcall2 = ScanMem(&vec, "\xC7\x45\xAB\xAB\xAB\x00\x00\xC7\x45\xAB\xAB\xAB\xAB\xAB\xC7\x45\xAB\xAB\xAB\xAB\xAB\xC7\x45\xAB\xAB\x00\x00\x00\xE8", offset2, ret, 29, false)) == 0xFFFFFFFF)
		EXIT("call pattern 2 not found.\n");
	pktcall2 += *(DWORD*)&vec[pktcall2 + 29] + 33;
	printf("Pattern 2: %08X\n", session_base_addr + pktcall2);

	printf("Step 5 - Extract packet length\n");
	if ((offset = ScanMem(&vec, "\x32\x30\xAB\xAB\x2D\xAB\xAB\x2D", 0, 0, 8, false)) == 0xFFFFFFFF)
		EXIT("Client date not found.\n");
	memcpy(ClientDate, &vec[offset], 4);
	memcpy(ClientDate + 4, &vec[offset + 5], 2);
	memcpy(ClientDate + 6, &vec[offset + 8], 2);
	sprintf(str, "PacketLengths_%s.ini", ClientDate);
	file.open(str);
	file << "[Packet_Lengths]\n";
	for (i = c = 0; i < 2; ++i) {
		if (!i)
			last = offset2;
		else {
			last = offset;
			if ((ret = ScanMem(&vec, "\xC3\xCC", offset, 0, 2, false)) == 0xFFFFFFFF)
				EXIT("ret not found.\n");
		}
		for (; (next = ScanMem(&vec, "\xE8", last, ret, 1, false)) != 0xFFFFFFFF; last = next) {
			WORD header;
			short len = 0;
			size_t calltype = next + *(DWORD*)&vec[++next] + 4;
			if (calltype != pktcall1 && calltype != pktcall2)
				continue;
			if (calltype == pktcall1) {
				if (vec[next - 5] == 0x6A) {
					header = vec[next - 4];
					offset2 = next - 5;
				}
				else {
					if (vec[next - 8] != 0x68)
						EXIT("pattern 1 header not found.\n");
					header = *(WORD*)&vec[next - 7];
					offset2 = next - 8;
				}
				if (vec[offset2 - 2] == 0x6A) {
					len = vec[offset2 - 1];
					if (len == 0xFF)
						len = -1;
				}
				else {
					if (vec[offset2 - 5] != 0x68)
						EXIT("pattern 1 len not found.\n");
					len = *(short*)&vec[offset2 - 4];
				}
			}
			else {
				if ((offset2 = ScanMem(&vec, "\xC7\x45\xAB\xAB\xAB\x00\x00", last, next, 7, false)) == 0xFFFFFFFF)
					EXIT("pattern 2 header not found.\n");
				header = *(WORD*)&vec[offset2 + 3];
				if ((offset2 = ScanMem(&vec, "\xC7\x45", offset2 + 1, next, 2, false)) == 0xFFFFFFFF)
					EXIT("pattern 2 len not found.\n");
				len = *(short*)&vec[offset2 + 3];
			}
			if (!pktlen[header]) {
				pktlen[header] = len;
				sprintf(str, "0x%04X = %d\n", header, len);
				file << str;
			}
			if (!i && c < MAX_SHUFFLE_PACKET)
				shuffle_pkt[c++] = header;
		}
	}

	file << "\n[Packet_Keys]\n";
	if ((offset = ScanMem(&vec, "\x8B\x0D\xAB\xAB\xAB\x00\x6A\x01\xE8", refOffset, 0, 9, false)) == 0xFFFFFFFF)
		EXIT("Packet keys not found.\n");
	offset += *(DWORD*)&vec[offset + 9];
	if ((offset = ScanMem(&vec, "\xC7\x41\xAB\xAB\xAB\xAB\xAB\xC7\x41\xAB\xAB\xAB\xAB\xAB\xC7\x41", offset, 0, 16, false)) == 0xFFFFFFFF)
		EXIT("Packet keys not found.\n");
	sprintf(str, "1 = 0x%08X\n", *(DWORD*)&vec[offset + 3]);
	file << str;
	sprintf(str, "2 = 0x%08X\n", *(DWORD*)&vec[offset + 10]);
	file << str;
	sprintf(str, "3 = 0x%08X\n", *(DWORD*)&vec[offset + 17]);
	file << str;

	file << "\n[Shuffle_Packets]\n";
	for (i = 0; i < MAX_SHUFFLE_PACKET; ++i) {
		sprintf(str, "0x%04X = %d\n", shuffle_pkt[i], i);
		file << str;
	}

	file.close();

	sprintf(str, "recvpackets_%s.txt", ClientDate);
	file.open(str);
	for (i = c = 0; i < MAX_PACKET; ++i) {
		if (pktlen[i]) {
			sprintf(str, "%04X %d\n", i, pktlen[i]);
			file << str;
			++c;
		}
	}
	file.close();
	printf("Total Packets: %d\n", c);
	printf("Done!\n");

	system("PAUSE");
	return 0;
}

bool match(const char *first, const char *second, size_t len) {
	if (*first == '\xAB' || *first == *second) {
		if (!(--len))
			return true;
		return match(first + 1, second + 1, len);
	}
	return false;
}

size_t ScanMem(vector<char> *vec, const char *data, size_t start, size_t end, size_t len, bool backwards) {
	size_t i;

	if (!end || end > vec->size())
		end = vec->size();

	if (backwards == false) {
		for (i = start; i < end - len; ++i) {
			if (match(data, &(*vec)[i], len) == true)
				return i;
		}
	}
	else {
		for (i = end - len - 1; i >= start; --i) {
			if (match(data, &(*vec)[i], len) == true)
				return i;
		}
	}
	return 0xFFFFFFFF;
}

size_t ReadSessionMemory(HANDLE process, vector<char> *vec) {
	SYSTEM_INFO si;
	GetSystemInfo(&si);

	MEMORY_BASIC_INFORMATION info;
	char* p = 0;
	while (p < si.lpMaximumApplicationAddress) {
		if (VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info)) {
			p = (char*)info.BaseAddress;
			vec->resize(info.RegionSize);
			SIZE_T bytesRead;
			if (ReadProcessMemory(process, p, &(*vec)[0], info.RegionSize, &bytesRead)) {
				SIZE_T i;
				for (i = 0; i < bytesRead - 41; ++i) {
					if (match("\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x50\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x6A\x01\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x6A\x06", &(*vec)[i], 41) == true)
						return (size_t)info.BaseAddress;
				}
			}
			p += info.RegionSize;
		}
	}
	vec->clear();
	return 0;
}

DWORD GetPid(const char* ProcessName) {
	PROCESSENTRY32 entry;
	HANDLE hsnapshot;
	BOOL ret;

	hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE) {
		printf("GetPid: CreateToolhelp32Snapshot fail.\n");
		system("PAUSE");
		exit(EXIT_FAILURE);
	}

	entry.dwSize = sizeof(PROCESSENTRY32);
	ret = Process32First(hsnapshot, &entry);
	while (ret) {
		if (!stricmp(entry.szExeFile, ProcessName)) {
			CloseHandle(hsnapshot);
			return entry.th32ProcessID;
		}
		ret = Process32Next(hsnapshot, &entry);
	}
	CloseHandle(hsnapshot);
	return 0;
}
