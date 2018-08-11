#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <fstream>

# if defined(_MSC_VER)
# ifndef _CRT_SECURE_NO_DEPRECATE
# define _CRT_SECURE_NO_DEPRECATE (1)
# endif
# pragma warning(disable : 4996)
# endif

#define RO_EXE_NAME "Ragexe.exe"
#define MAX_PACKET 0x1000
#define MAX_SHUFFLE_PACKET 29
#define MAX_SYNC_EX_PACKET 84
#define EXIT(msg, ...) \
	do { \
		printf((msg), ##__VA_ARGS__); \
		cout << "Press ENTER to exit..."; \
		cin.ignore((numeric_limits<streamsize>::max)(), '\n'); \
		exit(EXIT_FAILURE); \
	} while (false)

using namespace std;

DWORD GetPid(const char* ProcessName);
size_t ReadSessionMemory(HANDLE process, vector<char> *vec);
size_t ScanMem(vector<char> *vec, const char *data, size_t start, size_t end, size_t len, bool backwards);
char MonthName2Num(const char *name);

#define ReadMemory(addr) vec[(addr)]
int main(void) {
	vector<char> vec;
	DWORD pid;
	HANDLE process;
	int i, c;
	short pktlen[MAX_PACKET] = { 0 };
	WORD shuffle_pkt[MAX_SHUFFLE_PACKET + (MAX_SYNC_EX_PACKET << 1)] = { 0 };
	size_t session_base_addr, offset, offset2, refOffset, ret, pktcall1, pktcall2, last, next;
	byte g_PacketLenMap[] = "\x0\x0\x0\x0\x0\xE8\xAB\xAB\xAB\xAB\x68\xAB\xAB\xAB\x00\xE8\xAB\xAB\xAB\xAB\x59\xC3";
	unsigned int ClientDate;
	ofstream file;
	char str[128];

	while (!(pid = GetPid(RO_EXE_NAME))) {
		cout << "Please run RO clinet." << endl << "Press ENTER to continue...";
		cin.ignore((numeric_limits<streamsize>::max)(), '\n');
	}

	if (!(process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid)))
		EXIT("OpenProcess failed.\n");



	printf("Step 1 - Read process memory to vector\n");
	if (!(session_base_addr = ReadSessionMemory(process, &vec)))
		EXIT("Read memory failed.\n");
	printf("Done.\n");

	//printf("Step 2a - Find the position of rijndael encryption function\n");
	//if ((refOffset = ScanMem(&vec, "\x8B\x8B\xD0\x03\x00\x00\x8B\x83\xC8\x03\x00\x00\x41\x0F\xAF\xCE\x99", 0, 0, 17, false)) == 0xFFFFFFFF)
	//	EXIT("No rijndael encryption found.\n");
	//printf("Address: %08X (raw: %08X)\n", session_base_addr + refOffset - 1, refOffset - 1);

	//printf("Step 2b - Find the entry address of rijndael encryption function\n");
	//if ((refOffset = ScanMem(&vec, "\x55\x8B\xEC\x83\xEC\x18", 0, refOffset, 6, true)) == 0xFFFFFFFF)
	//	EXIT("No rijndael encryption found.\n");
	//offset = session_base_addr + refOffset;
	//printf("Address: %08X (raw: %08X)\n", session_base_addr + refOffset, refOffset);

	//printf("Step 2c - Find the source of function call\n");
	//char searchValue[4];
	//searchValue[0] = offset & 0xFF;
	//searchValue[1] = (offset >> 8) & 0xFF;
	//searchValue[2] = (offset >> 16) & 0xFF;
	//searchValue[3] = (offset >> 24) & 0xFF;
	//if ((refOffset = ScanMem(&vec, searchValue, 0, 0, 4, false)) == 0xFFFFFFFF)
	//	EXIT("No rijndael encryption found.\n");
	//printf("Address: %08X\n", session_base_addr + refOffset);

	//printf("Step 2d - Find the call function of first key\n");
	//if ((refOffset = ScanMem(&vec, "\x8D\x93", refOffset + 1, 0, 2, false)) == 0xFFFFFFFF)
	//	EXIT("No rijndael encryption found.\n");
	//printf("Address: %08X\n", session_base_addr + refOffset - 1);
	//printf("Key EBP Offset: %08X\n", session_base_addr + refOffset - 1);

	////*(DWORD*)&ReadMemory(offset + 3)

	printf("Step 2a - Find the GetPacketSize function call\n");
	if ((refOffset = ScanMem(&vec, "\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x50\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x6A\x01\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x6A\x06", 0, 0, 41, false)) == 0xFFFFFFFF)
		EXIT("GetPacketSize function call not found.\n");
	printf("Address: %08X\n", session_base_addr + refOffset - 1);

	printf("Step 2b - Go Inside the GetPacketSize function\n");
	offset = refOffset + *(DWORD*)&ReadMemory(refOffset + 8) + 12;
	printf("Address: %08X\n", session_base_addr + offset);

	printf("Step 2c - Look for g_PacketLenMap reference and the pktLen function call following it\n");
	if ((offset = ScanMem(&vec, "\xB9\xAB\xAB\xAB\x00\xE8\xAB\xAB\xAB\xAB\x8B\xAB\x04", offset, 0, 13, false)) == 0xFFFFFFFF)
// TODO : for New client = offset === -1 "\xB9\xAB\xAB\xAB\x01\xE8\xAB\xAB\xAB\xAB\x8B\xAB\x04"	 [4144]	
		EXIT("g_PacketLenMap reference not found.\n");
	printf("Address: %08X\n", session_base_addr + offset);

	printf("Step 2d - Extract the g_PacketLenMap assignment\n");
	memcpy(g_PacketLenMap, &ReadMemory(offset), 5);
	printf("g_PacketLenMap reference: %02X:%02X:%02X:%02X:%02X\n", g_PacketLenMap[0], g_PacketLenMap[1], g_PacketLenMap[2], g_PacketLenMap[3], g_PacketLenMap[4]);

	printf("Step 3a - Find the InitPacketMap function call using g_PacketLenMap\n");
	if ((offset = ScanMem(&vec, (char*)g_PacketLenMap, 0, 0, 22, false)) == 0xFFFFFFFF)
		EXIT("InitPacketMap function call not found.\n");
	printf("Address: %08X\n", session_base_addr + offset + 5);

	printf("Step 3b - Go inside InitPacketMap\n");
	offset += *(DWORD*)&ReadMemory(offset + 6) + 10;
	printf("Address: %08X\n", session_base_addr + offset);

	printf("Step 3c - Look for InitPacketLenWithClient call\n");
	if ((offset = ScanMem(&vec, "\x8B\xCE\xE8\xAB\xAB\xAB\xAB\xC7", offset, 0, 8, false)) == 0xFFFFFFFF)
		EXIT("InitPacketLenWithClient call not found.\n");
	printf("Address: %08X\n", session_base_addr + offset + 2);

	printf("Step 3d - Go inside InitPacketLenWithClient\n");
	offset += *(DWORD*)&ReadMemory(offset + 3) + 7;
	printf("Address: %08X\n", session_base_addr + offset);

	printf("Step 4a - Look for the first call\n");
	if ((offset = ScanMem(&vec, "\x8B\xF1\xE8\xAB\xAB\xAB\xAB", offset, 0, 7, false)) == 0xFFFFFFFF)
		EXIT("InitPacketLenWithClient call not found.\n");
	printf("Address: %08X\n", session_base_addr + offset + 2);

	printf("Step 4b - Go inside\n");
	offset2 = offset + *(DWORD*)&ReadMemory(offset + 3) + 7;
	printf("Address: %08X\n", session_base_addr + offset2);

	printf("Step 4c - Look for ret\n");
	if ((ret = ScanMem(&vec, "\xC3\xCC", offset2, 0, 2, false)) == 0xFFFFFFFF)
		EXIT("InitPacketLenWithClient call not found.\n");
	printf("Address: %08X\n", session_base_addr + ret);

	printf("Step 4d - Look for call pattern 1\n");
	if ((pktcall1 = ScanMem(&vec, "\x6A\xAB\x6A\xAB\x6A\xAB\x68\xAB\xAB\x00\x00\x8B\xCE\xE8", offset2, ret, 14, false)) == 0xFFFFFFFF)
		EXIT("call pattern 1 not found.\n");
	pktcall1 += *(DWORD*)&ReadMemory(pktcall1 + 14) + 18;
	printf("Pattern 1: %08X\n", session_base_addr + pktcall1);

	printf("Step 4e - Look for call pattern 2\n");
	if ((pktcall2 = ScanMem(&vec, "\xC7\x45\xAB\xAB\xAB\x00\x00\xC7\x45\xAB\xAB\xAB\xAB\xAB\xC7\x45\xAB\xAB\xAB\xAB\xAB\xC7\x45\xAB\xAB\x00\x00\x00\xE8", offset2, ret, 29, false)) == 0xFFFFFFFF)
		EXIT("call pattern 2 not found.\n");
	pktcall2 += *(DWORD*)&ReadMemory(pktcall2 + 29) + 33;
	printf("Pattern 2: %08X\n", session_base_addr + pktcall2);

	printf("Step 5a - Get Client date\n");
	if ((next = ScanMem(&vec, "mylog(\xAB\xAB\xAB \xAB\xAB \xAB\xAB\xAB\xAB).txt", 0, 0, 22, false)) == 0xFFFFFFFF) {
		printf("Client date not found.\n");
		ClientDate = 2016;
	} else {
		sprintf(str, "%.4s%02d%02d", &ReadMemory(next + 13), MonthName2Num(&ReadMemory(next + 6)), atoi(&ReadMemory(next + 10)));
		ClientDate = atoi(str);
		printf("Client date: %d\n", ClientDate);
	}

	printf("Step 5b - Extract packet length\n");
	for (i = c = 0; i < 2; ++i) {
		if (!i)
			last = offset2;
		else {
			last = offset;
			if ((ret = ScanMem(&vec, "\xC3\xCC", offset, 0, 2, false)) == 0xFFFFFFFF)
				EXIT("ret not found.\n");
		}
		for (; (next = ScanMem(&vec, "\xE8\xAB\xAB\xFF\xFF", last, ret, 5, false)) != 0xFFFFFFFF; last = next) {
			WORD header = 0;
			short len = 0;
			size_t calltype = next + *(DWORD*)&ReadMemory(++next) + 4;
			if (calltype != pktcall1 && calltype != pktcall2)
				continue;
			if (calltype == pktcall1) {
				if (ReadMemory(next - 5) == 0x6A) {
					header = ReadMemory(next - 4);
					offset2 = next - 5;
				}
				else {
					if (ReadMemory(next - 8) != 0x68)
						EXIT("pattern 1 header not found.\n");
					header = *(WORD*)&ReadMemory(next - 7);
					offset2 = next - 8;
				}
				if (ReadMemory(offset2 - 2) == 0x6A) {
					len = ReadMemory(offset2 - 1);
					if (len == 0xFF)
						len = -1;
				}
				else {
					if (ReadMemory(offset2 - 5) != 0x68)
						EXIT("pattern 1 len not found.\n");
					len = *(short*)&ReadMemory(offset2 - 4);
				}
			}
			else {
				if ((offset2 = ScanMem(&vec, "\xC7\x45\xAB\xAB\xAB\x00\x00", last, next, 7, false)) == 0xFFFFFFFF)
					EXIT("pattern 2 header not found.\n");
				header = *(WORD*)&ReadMemory(offset2 + 3);
				if ((offset2 = ScanMem(&vec, "\xC7\x45", offset2 + 1, next, 2, false)) == 0xFFFFFFFF)
					EXIT("pattern 2 len not found.\n");
				len = *(short*)&ReadMemory(offset2 + 3);
			}
			if (!pktlen[header]) {
				pktlen[header] = len;
			}
			if (!i && c < MAX_SHUFFLE_PACKET + (MAX_SYNC_EX_PACKET << 1))
				shuffle_pkt[c++] = header;
		}
	}

	printf("Step 6 - Key Extraction\n");
	file.open("keys.txt");
	sprintf(str, "# Client Date <%d>\n", ClientDate);
	file << str;
	sprintf(str, "# PacketExtractor by BryanWai\n");
	file << str;
	if ((offset = ScanMem(&vec, "\x8B\x0D\xAB\xAB\xAB\x00\x6A\x01\xE8", refOffset, 0, 9, false)) == 0xFFFFFFFF)
// For New client offset === -1 \x8B\x0D\xAB\xAB\xAB\x01\x6A\x01\xE8 [4144]	
		EXIT("Packet keys not found.\n");
	printf("Key function address: %08X\n", offset);
	offset += *(DWORD*)&ReadMemory(offset + 9);
	if ((offset = ScanMem(&vec, "\xC7\x41\xAB\xAB\xAB\xAB\xAB\xC7\x41\xAB\xAB\xAB\xAB\xAB\xC7\x41", offset, 0, 16, false)) == 0xFFFFFFFF)
		EXIT("Packet keys not found.\n");
	printf("Key function address: %08X\n", offset);
	sprintf(str, "0x%08X\n", *(DWORD*)&ReadMemory(offset + 3));
	file << str;
	sprintf(str, "0x%08X\n", *(DWORD*)&ReadMemory(offset + 17));
	file << str;
	sprintf(str, "0x%08X\n", *(DWORD*)&ReadMemory(offset + 10));
	file << str;

	file.close();

	file.open("recvpackets.txt");
	sprintf(str, "# Client Date <%d>\n", ClientDate);
	file << str;
	sprintf(str, "# PacketExtractor by BryanWai\n");
	file << str;
	for (i = c = 0; i < MAX_PACKET; ++i) {
		if (pktlen[i]) {
			sprintf(str, "%04X %d\n", i, pktlen[i]);
			file << str;
			++c;
		}
	}
	file.close();
	printf("Total Packets: %d\n", c);

	file.open("sync.txt");
	sprintf(str, "# Client Date <%d>\n", ClientDate);
	file << str;
	sprintf(str, "# PacketExtractor by BryanWai\n");
	file << str;
	for (i = MAX_SHUFFLE_PACKET; i < MAX_SHUFFLE_PACKET + MAX_SYNC_EX_PACKET; ++i) {
		if (!shuffle_pkt[i + MAX_SYNC_EX_PACKET])
			EXIT("Cannot generate sync.txt: sync_ex_reply header not found.\n");
		if (pktlen[shuffle_pkt[i]] != 2)
			EXIT("Cannot generate sync.txt: sync_ex_reply len not match.\n");
		sprintf(str, "%04X %04X\n", shuffle_pkt[i], shuffle_pkt[i + MAX_SYNC_EX_PACKET]);
		file << str;
	}
	file.close();

	{
		const char* func[] =
		{
			(char*)("0089 actor_action"),
			(char*)("0113 skill_use"),
			(char*)("0085 character_move"),
			(char*)("007E sync"),
			(char*)("009B actor_look_at"),
			(char*)("009F item_take"),
			(char*)("00A2 item_drop"),
			(char*)("00F3 storage_item_add"),
			(char*)("00F5 storage_item_remove"),
			(char*)("0116 skill_use_location"),
			(char*)(""),
			(char*)("0094 actor_info_request"),
			(char*)("0193 actor_name_request"),
			(char*)(""),
			(char*)(""),
			(char*)(""),
			(char*)("0819 buy_bulk_buyer"),
			(char*)("0817 buy_bulk_request"),
			(char*)("0815 buy_bulk_closeShop"),
			(char*)("0811 buy_bulk_openShop"),
			(char*)("0802 booking_register"),
			(char*)(""),
			(char*)(""),
			(char*)("0072 map_login"),
			(char*)("02C4 party_join_request_by_name"),
			(char*)(""),
			(char*)("0202 friend_request"),
			(char*)("022D homunculus_command"),
			(char*)("023B storage_password"),
		};
		file.open("shuffles.txt");
		sprintf(str, "# Client Date <%d>\n", ClientDate);
		file << str;
		sprintf(str, "# PacketExtractor by BryanWai\n");
		file << str;
		for (i = 0; i < MAX_SHUFFLE_PACKET; ++i) {
			if (!shuffle_pkt[i])
				EXIT("Cannot generate openkore: shuffle_pkt header not found.\n");
			switch (i) {
			case 10: case 13: case 14:
			case 15: case 21: case 22:
			case 25:
				continue;
			default:
				sprintf(str, "%04X %s\n", shuffle_pkt[i], func[i]); break;
			}
			file << str;
		}
		file.close();
	}
	printf("Done!\n");

	cout << "Press ENTER to exit...";
	cin.ignore((numeric_limits<streamsize>::max)(), '\n');
	return 0;
}
#undef ReadMemory

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
	if (hsnapshot == INVALID_HANDLE_VALUE)
		EXIT("GetPid: CreateToolhelp32Snapshot fail.\n");

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

char MonthName2Num(const char *name) {
	switch (*name) {
	case 'J':
		if (*(name + 1) == 'a')
			return 1;
		else if (*(name + 2) == 'n')
			return 6;
		else
			return 7;
	case 'F':
		return 2;
	case 'M':
		if (*(name + 2) == 'r')
			return 3;
		else
			return 5;
	case 'A':
		if (*(name + 1) == 'p')
			return 4;
		else
			return 8;
	case 'S':
		return 9;
	case 'O':
		return 10;
	case 'N':
		return 11;
	case 'D':
		return 12;
	}
	return 0;
}
