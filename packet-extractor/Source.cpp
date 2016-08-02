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

#define RO_EXE_NAME "ragexe.exe"
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

	printf("Step 2a - Find the GetPacketSize function call\n");
	if ((refOffset = ScanMem(&vec, "\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x50\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x6A\x01\xE8\xAB\xAB\xAB\xAB\x8B\xC8\xE8\xAB\xAB\xAB\xAB\x6A\x06", 0, 0, 41, false)) == 0xFFFFFFFF)
		EXIT("GetPacketSize function call not found.\n");
	printf("Address: %08X\n", session_base_addr + refOffset - 1);

	printf("Step 2b - Go Inside the GetPacketSize function\n");
	offset = refOffset + *(DWORD*)&ReadMemory(refOffset + 8) + 12;
	printf("Address: %08X\n", session_base_addr + offset);

	printf("Step 2c - Look for g_PacketLenMap reference and the pktLen function call following it\n");
	if ((offset = ScanMem(&vec, "\xB9\xAB\xAB\xAB\x00\xE8\xAB\xAB\xAB\xAB\x8B\xAB\x04", offset, 0, 13, false)) == 0xFFFFFFFF)
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
	if ((next = ScanMem(&vec, "mylog(\xAB\xAB\xAB \xAB\xAB \xAB\xAB\xAB\xAB).txt", 0, 0, 22, false)) == 0xFFFFFFFF)
		EXIT("Client date not found.\n");
	sprintf(str, "%.4s%02d%02d", &ReadMemory(next + 13), MonthName2Num(&ReadMemory(next + 6)), atoi(&ReadMemory(next + 10)));
	ClientDate = atoi(str);
	printf("Client date: %d\n", ClientDate);

	printf("Step 5b - Extract packet length\n");
	sprintf(str, "PacketLengths_%d.ini", ClientDate);
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
				sprintf(str, "0x%04X = %d\n", header, len);
				file << str;
			}
			if (!i && c < MAX_SHUFFLE_PACKET + (MAX_SYNC_EX_PACKET << 1))
				shuffle_pkt[c++] = header;
		}
	}

	file << "\n[Packet_Keys]\n";
	if ((offset = ScanMem(&vec, "\x8B\x0D\xAB\xAB\xAB\x00\x6A\x01\xE8", refOffset, 0, 9, false)) == 0xFFFFFFFF)
		EXIT("Packet keys not found.\n");
	offset += *(DWORD*)&ReadMemory(offset + 9);
	if ((offset = ScanMem(&vec, "\xC7\x41\xAB\xAB\xAB\xAB\xAB\xC7\x41\xAB\xAB\xAB\xAB\xAB\xC7\x41", offset, 0, 16, false)) == 0xFFFFFFFF)
		EXIT("Packet keys not found.\n");
	sprintf(str, "1 = 0x%08X\n", *(DWORD*)&ReadMemory(offset + 3));
	file << str;
	sprintf(str, "2 = 0x%08X\n", *(DWORD*)&ReadMemory(offset + 10));
	file << str;
	sprintf(str, "3 = 0x%08X\n", *(DWORD*)&ReadMemory(offset + 17));
	file << str;

	file << "\n[Shuffle_Packets]\n";
	for (i = 0; i < MAX_SHUFFLE_PACKET; ++i) {
		sprintf(str, "0x%04X = %d\n", shuffle_pkt[i], i);
		file << str;
	}

	file.close();

	sprintf(str, "recvpackets_%d.txt", ClientDate);
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

	sprintf(str, "openkore_%d.txt", ClientDate);
	file.open(str);
	file << "[Receive]\n";
	for (i = MAX_SHUFFLE_PACKET; i < MAX_SHUFFLE_PACKET + MAX_SYNC_EX_PACKET; ++i) {
		if (!shuffle_pkt[i])
			EXIT("Cannot generate openkore: sync_request_ex header not found.\n");
		if (pktlen[shuffle_pkt[i]] != 2)
			EXIT("Cannot generate openkore: sync_request_ex len not match.\n");
		sprintf(str, "\t\t'%04X' => ['sync_request_ex'],\n", shuffle_pkt[i]);
		file << str;
	}
	file << "\n";
	for (i = MAX_SHUFFLE_PACKET; i < MAX_SHUFFLE_PACKET + MAX_SYNC_EX_PACKET; ++i) {
		if (!shuffle_pkt[i + MAX_SYNC_EX_PACKET])
			EXIT("Cannot generate openkore: sync_ex_reply header not found.\n");
		if (pktlen[shuffle_pkt[i]] != 2)
			EXIT("Cannot generate openkore: sync_ex_reply len not match.\n");
		sprintf(str, "\t\t'%04X' => '%04X',\n", shuffle_pkt[i], shuffle_pkt[i + MAX_SYNC_EX_PACKET]);
		file << str;
	}
	file << "\n\n[Send]\n";
	{
		short shuffle_pkt_len[MAX_SHUFFLE_PACKET] = { 7, 10, 5, 6, 5, 6, 6, 8, 8, 10, 90, 6, 6, 12, 2, -1, -1, 6, 2, -1, 18, 8, -1, 19, 26, 4, 26, 5, 36 };
		for (i = 0; i < MAX_SHUFFLE_PACKET; ++i) {
			if (!shuffle_pkt[i])
				EXIT("Cannot generate openkore: shuffle_pkt header not found.\n");
			if (pktlen[shuffle_pkt[i]] != shuffle_pkt_len[i])
				EXIT("Cannot generate openkore: shuffle_pkt len not match.\n");
			switch (i) {
			case 0:
				sprintf(str, "\t\t'%04X' => ['actor_action', 'a4 C', [qw(targetID type)]],\n", shuffle_pkt[i]); break;
			case 1:
				sprintf(str, "\t\t'%04X' => ['skill_use', 'v2 a4', [qw(lv skillID targetID)]],\n", shuffle_pkt[i]); break;
			case 2:
				sprintf(str, "\t\t'%04X' => ['character_move','a3', [qw(coords)]],\n", shuffle_pkt[i]); break;
			case 3:
				sprintf(str, "\t\t'%04X' => ['sync', 'V', [qw(time)]],\n", shuffle_pkt[i]); break;
			case 4:
				sprintf(str, "\t\t'%04X' => ['actor_look_at', 'v C', [qw(head body)]],\n", shuffle_pkt[i]); break;
			case 5:
				sprintf(str, "\t\t'%04X' => ['item_take', 'a4', [qw(ID)]],\n", shuffle_pkt[i]); break;
			case 6:
				sprintf(str, "\t\t'%04X' => ['item_drop', 'v2', [qw(index amount)]],\n", shuffle_pkt[i]); break;
			case 7:
				sprintf(str, "\t\t'%04X' => ['storage_item_add', 'v V', [qw(index amount)]],\n", shuffle_pkt[i]); break;
			case 8:
				sprintf(str, "\t\t'%04X' => ['storage_item_remove', 'v V', [qw(index amount)]],\n", shuffle_pkt[i]); break;
			case 9:
				sprintf(str, "\t\t'%04X' => ['skill_use_location', 'v4', [qw(lv skillID x y)]],\n", shuffle_pkt[i]); break;
			case 10:
				sprintf(str, "\t\t#PACKET_CZ_USE_SKILL_TOGROUND_WITHTALKBOX2\n"); break;
			case 11:
				sprintf(str, "\t\t'%04X' => ['actor_info_request', 'a4', [qw(ID)]],\n", shuffle_pkt[i]); break;
			case 12:
				sprintf(str, "\t\t'%04X' => ['actor_name_request', 'a4', [qw(ID)]],\n", shuffle_pkt[i]); break;
			case 13:
				sprintf(str, "\t\t#PACKET_CZ_SSILIST_ITEM_CLICK\n"); break;
			case 14:
				sprintf(str, "\t\t#PACKET_CZ_SEARCH_STORE_INFO_NEXT_PAGE\n"); break;
			case 15:
				sprintf(str, "\t\t#PACKET_CZ_SEARCH_STORE_INFO\n"); break;
			case 16:
				sprintf(str, "\t\t'%04X' => ['buy_bulk_buyer', 'a4 a4 a*', [qw(buyerID buyingStoreID itemInfo)]],\n", shuffle_pkt[i]); break;
			case 17:
				sprintf(str, "\t\t'%04X' => ['buy_bulk_request', 'a4', [qw(ID)]],\n", shuffle_pkt[i]); break;
			case 18:
				sprintf(str, "\t\t'%04X' => ['buy_bulk_closeShop'],\n", shuffle_pkt[i]); break;
			case 19:
				sprintf(str, "\t\t'%04X' => ['buy_bulk_openShop', 'a4 c a*', [qw(limitZeny result itemInfo)]],\n", shuffle_pkt[i]); break;
			case 20:
				sprintf(str, "\t\t'%04X' => ['booking_register', 'v8', [qw(level MapID job0 job1 job2 job3 job4 job5)]],\n", shuffle_pkt[i]); break;
			case 21:
				sprintf(str, "\t\t#PACKET_CZ_JOIN_BATTLE_FIELD\n"); break;
			case 22:
				sprintf(str, "\t\t#PACKET_CZ_ITEMLISTWIN_RES\n"); break;
			case 23:
				sprintf(str, "\t\t'%04X' => ['map_login', 'a4 a4 a4 V C', [qw(accountID charID sessionID tick sex)]],\n", shuffle_pkt[i]); break;
			case 24:
				sprintf(str, "\t\t'%04X' => ['party_join_request_by_name', 'Z24', [qw(partyName)]],\n", shuffle_pkt[i]); break;
			case 25:
				sprintf(str, "\t\t#PACKET_CZ_GANGSI_RANK\n"); break;
			case 26:
				sprintf(str, "\t\t'%04X' => ['friend_request', 'a*', [qw(username)]],\n", shuffle_pkt[i]); break;
			case 27:
				sprintf(str, "\t\t'%04X' => ['homunculus_command', 'v C', [qw(commandType, commandID)]],\n", shuffle_pkt[i]); break;
			case 28:
				sprintf(str, "\t\t'%04X' => ['storage_password'],\n", shuffle_pkt[i]); break;
			}
			file << str;
		}
		file << "\n";
		for (i = 0; i < MAX_SHUFFLE_PACKET; ++i) {
			switch (i) {
			case 0:
				sprintf(str, "\t\tactor_action %04X\n", shuffle_pkt[i]); break;
			case 1:
				sprintf(str, "\t\tskill_use %04X\n", shuffle_pkt[i]); break;
			case 2:
				sprintf(str, "\t\tcharacter_move %04X\n", shuffle_pkt[i]); break;
			case 3:
				sprintf(str, "\t\tsync %04X\n", shuffle_pkt[i]); break;
			case 4:
				sprintf(str, "\t\tactor_look_at %04X\n", shuffle_pkt[i]); break;
			case 5:
				sprintf(str, "\t\titem_take %04X\n", shuffle_pkt[i]); break;
			case 6:
				sprintf(str, "\t\titem_drop %04X\n", shuffle_pkt[i]); break;
			case 7:
				sprintf(str, "\t\tstorage_item_add %04X\n", shuffle_pkt[i]); break;
			case 8:
				sprintf(str, "\t\tstorage_item_remove %04X\n", shuffle_pkt[i]); break;
			case 9:
				sprintf(str, "\t\tskill_use_location %04X\n", shuffle_pkt[i]); break;
			case 10:
				continue;
			case 11:
				sprintf(str, "\t\tactor_info_request %04X\n", shuffle_pkt[i]); break;
			case 12:
				sprintf(str, "\t\tactor_name_request %04X\n", shuffle_pkt[i]); break;
			case 13:
				continue;
			case 14:
				continue;
			case 15:
				continue;
			case 16:
				sprintf(str, "\t\tbuy_bulk_buyer %04X\n", shuffle_pkt[i]); break;
			case 17:
				sprintf(str, "\t\tbuy_bulk_request %04X\n", shuffle_pkt[i]); break;
			case 18:
				sprintf(str, "\t\tbuy_bulk_closeShop %04X\n", shuffle_pkt[i]); break;
			case 19:
				sprintf(str, "\t\tbuy_bulk_openShop %04X\n", shuffle_pkt[i]); break;
			case 20:
				sprintf(str, "\t\tbooking_register %04X\n", shuffle_pkt[i]); break;
			case 21:
				continue;
			case 22:
				continue;
			case 23:
				sprintf(str, "\t\tmap_login %04X\n", shuffle_pkt[i]); break;
			case 24:
				sprintf(str, "\t\tparty_join_request_by_name %04X\n", shuffle_pkt[i]); break;
			case 25:
				continue;
			case 26:
				sprintf(str, "\t\tfriend_request %04X\n", shuffle_pkt[i]); break;
			case 27:
				sprintf(str, "\t\thomunculus_command %04X\n", shuffle_pkt[i]); break;
			case 28:
				sprintf(str, "\t\tstorage_password %04X\n", shuffle_pkt[i]); break;
			}
			file << str;
		}
		sprintf(str, "\n\t$self->cryptKeys(0x%08X, 0x%08X, 0x%08X);\n", *(DWORD*)&ReadMemory(offset + 3), *(DWORD*)&ReadMemory(offset + 17), *(DWORD*)&ReadMemory(offset + 10));
		file << str;
	}
	file.close();
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