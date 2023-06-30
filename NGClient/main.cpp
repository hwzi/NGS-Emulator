#ifdef UNICODE
#undef UNICODE
#endif

#ifdef _UNICODE
#undef _UNICODE
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <Windows.h>
#include <iostream>

#include "ngs_heartbeat.hpp"
#include "ngs_buffer.hpp"
#include "ngs_files.hpp"

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

typedef void (__stdcall* NGSSendCallback_t)(void* buffer, unsigned int size);
static NGSSendCallback_t ngs_send_callback = nullptr;

typedef struct NGClient_internals
{
	void* control;	// NGClient.aes+3320
	void* f1;		// 
} NGClient_internals;

typedef struct BlackCall_internals
{
	NGClient_internals* ngclient;
	void* f1;		// BlackCall.aes+10E30
	void* f2;		// BlackCall.aes+11540
	void* f3;		// BlackCall.aes+115A0
	void* f4;		// BlackCall.aes+115E0
	void* module;	// BlackCall.aes
} BlackCall_internals;

__declspec(naked) int __stdcall BlackCall_ret()
{
	__asm xor eax,eax
	__asm ret
}

__declspec(naked) int __stdcall NGClient_ret()
{
	__asm xor eax,eax
	__asm ret 0x0004
}

void __fastcall NGClient_Control(void* ecx, void* edx, unsigned char* buffer, unsigned int size)
{
	static ngs::heartbeat emulator;

	ngs::buffer::request request(buffer, size);
	ngs::buffer::response response;

	if (emulator.make_response(request, response))
		ngs_send_callback(&response, response.get_length());
}

int __stdcall NGClient_Start(NGSSendCallback_t NGSSendCallback, BlackCall_internals** pNGSClient, BOOL bSplash)
{
	ngs_send_callback = NGSSendCallback;
	
	static NGClient_internals ngclient = 
	{
		NGClient_Control,
		NGClient_ret							// NGClient.aes+11E0
	};

	static BlackCall_internals blackcall = 
	{
		&ngclient,
		BlackCall_ret,							// BlackCall.aes+10E30
		BlackCall_ret,							// BlackCall.aes+11540
		BlackCall_ret,							// BlackCall.aes+115A0
		BlackCall_ret,							// BlackCall.aes+115E0
		reinterpret_cast<void*>(&__ImageBase)	// BlackCall.aes
	};

	if (pNGSClient)
		*pNGSClient = &blackcall;
	
	return 0;
}

int __stdcall NGClient_Stop()
{
	return 0;
}

int __stdcall NGClient_Ordinal3()
{
	return 0;
}

int __stdcall NGClient_Ordinal4()
{
	return 0;
}

int __stdcall NGClient_Ordinal5()
{
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, void* lpvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		srand(GetTickCount());
		ngs::files::initialize();
	}

	return TRUE;
}