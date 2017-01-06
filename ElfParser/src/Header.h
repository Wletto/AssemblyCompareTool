#ifndef __ELF_PARSER_H__
#define __ELF_PARSER_H__

#define DLL_EXPORT

#if defined DLL_EXPORT
#define DECLDIR __declspec(dllexport)
#else
#define DECLDIR __declspec(dllimport)
#endif

#define WINAPI      __stdcall

extern "C"
{
	DECLDIR int WINAPI ParseElf(char * base);
}


#endif
