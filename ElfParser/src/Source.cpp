#include <iostream>  
#include <string.h>  
#include <stdio.h>  
#include "elf.h"  
#include "Header.h"

/**
非常重要的一个宏，功能很简单：
P:需要对其的段地址
ALIGNBYTES:对其的字节数
功能：将P值补充到时ALIGNBYTES的整数倍
这个函数也叫：页面对其函数
eg: 0x3e45/0x1000 == >0x4000

*/
using namespace std;

#define ALIGN(P, ALIGNBYTES)  ( ((unsigned long)P + ALIGNBYTES -1)&~(ALIGNBYTES-1) )  

int ElfParse(char * sElfPath, char ** pOut);

// int main()
// {
// 	int iSize1 = 0;
// 	int iSize2 = 0;
// 	char *p1, *p2;
// 
// 	iSize1 = ElfParse("E:\\MyPrj\\增量so\\libs_ls_batadjcashflow_1.so", &p2);
// 	iSize2 = ElfParse("E:\\MyPrj\\增量so\\libs_ls_batadjcashflow.so", &p1);
// 
// 	if (iSize1 != iSize2)
// 	{
// 		free(p1);
// 		free(p2);
// 		return 1;
// 	}
// 
// 	for (int i = 0; i < iSize1; i++)
// 	{
// 		if (p1[i] != p2[i])
// 		{
// 			free(p1);
// 			free(p2);
// 			return 1;
// 		}
// 	}
// 
// 	free(p1);
// 	free(p2);
// 	return 0;
// }



static uint32_t ParseStrTab(char * base, Elf64_Shdr * s_hdr_strtab, char * tgtsecName)
{
	uint32_t i = 0;
	uint32_t iStart = 1;
	uint32_t j = 0;
	char * p = base + s_hdr_strtab->sh_offset;
	char sTemp[256] = { 0 };
	for (i = 1; i < s_hdr_strtab->sh_size; i++)
	{
		if (p[i] == 0)
		{
			sTemp[j] = 0;
			j = 0;
			if (!strcmp(sTemp, tgtsecName))
			{
				return iStart;
			}
			iStart = i + 1;
		}
		else
		{
			sTemp[j] = p[i];
			j++;
		}
	}

	return 0;
}

 // 替换为0
static void DoFilter(void * addr, uint64_t len, unsigned char val)//过滤
{
	memset(addr, val, len);
}

//这里的处理逻辑,就是先根据.shstrtab里的内容,知道名称为'.strtab'和'.symtab'这2个字符串的数字id是什么(由于名称是个可变的,因此elf里设计成了在具体结构中使用名称的数字id,然后建一个数据字段,对应各个字符串和数字id)
//然后根据.strtab,找到名称'GetBizFunctionsInfo'的数字id是多少
//再根据'GetBizFunctionsInfo'的数字id去.symtab找到描述'GetBizFunctionsInfo'的结构体,取到其中的函数偏移和长度,将其全部用0覆写掉即可
DECLDIR int WINAPI ParseElf(char * base)
{
	// elf 头部结 构体体
	Elf64_Ehdr *ehdr;
	//程序头部表 结构体
	Elf64_Phdr *t_phdr;
	// 节区头部表 结构体
	Elf64_Shdr *s_hdr;
	Elf64_Shdr * local_hdr, *p;

	ehdr = (Elf64_Ehdr*)base;
	t_phdr = (Elf64_Phdr*)(base + sizeof(Elf64_Ehdr));
	//section header  
	s_hdr = (Elf64_Shdr*)(base + ehdr->e_shoff);
	local_hdr = (Elf64_Shdr*)malloc((ehdr->e_shnum)*sizeof(Elf64_Shdr));
	if (local_hdr == NULL)
	{
		return -1;
	}

	p = local_hdr;
	uint32_t symtabnmidx = 0;
	uint32_t strtabnmidx = 0;
	uint32_t GetBiznmidx = 0;
	int rechdrcnt = 0;
	uint32_t iTempRet = 0;
	int i = 0;
	uint64_t secoffset = 0;

	for (i = 0; i < ehdr->e_shnum; i++)
	{
		secoffset = s_hdr->sh_offset;
		//SHT_STRTAB  此节区包含字符串表。目标文件可能包含多个字符串表节区。
		if (s_hdr->sh_type == SHT_STRTAB)
		{//有3个SHT_STRTAB类型的,一个是.dynstr,还一个是.strtab,.shstrtab	
		 //由于无法在一开始就定位到具体哪个SHT_STRTAB是.shstrtab,所以遇到一个SHT_STRTAB类型的,我们就遍历找找看是否有.symtab和.strtab的数据字典项
			if (symtabnmidx == 0)
			{
				iTempRet = ParseStrTab(base, s_hdr, ".symtab");
				if (iTempRet != 0)
				{
					symtabnmidx = iTempRet;
				}
			}

			if (strtabnmidx == 0)
			{
				iTempRet = ParseStrTab(base, s_hdr, ".strtab");
				if (iTempRet != 0)
				{
					strtabnmidx = iTempRet;
				}
			}
		}

		if (s_hdr->sh_type == SHT_NOTE) //note不做比较,直接用0覆盖掉
		{
			DoFilter((void*)(base + s_hdr->sh_offset), s_hdr->sh_size, 0);
		}
		else
		{//将所有的Section Head结构体复制到本地的结构体数组中
			memcpy((void*)p, s_hdr, sizeof(Elf64_Shdr));
			p++;
			rechdrcnt++;
		}

		s_hdr++;
	}

	if (symtabnmidx == 0)
	{
		free(local_hdr);
		return -2;
	}


	if (strtabnmidx == 0)
	{
		free(local_hdr);
		return -3;
	}

	// 符号表结构体
	Elf64_Sym * q;
	int symhdridx = 0;
	int strhdridx = 0;
	for (i = 0; i < rechdrcnt; i++)
	{//遍历本地Section Head结构体数组,比较其Section Name(数字id),是否与.shstrtab定义的名称映射数字id相等
		if (local_hdr[i].sh_name == symtabnmidx)
		{//记录下.symtab在本地Section Head结构体数组中的下标
			symhdridx = i;
		}
		else if (local_hdr[i].sh_name == strtabnmidx)
		{//记录下.strtab在本地Section Head结构体数组中的下标
			strhdridx = i;
		}
	}

	//从.strtab中获取GetBizFunctionsInfo的对应数字id
	GetBiznmidx = ParseStrTab(base, &local_hdr[strhdridx], "GetBizFunctionsInfo");
	if (GetBiznmidx == 0)
	{
		free(local_hdr);
		return -4;
	}

	uint64_t symcnt = local_hdr[symhdridx].sh_size / local_hdr[symhdridx].sh_entsize;
	for (uint64_t j = 0; j < symcnt; j++)
	{//遍历.symtab,找到结构体的st_name字段值为GetBizFunctionsInfo对应数字id的结构体,获取其便宜和长度,然后替换为0
		q = (Elf64_Sym *)(base + local_hdr[symhdridx].sh_offset + j*local_hdr[symhdridx].sh_entsize);
		if (q->st_name == GetBiznmidx)
		{
			DoFilter((void*)(base + q->st_value), q->st_size, 0);
			break;
		}
	}
	free(local_hdr);

	return 0;
} 

