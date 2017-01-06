#include <iostream>  
#include <string.h>  
#include <stdio.h>  
#include "elf.h"  
#include "Header.h"

/**
�ǳ���Ҫ��һ���꣬���ܼܺ򵥣�
P:��Ҫ����Ķε�ַ
ALIGNBYTES:������ֽ���
���ܣ���Pֵ���䵽ʱALIGNBYTES��������
�������Ҳ�У�ҳ����亯��
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
// 	iSize1 = ElfParse("E:\\MyPrj\\����so\\libs_ls_batadjcashflow_1.so", &p2);
// 	iSize2 = ElfParse("E:\\MyPrj\\����so\\libs_ls_batadjcashflow.so", &p1);
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

 // �滻Ϊ0
static void DoFilter(void * addr, uint64_t len, unsigned char val)//����
{
	memset(addr, val, len);
}

//����Ĵ����߼�,�����ȸ���.shstrtab�������,֪������Ϊ'.strtab'��'.symtab'��2���ַ���������id��ʲô(���������Ǹ��ɱ��,���elf����Ƴ����ھ���ṹ��ʹ�����Ƶ�����id,Ȼ��һ�������ֶ�,��Ӧ�����ַ���������id)
//Ȼ�����.strtab,�ҵ�����'GetBizFunctionsInfo'������id�Ƕ���
//�ٸ���'GetBizFunctionsInfo'������idȥ.symtab�ҵ�����'GetBizFunctionsInfo'�Ľṹ��,ȡ�����еĺ���ƫ�ƺͳ���,����ȫ����0��д������
DECLDIR int WINAPI ParseElf(char * base)
{
	// elf ͷ���� ������
	Elf64_Ehdr *ehdr;
	//����ͷ���� �ṹ��
	Elf64_Phdr *t_phdr;
	// ����ͷ���� �ṹ��
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
		//SHT_STRTAB  �˽��������ַ�����Ŀ���ļ����ܰ�������ַ����������
		if (s_hdr->sh_type == SHT_STRTAB)
		{//��3��SHT_STRTAB���͵�,һ����.dynstr,��һ����.strtab,.shstrtab	
		 //�����޷���һ��ʼ�Ͷ�λ�������ĸ�SHT_STRTAB��.shstrtab,��������һ��SHT_STRTAB���͵�,���Ǿͱ������ҿ��Ƿ���.symtab��.strtab�������ֵ���
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

		if (s_hdr->sh_type == SHT_NOTE) //note�����Ƚ�,ֱ����0���ǵ�
		{
			DoFilter((void*)(base + s_hdr->sh_offset), s_hdr->sh_size, 0);
		}
		else
		{//�����е�Section Head�ṹ�帴�Ƶ����صĽṹ��������
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

	// ���ű�ṹ��
	Elf64_Sym * q;
	int symhdridx = 0;
	int strhdridx = 0;
	for (i = 0; i < rechdrcnt; i++)
	{//��������Section Head�ṹ������,�Ƚ���Section Name(����id),�Ƿ���.shstrtab���������ӳ������id���
		if (local_hdr[i].sh_name == symtabnmidx)
		{//��¼��.symtab�ڱ���Section Head�ṹ�������е��±�
			symhdridx = i;
		}
		else if (local_hdr[i].sh_name == strtabnmidx)
		{//��¼��.strtab�ڱ���Section Head�ṹ�������е��±�
			strhdridx = i;
		}
	}

	//��.strtab�л�ȡGetBizFunctionsInfo�Ķ�Ӧ����id
	GetBiznmidx = ParseStrTab(base, &local_hdr[strhdridx], "GetBizFunctionsInfo");
	if (GetBiznmidx == 0)
	{
		free(local_hdr);
		return -4;
	}

	uint64_t symcnt = local_hdr[symhdridx].sh_size / local_hdr[symhdridx].sh_entsize;
	for (uint64_t j = 0; j < symcnt; j++)
	{//����.symtab,�ҵ��ṹ���st_name�ֶ�ֵΪGetBizFunctionsInfo��Ӧ����id�Ľṹ��,��ȡ����˺ͳ���,Ȼ���滻Ϊ0
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

