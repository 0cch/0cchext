#include "StdAfx.h"
#include "util.h"

BOOL IsPrintAble(CHAR *str, ULONG len)
{
	for (ULONG i = 0; i < len; i++) {
		if (!isprint((UCHAR)str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}
