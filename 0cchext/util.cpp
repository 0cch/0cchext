#include "StdAfx.h"
#include "util.h"
#include <fstream>

BOOL IsPrintAble(CHAR *str, ULONG len)
{
	for (ULONG i = 0; i < len; i++) {
		if (!isprint((UCHAR)str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

PCHAR* WdbgCommandLineToArgv(PCHAR cmd_line, int* arg_num)
{
	PCHAR* argv;
	PCHAR argv_buf;
	ULONG len;
	ULONG argc;
	CHAR a;
	ULONG i, j;

	BOOLEAN in_QM;
	BOOLEAN in_TEXT;
	BOOLEAN in_SPACE;

	len = (ULONG)strlen(cmd_line);
	i = ((len + 2) / 2) * sizeof(PVOID) + sizeof(PVOID);

	argv = (PCHAR*)LocalAlloc(LMEM_FIXED,
		i + (len + 2)*sizeof(CHAR));

	argv_buf = (PCHAR)(((PUCHAR)argv) + i);

	argc = 0;
	argv[argc] = argv_buf;
	in_QM = FALSE;
	in_TEXT = FALSE;
	in_SPACE = TRUE;
	i = 0;
	j = 0;

	while( a = cmd_line[i] ) {
		if(in_QM) {
			if(a == '\'') {
				in_QM = FALSE;
			} else {
				argv_buf[j] = a;
				j++;
			}
		} else {
			switch(a) {
			case '\'':
				in_QM = TRUE;
				in_TEXT = TRUE;
				if(in_SPACE) {
					argv[argc] = argv_buf+j;
					argc++;
				}
				in_SPACE = FALSE;
				break;
			case ' ':
			case '\t':
			case '\n':
			case '\r':
				if(in_TEXT) {
					argv_buf[j] = '\0';
					j++;
				}
				in_TEXT = FALSE;
				in_SPACE = TRUE;
				break;
			default:
				in_TEXT = TRUE;
				if(in_SPACE) {
					argv[argc] = argv_buf+j;
					argc++;
				}
				argv_buf[j] = a;
				j++;
				in_SPACE = FALSE;
				break;
			}
		}
		i++;
	}
	argv_buf[j] = '\0';
	argv[argc] = NULL;

	(*arg_num) = argc;
	return argv;
}

std::string ReadLines(PCSTR start_pos, PCSTR str, int lines)
{
	std::string buf;
	int cur_lines = 0;
	while (*str != '\n' && str >= start_pos) {
		str--;
	}
	str++;

	while (*str != 0) {
		if (*str == '\n') {
			cur_lines++;
		}

		if (cur_lines >= lines) {
			break;
		}

		buf += *str;
		str++;
	}

	return buf;
}

void ReadLines(PCSTR str, std::vector<std::string> &str_vec)
{
	std::string buf;
	while (*str != 0) {
		if (*str == '\n') {
			str_vec.push_back(buf);
			buf.clear();
		}
		else if (*str == '\r') {
			
		}
		else {
			buf += *str;
		}
		str++;
	}

	if (!buf.empty()) {
		str_vec.push_back(buf);
		buf.clear();
	}
}

BOOL GetTxtFileDataA(LPCSTR file, std::string &data)
{
	std::ifstream ifs(file);
	if (!ifs.is_open()) {
		return FALSE;
	}

	std::string str((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
	data = str;
	return TRUE;
}


BOOL CIMDateTimetoFileTime(LPCWSTR cimdatetime, LPFILETIME filetime, BOOL localtime)
{
	BOOL retval = FALSE;
	ISWbemDateTime *wbem_data_time = NULL;
	HRESULT hr = CoCreateInstance(CLSID_SWbemDateTime, NULL, CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&wbem_data_time));
	if (SUCCEEDED(hr)) {
		BSTR timebstr = SysAllocString(cimdatetime);
		if (timebstr) {
			hr = wbem_data_time->put_Value(timebstr);
			if (SUCCEEDED(hr)) {
				BSTR bstrFileTime;
				hr = wbem_data_time->GetFileTime(localtime ? VARIANT_TRUE : VARIANT_FALSE,
					&bstrFileTime);
				if (SUCCEEDED(hr)) {
					ULARGE_INTEGER temp_file_time;
					temp_file_time.QuadPart = _wtoi64(bstrFileTime); 
					filetime->dwLowDateTime = temp_file_time.LowPart;
					filetime->dwHighDateTime = temp_file_time.HighPart;
					SysFreeString(bstrFileTime);
					retval = TRUE;

				}
			}
			SysFreeString(timebstr);
		}
		wbem_data_time->Release();
	}
	return retval;
}

void WmiTimeToString(LPCWSTR cimdatetime, CString &datatime_str)
{
	FILETIME tm;
	if (!CIMDateTimetoFileTime(cimdatetime, &tm, TRUE)) {
		return;
	}

	SYSTEMTIME st;
	FileTimeToSystemTime(&tm, &st);

	datatime_str.Format(L"%04u-%02u-%02u %02u:%02u:%02u.%03u", 
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void ParseCIMValueToString(LPCTSTR name, CIMTYPE type, VARIANT &value, LONG flavor, CString &out_str)
{
	CString flavor_str;
	switch (flavor & WBEM_FLAVOR_MASK_ORIGIN)
	{
	case WBEM_FLAVOR_ORIGIN_SYSTEM:
		flavor_str = TEXT("system");
		break;
	case WBEM_FLAVOR_ORIGIN_PROPAGATED:
		flavor_str = TEXT("inherited"); 
		break;
	case WBEM_FLAVOR_ORIGIN_LOCAL:
		flavor_str = TEXT("local"); 
		break;
	}

	BOOL cim_array = FALSE;
	if (type & CIM_FLAG_ARRAY) {
		type &= ~CIM_FLAG_ARRAY;
		cim_array = TRUE;
	}

	CString line;
	line.Format(TEXT("  %-40s  %-10s  "), name, flavor_str.GetString());

	if (value.vt == VT_NULL) {
		line.Append(TEXT("\r\n"));
	}

	LONG array_upper_bound = 0;
	LONG array_lower_bound = 0;
	LONG array_count = 0;
	PVOID array_raw_data = 0;
	if (cim_array && (value.vt & VT_ARRAY) != 0) {
		SafeArrayGetLBound(V_ARRAY(&value), 1, &array_lower_bound);
		SafeArrayGetUBound(V_ARRAY(&value), 1, &array_upper_bound);
		array_count = array_upper_bound - array_lower_bound + 1;
		SafeArrayAccessData(V_ARRAY(&value), &array_raw_data);
	}

	

	switch (type)
	{
	case CIM_EMPTY: break;
		line.Append(TEXT("\r\n"));
		break;
	case CIM_SINT8: 
		if (cim_array) {
			if (value.vt == (VT_I2 | VT_ARRAY) && array_raw_data != NULL) {
				SHORT *data = (SHORT *)array_raw_data;
				line.AppendFormat(TEXT("CIM_SINT8[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %d\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_I2) {
				line.AppendFormat(TEXT("CIM_SINT8  %d\r\n"), value.iVal);
			}
		}
		break;
	case CIM_UINT8: 
		if (cim_array) {
			if (value.vt == (VT_UI1 | VT_ARRAY) && array_raw_data != NULL) {
				USHORT *data = (USHORT *)array_raw_data;
				line.AppendFormat(TEXT("CIM_UINT8[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %u\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_UI1) {
				line.AppendFormat(TEXT("CIM_UINT8  %u\r\n"), value.bVal);
			}
		}
		break;
	case CIM_SINT16:
		if (cim_array) {
			if (value.vt == (VT_I2 | VT_ARRAY) && array_raw_data != NULL) {
				SHORT *data = (SHORT *)array_raw_data;
				line.AppendFormat(TEXT("CIM_SINT16[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %d\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_I2) {
				line.AppendFormat(TEXT("CIM_SINT16  %d\r\n"), value.iVal);
			}
		}
		break;
	case CIM_UINT16: 
		if (cim_array) {
			if (value.vt == (VT_I4 | VT_ARRAY) && array_raw_data != NULL) {
				ULONG *data = (ULONG *)array_raw_data;
				line.AppendFormat(TEXT("CIM_UINT16[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %u\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_I4) {
				line.AppendFormat(TEXT("CIM_UINT16  %u\r\n"), value.intVal);
			}
		}
		break;
	case CIM_SINT32: 
		if (cim_array) {
			if (value.vt == (VT_I4 | VT_ARRAY) && array_raw_data != NULL) {
				LONG *data = (LONG *)array_raw_data;
				line.AppendFormat(TEXT("CIM_SINT32[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %d\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_I4) {
				line.AppendFormat(TEXT("CIM_SINT32  %d\r\n"), value.intVal);
			}
		}
		break;
	case CIM_UINT32: 
		if (cim_array) {
			if (value.vt == (VT_I4 | VT_ARRAY) && array_raw_data != NULL) {
				ULONG *data = (ULONG *)array_raw_data;
				line.AppendFormat(TEXT("CIM_UINT32[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %u\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_I4) {
				line.AppendFormat(TEXT("CIM_UINT32  %u\r\n"), value.intVal);
			}
		}
		break;
	case CIM_SINT64: 
		if (cim_array) {
			if (value.vt == (VT_BSTR | VT_ARRAY) && array_raw_data != NULL) {
				BSTR *data = (BSTR *)array_raw_data;
				line.AppendFormat(TEXT("CIM_SINT64[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %s\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_BSTR) {
				line.AppendFormat(TEXT("CIM_SINT64  %s\r\n"), value.bstrVal);
			}	
		}
		break;
	case CIM_UINT64: 
		if (cim_array) {
			if (value.vt == (VT_BSTR | VT_ARRAY) && array_raw_data != NULL) {
				BSTR *data = (BSTR *)array_raw_data;
				line.AppendFormat(TEXT("CIM_UINT64[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %s\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_BSTR) {
				line.AppendFormat(TEXT("CIM_UINT64  %s\r\n"), value.bstrVal);
			}
		}
		break;
	case CIM_REAL32: 
		if (cim_array) {
			if (value.vt == (VT_R4 | VT_ARRAY) && array_raw_data != NULL) {
				FLOAT *data = (FLOAT *)array_raw_data;
				line.AppendFormat(TEXT("CIM_REAL32[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %f\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_R4) {
				line.AppendFormat(TEXT("CIM_REAL32  %f\r\n"), value.fltVal);
			}
		}
		break;
	case CIM_REAL64: 
		if (cim_array) {
			if (value.vt == (VT_R8 | VT_ARRAY) && array_raw_data != NULL) {
				DOUBLE *data = (DOUBLE *)array_raw_data;
				line.AppendFormat(TEXT("CIM_REAL64[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %lf\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_R8) {
				line.AppendFormat(TEXT("CIM_REAL64  %lf\r\n"), value.dblVal);
			}
		}
		break;
	case CIM_BOOLEAN: 
		if (cim_array) {
			if (value.vt == (VT_BOOL | VT_ARRAY) && array_raw_data != NULL) {
				VARIANT_BOOL *data = (VARIANT_BOOL *)array_raw_data;
				line.AppendFormat(TEXT("CIM_BOOLEAN[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %s\r\n"), 58, TEXT(" "), i, data[i] == VARIANT_TRUE ? TEXT("True") : TEXT("False"));
				}
			}
		}
		else {
			if (value.vt == VT_BOOL) {
				line.AppendFormat(TEXT("CIM_BOOLEAN  %s\r\n"), value.boolVal == VARIANT_TRUE ? TEXT("True") : TEXT("False"));
			}
		}
		break;
	case CIM_STRING:
		if (cim_array) {
			if (value.vt == (VT_BSTR | VT_ARRAY) && array_raw_data != NULL) {
				BSTR *data = (BSTR *)array_raw_data;
				line.AppendFormat(TEXT("CIM_STRING[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %s\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_BSTR) {
				line.AppendFormat(TEXT("CIM_STRING  %s\r\n"), value.bstrVal);
			}
		}
		break;
	case CIM_DATETIME: 
		if (cim_array) {
			if (value.vt == (VT_BSTR | VT_ARRAY) && array_raw_data != NULL) {
				BSTR *data = (BSTR *)array_raw_data;
				line.AppendFormat(TEXT("CIM_DATETIME[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					CString datatime;
					WmiTimeToString(data[i], datatime);
					line.AppendFormat(TEXT("%*s[%u]  %s\r\n"), 58, TEXT(" "), i, datatime.GetString());
				}
			}
		}
		else {
			if (value.vt == VT_BSTR) {
				CString datatime;
				WmiTimeToString(value.bstrVal, datatime);
				line.AppendFormat(TEXT("CIM_DATETIME  %s\r\n"), datatime.GetString());
			}
		}
		break;
	case CIM_REFERENCE: 
		if (cim_array) {
			if (value.vt == (VT_BSTR | VT_ARRAY) && array_raw_data != NULL) {
				BSTR *data = (BSTR *)array_raw_data;
				line.AppendFormat(TEXT("CIM_REFERENCE[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %s\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_BSTR) {
				line.AppendFormat(TEXT("CIM_REFERENCE  %s\r\n"), value.bstrVal);
			}
		}
		break;
	case CIM_CHAR16:
		if (cim_array) {
			if (value.vt == (VT_I2 | VT_ARRAY) && array_raw_data != NULL) {
				SHORT *data = (SHORT *)array_raw_data;
				line.AppendFormat(TEXT("CIM_CHAR16[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %c\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_I2) {
				line.AppendFormat(TEXT("CIM_CHAR16  %c\r\n"), value.iVal);
			}
		}
		break;
	case CIM_OBJECT: 
		if (cim_array) {
			if (value.vt == (VT_UNKNOWN | VT_ARRAY) && array_raw_data != NULL) {
				IUnknown **data = (IUnknown **)array_raw_data;
				line.AppendFormat(TEXT("CIM_OBJECT[%u]\r\n"), array_count);
				for (LONG i = 0; i < array_count; i++) {
					line.AppendFormat(TEXT("%*s[%u]  %p\r\n"), 58, TEXT(" "), i, data[i]);
				}
			}
		}
		else {
			if (value.vt == VT_UNKNOWN) {
				line.AppendFormat(TEXT("VT_UNKNOWN  %p\r\n"), value.punkVal);
			}
		}
		break;
	default:
		break;
	}

	if (cim_array) {
		SafeArrayUnaccessData(V_ARRAY(&value));
	}

	out_str = line;
}

BOOL WmiQueryInfoImpl(LPCWSTR query_str, CString &query_result)
{
	HRESULT hr;
	CComPtr<IWbemLocator> locator;
	CComPtr<IWbemServices> services;
	hr = CoCreateInstance(
		CLSID_WbemLocator,             
		0, 
		CLSCTX_INPROC_SERVER, 
		IID_IWbemLocator, (LPVOID *) &locator);

	if (FAILED(hr))	{
		return FALSE;
	}

	hr = locator->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&services
		);

	if (FAILED(hr)) {
		return FALSE;
	}

	CoSetProxyBlanket(
		services,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
		);

	CComPtr<IEnumWbemClassObject> enumerator;
	hr = services->ExecQuery(
		bstr_t("WQL"), 
		bstr_t(query_str),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
		NULL,
		&enumerator);

	if (FAILED(hr)) {
		return FALSE;
	}

	while (enumerator)
	{
		CComPtr<IWbemClassObject> class_obj;
		ULONG return_length = 0;

		hr = enumerator->Next(WBEM_INFINITE, 1, 
			&class_obj, &return_length);

		if(0 == return_length) {
			break;
		}
		CComVariant v;

		query_result.Append(TEXT("-------------------------------------------------------------\r\n"));
		if (SUCCEEDED(class_obj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY))) {
			BSTR key_str = NULL;
			VARIANT value;
			VariantInit(&value);
			CIMTYPE value_type;
			LONG flavor;
			while (SUCCEEDED(class_obj->Next(0, &key_str, &value, &value_type, &flavor)) && key_str != NULL) {

				CString out_str;
				ParseCIMValueToString(key_str, value_type, value, flavor, out_str);

				query_result.Append(out_str);

				SysFreeString(key_str);
				key_str = NULL;
				VariantClear(&value);
			}

			class_obj->EndEnumeration();
		}

		query_result.Append(TEXT("-------------------------------------------------------------\r\n"));
	}

	return TRUE;
}