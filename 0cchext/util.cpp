#include "StdAfx.h"
#include "util.h"
#include <fstream>

#include <WinError.h>

BOOL IsPrintAble(CHAR *str, ULONG len)
{
	for (ULONG i = 0; i < len; i++) {

		if (iscntrl((UCHAR)str[i])) {
			str[i] = '.';
		}

		if (!isprint((UCHAR)str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

BOOL IsPrintAbleW(WCHAR *str, ULONG len)
{
	for (ULONG i = 0; i < len; i++) {

		if (iswcntrl(str[i])) {
			str[i] = L'.';
		}

		if (!iswprint(str[i])) {
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

	if (cim_array && (value.vt & VT_ARRAY) != 0) {
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


LONG (NTAPI *RtlFindMessage)(
	PVOID DllHandle,
	ULONG MessageTableId,
	ULONG MessageLanguageId,
	ULONG MessageId,
	PMESSAGE_RESOURCE_ENTRY *MessageEntry
	) = NULL;

BOOL FindMessage(PVOID dll, ULONG id, CStringW &message)
{
	if (RtlFindMessage == NULL) {
		HMODULE h = GetModuleHandle(TEXT("ntdll.dll"));
		if (h == NULL) {
			return FALSE;
		}

		*(FARPROC *)&RtlFindMessage = GetProcAddress(h, "RtlFindMessage");
		if (RtlFindMessage == NULL) {
			return FALSE;
		}
	}
	
	PMESSAGE_RESOURCE_ENTRY msg = NULL;
	LONG ns = RtlFindMessage(dll, 0xb, 0, id, &msg);
	if (ns < 0) {
		return FALSE;
	}

	if (msg->Flags & MESSAGE_RESOURCE_UNICODE) {
		message = (WCHAR *)msg->Text;
	}
	else {
		message = (CHAR *)msg->Text;
	}

	return TRUE;
}

BOOL HttpDownloader::Create(LPCTSTR agent, LPCTSTR proxy /*= NULL*/)
{
	if (proxy == NULL) {
		sesstion_ = InternetOpen(agent, 
			INTERNET_OPEN_TYPE_PRECONFIG,
			NULL, 
			NULL, 
			0);
	}
	else {
		CString proxy_str(TEXT("http="));
		proxy_str.Append(proxy);
		sesstion_ = InternetOpen(agent, 
			INTERNET_OPEN_TYPE_PROXY,
			proxy_str, 
			NULL, 
			0);
	}
	
	return sesstion_ != NULL;
}

void HttpDownloader::Close()
{
	if (sesstion_ != NULL) {
		InternetCloseHandle(sesstion_);
		sesstion_ = NULL;
	}
}

HRESULT HttpDownloader::DownloadFile(LPCTSTR server_name, 
	INTERNET_PORT server_port, 
	LPCTSTR refer, 
	LPCTSTR remote_file, 
	LPCTSTR download_file,
	ULONG pos,
	DOWNLOAD_CALLBACK pfn,
	PVOID context,
	ULONG timeout)
{
	ULONG last_error = ERROR_SUCCESS;
	HINTERNET connect_handle = InternetConnect(sesstion_, 
		server_name,
		server_port, 
		NULL, 
		NULL, 
		INTERNET_SERVICE_HTTP, 
		0, 
		0);
	if (NULL == connect_handle) {
		return __HRESULT_FROM_WIN32(GetLastError());
	}

	PCTSTR accept[] = {TEXT("accept: */*"), NULL};
	HINTERNET request_handle = HttpOpenRequest(
		connect_handle, 
		TEXT("GET"), 
		remote_file, 
		NULL, 
		refer,
		accept, 
		0, 
		0);
	if (NULL == request_handle) {
		last_error = GetLastError();
		InternetCloseHandle(connect_handle);
		return __HRESULT_FROM_WIN32(last_error);
	}

	if (timeout != 0) {
		InternetSetOption(request_handle, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
		InternetSetOption(request_handle, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
	}
	

	TCHAR header_str[64] = { 0 };
	_stprintf_s(header_str, TEXT("Range:bytes=%u-\r\n"), pos);
	if (!HttpSendRequest(request_handle, header_str, (ULONG)_tcslen(header_str), NULL, 0)) {
		last_error = GetLastError();
		InternetCloseHandle(request_handle);
		InternetCloseHandle(connect_handle);
		return __HRESULT_FROM_WIN32(last_error);
	}

	ULONG status_code = 0;
	ULONG bytes_returned = sizeof(status_code);

	HttpQueryInfo(request_handle,
		HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
		&status_code, 
		&bytes_returned, 
		NULL);

	if (status_code == HTTP_STATUS_NOT_FOUND) {
		InternetCloseHandle(request_handle);
		InternetCloseHandle(connect_handle);
		return __HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}

	ULONG content_length = 0;
	bytes_returned = sizeof(content_length);
	HttpQueryInfo(request_handle,
		HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
		&content_length, 
		&bytes_returned, 
		NULL);

	if (content_length == 0) {
		InternetCloseHandle(request_handle);
		InternetCloseHandle(connect_handle);
		return __HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}


	HANDLE download_file_handle = CreateFile(download_file, 
		GENERIC_WRITE, 
		0, 
		NULL, 
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_ARCHIVE, 
		NULL);
	if (INVALID_HANDLE_VALUE == download_file_handle) {
		last_error = GetLastError();
		InternetCloseHandle(request_handle);
		InternetCloseHandle(connect_handle);
		return __HRESULT_FROM_WIN32(last_error);
	}

	SetFilePointer(download_file_handle, pos, NULL, FILE_BEGIN);

	const ULONG download_unit_size = 0x1000;
	PVOID cache_buffer = HeapAlloc(GetProcessHeap(), 0, download_unit_size);
	if (cache_buffer == NULL) {
		last_error = GetLastError();
		CloseHandle(download_file_handle);
		InternetCloseHandle(request_handle);
		InternetCloseHandle(connect_handle);
		return __HRESULT_FROM_WIN32(last_error);
	}

	ULONG bytes_left = content_length;
	ULONG bytes_written = 0;

	for (;;) {
		if (!InternetReadFile(request_handle, cache_buffer, download_unit_size, &bytes_returned)) {
			break;
		}
		
		if (pfn != NULL) {
			pfn(bytes_returned, content_length, context);
		}

		bytes_left -= bytes_returned;
		if (bytes_returned > 0) {
			WriteFile(download_file_handle, cache_buffer, bytes_returned, &bytes_written, NULL);
		}

		if (bytes_left == 0) {
			break;
		}
	}

	last_error = GetLastError();

	CloseHandle(download_file_handle);
	InternetCloseHandle(request_handle);
	InternetCloseHandle(connect_handle);
	HeapFree(GetProcessHeap(), 0, cache_buffer);
	return __HRESULT_FROM_WIN32(last_error);
}

HRESULT HttpDownloader::UrlDownloadFile( LPCTSTR full_uri, LPCTSTR download_file, ULONG pos, DOWNLOAD_CALLBACK pfn, PVOID context, ULONG timeout )
{
	URL_COMPONENTS url_components = {0};
	url_components.dwStructSize = sizeof(url_components);
	TCHAR host_name[INTERNET_MAX_HOST_NAME_LENGTH];
	url_components.lpszHostName = host_name;
	url_components.dwHostNameLength = INTERNET_MAX_HOST_NAME_LENGTH;
	TCHAR url_path[INTERNET_MAX_PATH_LENGTH];
	url_components.lpszUrlPath = url_path;
	url_components.dwUrlPathLength = INTERNET_MAX_PATH_LENGTH;
	if (!InternetCrackUrl(full_uri, _tcslen(full_uri), 0, &url_components)) {
		return __HRESULT_FROM_WIN32(GetLastError());
	}
	
	return DownloadFile(host_name, url_components.nPort, NULL, url_path, download_file, pos, pfn, context, timeout);
}

CStringW GUIDToWstring(GUID* guid) 
{
	WCHAR guid_string[64];
	swprintf_s(
		guid_string, sizeof(guid_string) / sizeof(guid_string[0]),
		L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
		guid->Data1, guid->Data2, guid->Data3,
		guid->Data4[0], guid->Data4[1], guid->Data4[2],
		guid->Data4[3], guid->Data4[4], guid->Data4[5],
		guid->Data4[6], guid->Data4[7]);
	return guid_string;
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FILETIME ft;
	unsigned __int64 tmpres = 0;
	static int tzflag;

	if (NULL != tv)
	{
		GetSystemTimeAsFileTime(&ft);

		tmpres |= ft.dwHighDateTime;
		tmpres <<= 32;
		tmpres |= ft.dwLowDateTime;

		tmpres /= 10;
		tmpres -= DELTA_EPOCH_IN_MICROSECS;
		tv->tv_sec = (long)(tmpres / 1000000UL);
		tv->tv_usec = (long)(tmpres % 1000000UL);
	}

	if (NULL != tz)
	{
		if (!tzflag)
		{
			_tzset();
			tzflag++;
		}
		_get_timezone((long *)&tz->tz_minuteswest);
		tz->tz_minuteswest /= 60;
		_get_daylight(&tz->tz_dsttime);
	}

	return 0;
}

BOOL IsElevated() 
{
	BOOL retval = FALSE;
	HANDLE token = NULL;
	if (OpenProcessToken(GetCurrentProcess( ), TOKEN_QUERY, &token)) {
		TOKEN_ELEVATION token_elevation;
		DWORD ret_size = sizeof(TOKEN_ELEVATION);
		if( GetTokenInformation( token, TokenElevation, &token_elevation, sizeof(token_elevation), &ret_size ) ) {
			retval = token_elevation.TokenIsElevated;
		}
	}
	if(token != NULL) {
		CloseHandle(token);
	}
	return retval;
}