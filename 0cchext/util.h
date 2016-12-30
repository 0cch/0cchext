#ifndef __0CCHEXT_UTIL_H__
#define __0CCHEXT_UTIL_H__

#include <Windows.h>
#include <string>
#include <vector>
#include <wininet.h>

#pragma comment(lib, "Wininet.lib")

typedef void (__stdcall *DOWNLOAD_CALLBACK)(ULONG read_length, ULONG content_length, PVOID context);

class HttpDownloader {
public:
	HttpDownloader() : sesstion_(NULL) {}
	~HttpDownloader() {Close();}

	BOOL Create(LPCTSTR agent);
	void Close();
	HRESULT DownloadFile(LPCTSTR server_name, 
		INTERNET_PORT server_port, 
		LPCTSTR refer, 
		LPCTSTR remote_file, 
		LPCTSTR download_file,
		ULONG pos,
		DOWNLOAD_CALLBACK pfn,
		PVOID context,
		ULONG timeout = 0);
	HRESULT UrlDownloadFile(LPCTSTR url_path, LPCTSTR download_file, ULONG pos, DOWNLOAD_CALLBACK pfn, PVOID context, ULONG timeout = 0);

private:
	HINTERNET sesstion_;
};


BOOL IsPrintAble(CHAR *str, ULONG len);
BOOL IsPrintAbleW(WCHAR *str, ULONG len);
PCHAR* WdbgCommandLineToArgv(PCHAR cmd_line, int* arg_num);
std::string ReadLines(PCSTR start_pos, PCSTR str, int lines);
void ReadLines(PCSTR str, std::vector<std::string> &str_vec);
BOOL GetTxtFileDataA(LPCSTR file, std::string &data);
BOOL WmiQueryInfoImpl(LPCWSTR query_str, CString &query_result);
BOOL FindMessage(PVOID dll, ULONG id, CStringW &message);
CStringW GUIDToWstring(GUID* guid);

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

struct timezone 
{
	int  tz_minuteswest; /* minutes W of Greenwich */
	int  tz_dsttime;     /* type of dst correction */
};

int gettimeofday(struct timeval *tv, struct timezone *tz);
BOOL IsElevated();
#endif
