#include "offsets.h"
#include "Driver.h"
#include<thread>
#include <iostream>
#include <Windows.h>
#include <string>
#include"auth.hpp"
#include "utils.hpp"
#include <iomanip>
#include "apex.hpp"
#include"mapdriver.hpp"
#include "SignatureScanner.h"
#include <iostream> 
#include <stdlib.h> 
#include <Windows.h>
#include <vector>
#include <string>
#include <string.h>
#include <iostream>
#include <fstream>
#include <winbase.h>
#include <tchar.h>
#include <WinInet.h>
#include <Windows.h>
#include "mapper/kdmapper.hpp"
#include "xorstr.hpp"
#include<stdlib.h>
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib, "winmm.lib")
#define _WIN32_WINNT 0x0500
#define DISABLE_OUTPUT

std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10); // long

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}

using namespace KeyAuth;
std::string name = skCrypt("Apex Loader").decrypt(); // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = skCrypt("wDybEC81px").decrypt(); // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = skCrypt("0550e1ab68c8263cce022896e41032ea21de94fdf2f9d98eb228bb7ef7343ed7").decrypt(); // app secret, the blurred text on licenses tab and other tabs
std::string version = skCrypt("1.2").decrypt(); // leave alone unless you've changed version on website
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting
api KeyAuthApp(name, ownerid, secret, version, url);
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
int main()
{
	if (1) {
		// 0 for background Color(Black) 
		// A for text color(Green)
		// https://www.geeksforgeeks.org/how-to-print-colored-text-in-c/ 
		system("Color 04");
		std::string consoleTitle = (std::string)skCrypt(" [Apex Loader - Ver: 1.2]  |  Build Created: ") + compilation_date;
		SetConsoleTitleA(consoleTitle.c_str());
		std::cout << skCrypt("\n\nConnecting..");
		KeyAuthApp.init();
		if (!KeyAuthApp.data.success)
		{
			std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
			Sleep(1500);
			exit(0);
		}
		if (KeyAuthApp.checkblack()) {
			abort();
		}
		std::cout << skCrypt("\n Version: ") << KeyAuthApp.data.version;
		//std::cout << skCrypt("\n Customer panel link: ") << KeyAuthApp.data.customerPanelLink;
		//std::cout << skCrypt("\n Checking session validation status (remove this if causing your loader to be slow)");
		KeyAuthApp.check();
		std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;

		if (std::filesystem::exists(".\\test.json")) //change test.txt to the path of your file :smile:
		{
			if (!CheckIfJsonKeyExists(".\\test.json", "username"))
			{
				std::string key = ReadFromJson(".\\test.json", "license");
				KeyAuthApp.license(key);
				if (!KeyAuthApp.data.success)
				{
					std::remove(".\\test.json");
					std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
					Sleep(1500);
					exit(0);
				}
				std::cout << skCrypt("\nAuto logged in...");
			}
			else
			{
				std::string username = ReadFromJson(".\\test.json", "username");
				std::string password = ReadFromJson(".\\test.json", "password");
				KeyAuthApp.login(username, password);
				if (!KeyAuthApp.data.success)
				{
					std::remove(".\\test.json");
					std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
					Sleep(1500);
					exit(0);
				}
				std::cout << skCrypt("\nSucceed");
			}
			KeyAuthApp.log("Somebody else is using");
		}
		else
		{
			std::string username;
			std::string password;
			std::string key;
			std::cout << skCrypt("\n Input Your License: ");
			std::cin >> key;
			KeyAuthApp.license(key);
			if (!KeyAuthApp.data.success)
			{
				std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
				Sleep(1500);
				exit(0);
			}
			if (username.empty() || password.empty())
			{
				WriteToJson(".\\test.json", "license", key, false, "", "");
				std::cout << skCrypt("Succeed");
			}
			else
			{
				WriteToJson(".\\test.json", "username", username, true, "password", password);
				std::cout << skCrypt("Succeed");
			}


		}

		std::cout << skCrypt("\nUser Data:");
		//std::cout << skCrypt("\n Username: ") << KeyAuthApp.data.username;
		std::cout << skCrypt("\n IP Addr: ") << KeyAuthApp.data.ip;
		std::cout << skCrypt("\n HWID: ") << KeyAuthApp.data.hwid;
		std::cout << skCrypt("\n Activated at: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.createdate)));
		std::cout << skCrypt("\n Last Log in: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.lastlogin)));
		std::cout << skCrypt("\n License Information: \n ");

		for (int i = 0; i < KeyAuthApp.data.subscriptions.size(); i++) { // Prompto#7895 was here
			auto sub = KeyAuthApp.data.subscriptions.at(i);
			//std::cout << skCrypt("\n name: ") << sub.name;
			std::cout << skCrypt("Expires:") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
		}

		std::cout << skCrypt("\n Checking..");
		KeyAuthApp.check();
		std::cout << skCrypt("\n Status:") << KeyAuthApp.data.message;

		Sleep(3000);
		system("cls");

		LoadLibraryA(XorStr("User32").c_str());
		if (GlobalFindAtomA(XorStr("drivercheck").c_str()) == 0) // checks if driver already loaded (resets when windows restarted)
		{
			system("Color 06");
			std::cout << XorStr("\n\n Starting Driver [+] ");
			Sleep(5000);

			std::vector<std::uint8_t> bytes = KeyAuthApp.download("899061"); // upload your file to KeyAuth then put driver file ID here

			HANDLE iqvw64e_device_handle = intel_driver::Load();

			if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
			{
				std::cout << XorStr("\n Error code iq00001, please disable any anti-cheat such as valorant or faceit and try again");
				Sleep(3500);
				exit(0);
			}

			if (!kdmapper::MapDriver(iqvw64e_device_handle, bytes.data()))
			{
				std::cout << XorStr("\n Error code iq00002, please disable any anti-cheat such as valorant or faceit and try again");
				intel_driver::Unload(iqvw64e_device_handle);
				Sleep(3500);
				exit(0);
			}

			GlobalAddAtomA(XorStr("drivercheck").c_str()); // adds atom so we know driver already loaded, and we won't load again until windows restarted
		}
	}

	Sleep(5000);
	system("cls");
	system("Color 04");
	std::cout << "Note:Driver Stays Running until PC Restart!\n";
	std::cout << "Press F2 to Start Injecting\n";
	while (1) {
		if (GetAsyncKeyState(VK_F2)) // check if F2 key pressed yet
			break;
		Sleep(500);
	}
	std::cout << XorStr("\n\n Injecting, please wait..");

	system("Color 0C");
	system("cls");
	std::cout << "Loading.";
	Sleep(1000);
	system("cls");
	std::cout << "Loading..";
	Sleep(1000);
	system("cls");
	std::cout << "Loading...";
	Sleep(1000);
	system("cls");
	std::cout << "Loading..";
	Sleep(1000);
	system("cls");

	mmap_driver();

	system("Color 04");
	while (!hwnd)
	{
		hwnd = FindWindowA(NULL, ("Apex Legends"));
		Sleep(1000);
		std::cout << "[+]Finding Apex Legends...\n";
		Sleep(3000);
		system("cls");
	}

	static RECT TempRect = { NULL };
	static POINT TempPoint;
	GetClientRect(hwnd, &TempRect);
	ClientToScreen(hwnd, &TempPoint);
	TempRect.left = TempPoint.x;
	TempRect.top = TempPoint.y;
	screenWeight = TempRect.right;
	screenHeight = TempRect.bottom;

	while (!oPID) // get the process id
	{
		oPID = GetPID("r5apex.exe");
		printf("[+] Status Apex:Found\n");
		Sleep(3000);
		system("cls");
	}

	std::cout << "[+] Requesting Base Modules From Driver Please be Patient!";
	Sleep(3000);
	system("cls");
	system("Color 0C");
	std::cout << "Loading.";
	Sleep(1000);
	system("cls");
	std::cout << "Loading..";
	Sleep(1000);
	system("cls");
	std::cout << "Loading...";
	Sleep(1000);
	system("cls");

	while (!oBaseAddress) // request the module base from driver
	{
		oBaseAddress = GetModuleBaseAddress(oPID, "r5apex.exe");
		system("Color 02");
		std::cout << "Modules Initalized Successfully!\n";
		Sleep(3000);
	}
	std::cout << "[+]Driver Loaded\n[+]Apex Launched";
	Beep(523, 300);
	ShowWindow(GetConsoleWindow(), SW_MINIMIZE);
	_beginthread((_beginthread_proc_type)mainthread, 0, 0);
	Sleep(10);
	_beginthread((_beginthread_proc_type)aimbotthread, 0, 0);
	_beginthread((_beginthread_proc_type)overlaythread, 0, 0);
	Sleep(10);
	_beginthread((_beginthread_proc_type)skinthread, 0, 0);
	Sleep(-1);
}