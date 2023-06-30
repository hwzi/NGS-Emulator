#ifdef UNICODE
#undef UNICODE
#endif

#ifdef _UNICODE
#undef _UNICODE
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "ngs_files.hpp"

#include <ImageHlp.h>

#pragma comment(lib, "ImageHlp")
#pragma comment(lib, "Version")

#include <fstream>

namespace ngs
{
	namespace files
	{
		std::string current_directory = std::string("");
		std::string current_hwid = std::string("");

		const std::string file_strings[4] =
		{
			std::string("\\NGClient.aes"),
			std::string("\\BlackCipher\\BlackCall.aes"),
			std::string("\\BlackCipher\\BlackCipher.aes"),
			std::string("\\BlackCipher\\BlackXchg.aes"),
		};

		bool initialize()
		{
			current_directory = std::string("G:\\Games\\MapleStory (Global)");
			current_hwid = std::string("1058-4E4B-5E3C-9DA0-4DA7-36F8-F0D5-0F47");
			return true;
		}
		
		std::string get_hwid()
		{
			return current_hwid;
		}

		std::string get_version(file_type filetype)
		{
			std::string file_path = current_directory + file_strings[static_cast<std::size_t>(filetype)];

			std::size_t size = GetFileVersionInfoSize(file_path.c_str(), nullptr);

			if (!size)
			{
				return std::string("0.0.0.0");
			}

			unsigned char* data = new unsigned char[size];

			if (!GetFileVersionInfo(file_path.c_str(), NULL, size, data))
			{
				delete[] data;
				return std::string("0.0.0.0");
			}

			VS_FIXEDFILEINFO* vs_info = nullptr;

			if (!VerQueryValueA(data, "\\", reinterpret_cast<void**>(&vs_info), &size))
			{
				delete[] data;
				return std::string("0.0.0.0");
			}
			
			if (size == 0 || vs_info->dwSignature != 0xfeef04bd)
			{
				delete[] data;
				return std::string("0.0.0.0");
			}

			char file_version[32];
			memset(file_version, 0, sizeof(file_version));
			
			sprintf(file_version, "%d.%d.%d.%d", HIWORD(vs_info->dwFileVersionMS), LOWORD(vs_info->dwFileVersionMS),
				HIWORD(vs_info->dwFileVersionLS), LOWORD(vs_info->dwFileVersionLS));
			
			delete[] data;
			return std::string(file_version);
		}
	}
}