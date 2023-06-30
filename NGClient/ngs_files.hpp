#pragma once

#include <Windows.h>
#include <string>

namespace ngs
{
	namespace files
	{
		enum class file_type
		{
			_ngclient_aes = 0,
			_blackcall_aes = 1,
			_blackcipher_aes = 2,
			_blackxchg_aes = 3,
		};

		bool initialize();
		
		std::string get_hwid();
		std::string get_version(file_type filetype);
	}
}