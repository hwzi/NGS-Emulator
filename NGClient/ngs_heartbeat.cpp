#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "ngs_heartbeat.hpp"
#include "ngs_files.hpp"

#include <functional>
#include <string.h>

namespace ngs
{
	heartbeat::heartbeat()
	{
		this->crypto_key = 0;

		this->ngs_has_detected = 0;
		this->ngs_detection_id_first = 1;
		this->ngs_detection_id_last = 1;
		
		this->hash_checksum = 0;
		this->option_checksum = 0;
	}

	heartbeat::~heartbeat()
	{

	}

	bool heartbeat::make_response(buffer::request& request, buffer::response& response)
	{
		if (request.get_type() != 0x01)
			request.crypt(this->crypto_key);
		
		if (!this->handle_type(request, response))
			return false;

		response.crypt(this->crypto_key);
		return true;
	}

	bool heartbeat::handle_type(buffer::request& request, buffer::response& response)
	{
		if (request.get_type() < 0x01 || request.get_type() > 0x07)
			throw std::string("unknown NGS heartbeat type");

		std::function<bool(buffer::request&, buffer::response&)> type_handlers[] =
		{
			std::bind(&heartbeat::type_handler_01, this, std::placeholders::_1, std::placeholders::_2),
			std::bind(&heartbeat::type_handler_02, this, std::placeholders::_1, std::placeholders::_2),
			std::bind(&heartbeat::type_handler_03, this, std::placeholders::_1, std::placeholders::_2),
			std::bind(&heartbeat::type_handler_04, this, std::placeholders::_1, std::placeholders::_2),
			std::bind(&heartbeat::type_handler_05, this, std::placeholders::_1, std::placeholders::_2),
			std::bind(&heartbeat::type_handler_06, this, std::placeholders::_1, std::placeholders::_2),
			std::bind(&heartbeat::type_handler_07, this, std::placeholders::_1, std::placeholders::_2)
		};
		
		return type_handlers[request.get_type() - 1](request, response);
	}
	
	bool heartbeat::type_handler_01(buffer::request& request, buffer::response& response)
	{
		this->crypto_key = request.get<unsigned char>();
		
		response.set_type(0x01);
		response.add_string(ngs::files::get_hwid(), true);
		return true;
	}
	
	bool heartbeat::type_handler_02(buffer::request& request, buffer::response& response)
	{
		unsigned char type = request.get<unsigned char>();

		if (type == 1)
		{
			// 00 02 16 00 00 00 00 00 [01] [0C 00] [00 01 02 03 04 05 07 10 11 12 14 16]
			this->option_checksum = 0x443072B6;
		}
		else if (type == 2)
		{
			// 00 02 0E 00 00 00 00 00 [02] [03 00] [00 01 03]
		}

		return false;
	}

	bool heartbeat::type_handler_03(buffer::request& request, buffer::response& response)
	{
		unsigned char type = request.get<unsigned char>();

		if (type == 0)
		{
			this->hash_checksum = 0;

			unsigned short hash_table_size = request.get<unsigned short>();
			unsigned char* hash_table = new unsigned char[hash_table_size];

			request.get_aob(hash_table, hash_table_size);
					
			for (unsigned short i = 0, j = 0; i < hash_table_size; i++, (j < 3 ? j++ : j = 0))
				reinterpret_cast<unsigned char*>(&this->hash_checksum)[j] ^= hash_table[i];

			delete[] hash_table;
		}
		else if (type == 1)
		{
			unsigned short ip_table_size = request.get<unsigned short>();
			unsigned char* ip_table = new unsigned char[ip_table_size];

			request.get_aob(ip_table, ip_table_size);

			for (unsigned short i = 0; i < ip_table_size; i += 4)
			{
				//printf("%d.%d.%d.%d\n", ip_table[i], ip_table[i + 1], ip_table[i + 2], ip_table[i + 3]);
			}

			delete[] ip_table;
		}

		return false;
	}
	
	bool heartbeat::type_handler_04(buffer::request& request, buffer::response& response)
	{
		unsigned short aob_table_size = request.get<unsigned short>();
		unsigned char* aob_table = new unsigned char[aob_table_size + 1];

		request.get_aob(aob_table, aob_table_size);
		aob_table[aob_table_size] = '\0';
		
		//printf("%s\n", aob_table);

		delete[] aob_table;
		return false;
	}

	bool heartbeat::type_handler_05(buffer::request& request, buffer::response& response)
	{
		std::function<std::string()> make_version_string = []() -> std::string
		{
			char version_string[64];
			memset(version_string, 0, sizeof(version_string));

			strcat(version_string, files::get_version(files::file_type::_blackxchg_aes).c_str());
			strcat(version_string, ";");
			strcat(version_string, files::get_version(files::file_type::_ngclient_aes).c_str());
			strcat(version_string, ";");
			strcat(version_string, files::get_version(files::file_type::_blackcipher_aes).c_str());
			strcat(version_string, ";");
			strcat(version_string, files::get_version(files::file_type::_blackcall_aes).c_str());

			return std::string(version_string, sizeof(version_string));
		};

		response.set_type(0x02);

		response.add<unsigned char>(this->ngs_has_detected);
		response.add<unsigned char>(this->ngs_detection_id_first);
		response.add<unsigned char>(this->ngs_detection_id_last);
		
		response.add<unsigned int>(this->hash_checksum);
		response.add<unsigned int>(this->option_checksum);

		response.add_string(make_version_string(), true);

		response.add<unsigned short>(request.get<unsigned short>());
		response.add<unsigned int>(request.get<unsigned int>());
		response.add<unsigned int>(request.get<unsigned int>() ^ 0xE06D6373);
		return true;
	}

	bool heartbeat::type_handler_06(buffer::request& request, buffer::response& response)
	{
		// Has not yet occured
		return false;
	}
	
	bool heartbeat::type_handler_07(buffer::request& request, buffer::response& response)
	{
		// 00 07 13 00 00 00 00 00 00 08 00 3B 3A 4F 3C 31 4B 4A 3C
		return false;
	}
}