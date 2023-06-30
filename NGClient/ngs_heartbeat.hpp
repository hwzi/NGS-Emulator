#pragma once

#include "ngs_buffer.hpp"

namespace ngs
{
	class heartbeat
	{
	public:
		heartbeat();
		~heartbeat();

		bool make_response(buffer::request& request, buffer::response& response);
	
	private:
		bool handle_type(buffer::request& request, buffer::response& response);
		
		bool type_handler_01(buffer::request& request, buffer::response& response);
		bool type_handler_02(buffer::request& request, buffer::response& response);
		bool type_handler_03(buffer::request& request, buffer::response& response);
		bool type_handler_04(buffer::request& request, buffer::response& response);
		bool type_handler_05(buffer::request& request, buffer::response& response);
		bool type_handler_06(buffer::request& request, buffer::response& response);
		bool type_handler_07(buffer::request& request, buffer::response& response);
	
		std::string make_version_string();

	private:
		unsigned char crypto_key;

		unsigned char ngs_has_detected;
		unsigned char ngs_detection_id_first;
		unsigned char ngs_detection_id_last;

		unsigned int hash_checksum;
		unsigned int option_checksum;
	};
}