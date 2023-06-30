#pragma once

#include <Windows.h>
#include <iostream>
#include <string>

#define BLACK_TRANS_BUFFER_MAX	8192

namespace ngs
{
	namespace buffer
	{
		#pragma pack(push, 1)
		class response
		{
		public:
			response() 
				: type(0), length(8), zero(0)
			{
				memset(this->buffer, 0, sizeof(this->buffer));
			}

			template <typename T>
			bool add(T data)
			{
				if ((this->length + sizeof(T)) <= (sizeof(this->buffer) + 8))
				{
					*reinterpret_cast<T*>(this->buffer + this->length - 8) = data;
					this->length += sizeof(T);
					return true;
				}

				return false;
			}

			bool add_aob(unsigned char* input, unsigned short size)
			{
				if ((this->length + size) <= (sizeof(this->buffer) + 8))
				{
					memcpy(this->buffer + this->length - 8, input, size);
					this->length += size;
					return true;
				}

				return false;
			}

			bool add_string(std::string const& input, bool null_terminator = false)
			{
				if ((this->length + (null_terminator ? input.length() + 1 : input.length())) <= (sizeof(this->buffer) + 8))
				{
					memcpy(this->buffer + this->length - 8, input.c_str(), (null_terminator ? input.length() + 1 : input.length()));
					this->length += (null_terminator ? input.length() + 1 : input.length());
					return true;
				}

				return false;
			}

			bool add_zero(unsigned short size)
			{
				if ((this->length + size) <= (sizeof(this->buffer) + 8))
				{
					memset(this->buffer + this->length - 8, 0, size);
					this->length += size;
					return true;
				}

				return false;
			}
			
			void crypt(unsigned char xor_key)
			{
				for (int i = 0, j = 0; i < (this->length - 8); i++, (j < 254 ? j++ : j = 0))
					this->buffer[i] ^= (xor_key ^ static_cast<unsigned char>(j));
			}
			
			unsigned short get_length()
			{
				return this->length;
			}

			unsigned short get_type()
			{
				return this->type;
			}

			void set_type(unsigned char type)
			{
				this->type = static_cast<unsigned short>(type << 8);
			}

		private:
			unsigned short type;
			unsigned short length;
			unsigned int zero;
			unsigned char buffer[BLACK_TRANS_BUFFER_MAX - 8];
		};

		class request
		{
		public:
			request(unsigned char* request, std::size_t size, unsigned int offset = 8) 
				: offset(offset)
			{
				memset(this->buffer, 0, sizeof(this->buffer));
				memcpy(this->buffer, request, size);
			}
			
			request(std::string& request, unsigned int offset = 8) 
				: offset(offset)
			{
				memset(this->buffer, 0, sizeof(this->buffer));
				memcpy(this->buffer, reinterpret_cast<const unsigned char*>(request.c_str()), request.length());
			}
			
			void crypt(unsigned char xor_key)
			{
				for (int i = 0, j = 0; i < (this->length - 8); i++, (j < 254 ? j++ : j = 0))
				{
					this->buffer[8 + i] ^= (xor_key ^ static_cast<unsigned char>(j));
				}
			}

			unsigned char get_type()
			{
				return static_cast<unsigned char>(this->type >> 8);
			}

			unsigned short get_length()
			{
				return this->length;
			}

			template <typename T>
			T get()
			{
				if ((this->offset + sizeof(T)) <= this->length)
				{
					this->offset += sizeof(T);
					return *reinterpret_cast<T*>(this->buffer + offset - sizeof(T));
				}

				return 0;
			}
			
			template <typename T>
			T get_at(std::size_t offset)
			{
				if ((offset + sizeof(T)) <= this->length)
				{
					return *reinterpret_cast<T*>(this->buffer + offset);
				}

				return 0;
			}

			bool get_aob(unsigned char* output, std::size_t size)
			{
				if (output && ((this->offset + size) <= this->length))
				{
					memcpy(output, this->buffer + this->offset, size);
					this->offset += size;
					return true;
				}

				return false;
			}

		private:
			union
			{
				struct
				{
					unsigned short type;
					unsigned short length;
					unsigned int zero;
				};

				unsigned char buffer[BLACK_TRANS_BUFFER_MAX];
			};

			unsigned int offset;
		};
		#pragma pack(pop)
	}
}