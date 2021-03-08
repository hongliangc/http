#pragma once
#include "ISerialize.h"
#include <sstream>
#include <iostream>
#include <iomanip>
#include <limits>
using namespace std;
namespace Serialize_
{
	inline std::uint8_t is_little_endian()
	{
		static std::int32_t test = 1;
		return *reinterpret_cast<std::int8_t*>(&test) == 1;
	}

	template <std::size_t DataSize>
	inline void swap_bytes(std::uint8_t *data)
	{
		for (std::size_t i = 0, end = DataSize / 2; i < end; i++)
		{
			std::swap(data[i], data[DataSize - i - 1]);
		}
	}

	/*! An output archive designed to save data in a compact binary representation*/
	class TBinaryArchive :public BaseArchive<TBinaryArchive>
	{
	public:
		class Options
		{
		public:
			enum class Endianness :std::uint8_t { big, little };
			static Options Default() { return Options(); }
			static Options LittleEndian() { return Options(Endianness::little); }
			static Options BigEndian() { return Options(Endianness::big); }
			explicit Options(Endianness endian = getEndianness()) :m_endian(endian) {}
		private:
			inline static Endianness getEndianness() { return Serialize_::is_little_endian() ? Endianness::little : Endianness::big; }
			inline std::uint8_t is_little_endian() const { return m_endian == Endianness::little; }
			friend class TBinaryArchive;
			Endianness m_endian;
		};
	public:
		explicit TBinaryArchive(eSerializeMode mode, std::iostream &stream, const Options & options = Options::Default()) :
			BaseArchive(this), m_mode(mode), m_data(stream), m_convertEndian(false)
		{
			if (mode == eSerializeWrite)
			{
				m_convertEndian = is_little_endian() ^ options.is_little_endian();
				this->operator()(options.is_little_endian());
			}
			else
			{
				uint8_t endian = 0xff;
				this->operator()(endian);
				m_convertEndian = endian ^ options.is_little_endian();
			}
		}
		explicit TBinaryArchive(eSerializeMode mode, std::iostream &stream, bool convert):
			BaseArchive(this), m_mode(mode), m_data(stream), m_convertEndian(convert){
		}
	public:
		bool IsRead()
		{
			return (m_mode == eSerializeRead);
		}
		bool IsWrite()
		{
			return (m_mode == eSerializeWrite);
		}

		template<std::streamsize DataSize>
		void Serialize(void *data, std::streamsize size)
		{
			if (IsWrite())
			{
				saveBinary<DataSize>(data, size);
			} 
			else if(IsRead())
			{
				loadBinary<DataSize>(data, size);
			}
		}

		const string GetSerializeString()
		{
			try
			{
				return (dynamic_cast<std::stringstream&>(m_data)).str();
			}
			catch (const std::exception &e)
			{
				std::cout << e.what() << endl;
				throw e;
				return "";
			}
		}

		template<std::streamsize DataSize>
		void saveBinary(const void *data, std::streamsize size)
		{
			std::streamsize writtenSize = 0;
			if (m_convertEndian)
			{
				for (std::streamsize i = 0; i < size; i += DataSize)
				{
					for (std::streamsize j = 0; j < DataSize; ++j)
					{
						writtenSize += m_data.rdbuf()->sputn(reinterpret_cast<const char*>(data) + DataSize - j - 1 + i, 1);
					}
				}
			}
			else
			{
				writtenSize = m_data.rdbuf()->sputn(reinterpret_cast<const char*>(data), size);
			}
			if (writtenSize != size)
				throw Exception("Failed to write:" + std::to_string(size) + ",bytes to output stream! Wrote:" + std::to_string(writtenSize));
		}

		template<std::streamsize DataSize>
		void loadBinary(void * const data, std::streamsize size)
		{
			//load data
			auto const readSize = m_data.rdbuf()->sgetn(reinterpret_cast<char*>(data), size);
			if (readSize != size)
				throw Exception("Failed to read:" + std::to_string(size) + ",bytes from input stream! Read:" + std::to_string(readSize));

			//flip bits if needed
			if (m_convertEndian)
			{
				std::uint8_t *ptr = reinterpret_cast<std::uint8_t*>(data);
				for (std::streamsize i = 0; i < readSize; i += DataSize)
				{
					swap_bytes<DataSize>(ptr + i);
				}
			}
		}
	private:
		eSerializeMode m_mode;
		std::iostream & m_data;
		uint8_t m_convertEndian; //!< IF set to true, we will need to swap bytes upon saving
	};

	template<class T>
	//could use "inline typename std::enable_if<std::is_arithmetic<T>::value, void>::type" instead of the following syntax that is the same
	inline typename std::enable_if_t<std::is_arithmetic<T>::value>
		SERIALIZE_FUNCTION_NAME(TBinaryArchive &ar, T &t)
	{
		static_assert(!std::is_floating_point<T>::value ||
			(std::is_floating_point<T>::value && std::numeric_limits<T>::is_iec559),
			"only supports IEEE 754 standardized floating point");
// 		if (ar.GetSerializeMode() == eSerializeRead)
// 		{
// 			ar.loadBinary<sizeof(T)>(std::addressof(t), sizeof(t));
// 		}
// 		else if (ar.GetSerializeMode() == eSerializeWrite)
// 		{
// 			ar.saveBinary<sizeof(T)>(std::addressof(t), sizeof(t));
// 		}
		ar.Serialize<sizeof(T)>(std::addressof(t), sizeof(t));
	}

	template<class T>
	inline void	SERIALIZE_FUNCTION_NAME(TBinaryArchive &ar, BinaryData<T> &bd)
	{
		//typedef typename std::remove_pointer<typename std::decay<T>::type>::type TT;
		using TT = typename std::remove_pointer<typename std::remove_all_extents<typename std::remove_reference<T>::type>::type>::type;
		printf("SERIALIZE_FUNCTION_NAME TT size:%ld\n", sizeof(TT));
		static_assert(!std::is_floating_point<TT>::value ||
			(std::is_floating_point<TT>::value && std::numeric_limits<TT>::is_iec559),
			"BinaryData only supports IEEE 754 standardized floating point");
// 		if (ar.GetSerializeMode() == eSerializeRead)
// 		{
// 			ar.loadBinary<sizeof(TT)>(bd.m_data, static_cast<std::streamsize>(bd.m_size));
// 		}
// 		else if (ar.GetSerializeMode() == eSerializeWrite)
// 		{
// 			ar.saveBinary<sizeof(TT)>(bd.m_data, static_cast<std::streamsize>(bd.m_size));
// 		}
		ar.Serialize<sizeof(TT)>(bd.m_data, static_cast<std::streamsize>(bd.m_size));
	}

	//!only support BinaryArray and arithmetic
	template<class Archive, class T>
	void SerializeArray(Archive &ar, T &array, std::true_type)
	{
		ar(Binary_data(array, sizeof(array)));
	}
	//! Binary is not supported or we are not arithmetic
	template<class Archive, class T>
	void SerializeArray(Archive &ar, T &array, std::false_type)
	{
		for (auto &it : array)
			ar(it);
	}

	template<class Archive, class T>
	inline typename std::enable_if_t<std::is_array<T>::value>
		SERIALIZE_ARR_FUNCTION_NAME(Archive &ar, T &array)
	{
		//Remove all array extents exclusive of const
		SerializeArray(ar, array,
			std::integral_constant<bool, std::is_arithmetic<typename std::remove_all_extents<T>::type>::value>());
	}

};