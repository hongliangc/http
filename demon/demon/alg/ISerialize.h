#pragma once
#include <memory>
#include <utility>
#include <stdexcept>
#include "traits.h"

typedef enum eSerializeMode
{
	eSerializeBegin = 0,
	eSerializeRead,
	eSerializeWrite,
	eSerializeEnd,
}eSerializeMode;


/* The base output archive*/
namespace Serialize_
{
	template<class T>
	struct BinaryData
	{
		//! Internally store the pointer as a void*, keeping const if created with a const pointer
		using PT = typename std::conditional<std::is_const<typename std::remove_pointer<typename std::remove_reference<T>::type>::type>::value,
			const void*, void *>::type;

		BinaryData(T &&data, uint64_t size):m_data(std::forward<T>(data)),m_size(size) {};

		PT m_data;			//! pointer to beginning of data
		uint64_t m_size;	//! size in bytes
	};

	//!it's convenience to create binary data for both const and non const pointers
	/*! @param data Pointer to beginning of the data
		@param size The size in bytes of the data*/
	template<class T> 
	inline BinaryData<T> Binary_data(T &&data, size_t size)
	{
		// T will be deduced to char*& if T is char*;
		return{ std::forward<T>(data), size };
	}

	template<class T>
	inline BinaryData<T> Binary_data_(T &data, size_t size)
	{
		// T will be deduced to char* if T is char*;
		return{ std::forward<T>(data), size };
	}

	struct Exception : public std::runtime_error
	{
		explicit Exception(const std::string & what_) : std::runtime_error(what_) {}
		explicit Exception(const char * what_) : std::runtime_error(what_) {}
	};

	template<class ArchiveType>
	class BaseArchive
	{
	public:
		BaseArchive(ArchiveType * const derived):self(derived){ }
		BaseArchive & operator=(BaseArchive const &) = delete;

		template <class ... Types> 
		inline ArchiveType & operator()(Types && ...args)
		{
			self->Process(std::forward<Types>(args)...);
			return *self;
		}

		template<class T>
		inline ArchiveType& operator& (T &&t)
		{
			self->Process(std::forward<T>(t));
			return *self;
		}


	private:
		template <class T>
		inline void Process(T &&head)
		{
			self->ProcessImp(head);
		}

		template <class T, class ...Other>
		inline void Process(T &&head, Other &&...tail)
		{
			self->Process(std::forward<T>(head));
			self->Process(std::forward<Other>(tail)...);
		}

		//#define PROCESS_IF(name) traits::EnableIf<traits::has_##name<T, ArchiveType>::value>* = nullptr
		//! helper macro that expands the requirements for activating on overload
#define PROCESS_IF(name) traits::EnableIf<traits::has_##name<T, ArchiveType>::value> = traits::sfinae

		template <class T, PROCESS_IF(serialize)>
		inline ArchiveType& ProcessImp(T const &t)
		{
			bool ret = traits::has_serialize<T, ArchiveType>::value;
			SERIALIZE_FUNCTION_NAME(*self, const_cast<T&>(t));
			return *self;
		}

		template <class T, PROCESS_IF(serialize_array)>
		inline ArchiveType& ProcessImp(T const &t)
		{
			bool ret = traits::has_serialize<T, ArchiveType>::value;
			SERIALIZE_ARR_FUNCTION_NAME(*self, const_cast<T&>(t));
			return *self;
		}

		template <class T, PROCESS_IF(member_serialize)>
		inline ArchiveType& ProcessImp(T const &t)
		{
			bool ret = traits::has_serialize<T, ArchiveType>::value;
			traits::access::member_serialize(*self, const_cast<T&>(t));
			return *self;
		}

		//! Empty class specialization
		template <class T, traits::EnableIf<std::is_empty<T>::value> = traits::sfinae> inline
			ArchiveType & ProcessImp(T const &t)
		{
			static_assert(std::is_empty<T>::value,"not support empty class!");
			return *self;
		}
// 		//! not support class specialization
// 		template <class T> inline
// 			ArchiveType & ProcessImp(T const &t)
// 		{
// 			static_assert(std::is_empty<T>::value, "not support empty class!");
// 			return *self;
// 		}


	private:
		ArchiveType * const self;
	};
}