#pragma once
#include <unordered_map>
#include <typeinfo>
#include <typeindex>
#include <functional>
#include <mutex>
#include <stdarg.h>
#include <stdio.h>
#include "TSingleton.h"

using namespace std;



#if defined(_MSC_VER) && !defined(__clang__)
#   define DLL_EXPORT __declspec(dllexport)
#   define USED
#else // clang or gcc
#   define DLL_EXPORT __attribute__ ((visibility("default")))
#   define USED __attribute__ ((__used__))
#endif


#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x) x
#endif

template <class Base, class Derived>
struct RegisterPolymorphicCaster;

struct PolymorphicCasters;

template <class Base, class Derived>
struct PolymorphicRelation;

/*!（When serializing a polymorphic base class pointer, using Run - Time Type Information(RTTI) to determine the true type of the object at the location stored in the pointer.
This type information is then used to look up the proper serialization methods in a map which will have been initialized at pre - execution time*/
//注册基类和子类映射
#define REGISTER_POLYMORPHIC_RELATION(Base, Derived)							\
  template <>                                                                   \
  struct PolymorphicRelation<Base, Derived>                                     \
  {																				\
	static void bind() { RegisterPolymorphicCaster<Base, Derived>::bind(); }	\
  };


//! Used to help out argument dependent lookup for finding potential overloads
//! of instantiate_poly_bind
struct adl_tag {};

//! Tag for init_binding, bind_to_archives and instantiate_poly_bind. Due to the use of anonymous
//! namespace it becomes a different type in each translation unit.
namespace { struct polymorphic_binding_tag {}; }

template <class Archive, class T>
struct polymorphic_serialization_support;

//注册序列化对象 原始模板
template<class T, class BindingTag>
void instantiate_poly_bind(T*, int, BindingTag, adl_tag){}

//注册序列化对象 特例化模板宏
#define REGISTER_ARCHIVE(Archive)												\
template<class T, class BindingTag>												\
typename polymorphic_serialization_support<Archive, T>::type					\
instantiate_poly_bind(T*, Archive*, BindingTag, adl_tag);

template <class T, class Tag = polymorphic_binding_tag>
struct init_binding;


#define BIND_TO_ARCHIVES(...)											 \
	template<>															 \
    struct init_binding<__VA_ARGS__> {                                   \
        static bind_to_archives<__VA_ARGS__> const & b;                  \
    };                                                                   \
    bind_to_archives<__VA_ARGS__> const & init_binding<__VA_ARGS__>::b = \
        TSingleton<														 \
            bind_to_archives<__VA_ARGS__>                                \
        >::GetInstance().bind();										 


template <class T>
struct binding_name {};

//注册类
#define REGISTER_TYPE(...)												 \
  template <>                                                            \
  struct binding_name<__VA_ARGS__>                                       \
  {                                                                      \
     char const * name() { return #__VA_ARGS__; }						 \
  };                                                                     \
  BIND_TO_ARCHIVES(__VA_ARGS__)

struct PolymorphicCaster
{
	PolymorphicCaster() = default;
	PolymorphicCaster(const PolymorphicCaster &) = default;
	PolymorphicCaster & operator=(const PolymorphicCaster &) = default;
	PolymorphicCaster(PolymorphicCaster &&)  {}
	PolymorphicCaster & operator=(PolymorphicCaster &&)  { return *this; }
	virtual ~PolymorphicCaster() = default;

	//! Downcasts to the proper derived type
	virtual void const * downcast(void const * const ptr) const = 0;
	//! Upcast to proper base type
	virtual void * upcast(void * const ptr) const = 0;
};

//! Demangles the type encoded in a string
/*! @internal */
inline std::string demangle(std::string const & name)
{
	return name;
}

//! Gets the demangled name of a type
/*! @internal */
template <class T> inline
std::string demangledName()
{
	return typeid(T).name();
}

//! Holds registered mappings between base and derived types for casting
/*! This will be allocated as a StaticObject and holds a map containing
all registered mappings between base and derived types. */
struct PolymorphicCasters
{
	//! Maps from a derived type index to a set of chainable casters
	using DerivedCasterMap = std::unordered_map<std::type_index, PolymorphicCaster const *>;
	//! Maps from base type index to a map from derived type index to caster
	std::unordered_map<std::type_index, DerivedCasterMap> map;

	//! Error message used for unregistered polymorphic casts
#define UNREGISTERED_POLYMORPHIC_CAST_EXCEPTION(LoadSave)                                                                                                                \
        throw Exception("Trying to " #LoadSave " a registered polymorphic type with an unregistered polymorphic cast.\n"                                               \
                                "Could not find a path to a base class (" + demangle(baseInfo.name()) + ") for type: " + demangledName<Derived>() + "\n" \
                                "Make sure you either serialize the base class at some point via cereal::base_class or cereal::virtual_base_class.\n"                          \
                                "Alternatively, manually register the association with CEREAL_REGISTER_POLYMORPHIC_RELATION.");


	static std::pair<bool, PolymorphicCaster const *>
		lookup_if_exists(std::type_index const & baseIndex, std::type_index const & derivedIndex)
	{
		// First phase of lookup - match base type index
		auto const & baseMap = TSingleton<PolymorphicCasters>::GetInstance().map;
		auto baseIter = baseMap.find(baseIndex);
		if (baseIter == baseMap.end())
			return{ false,{} };

		// Second phase - find a match from base to derived
		auto const & derivedMap = baseIter->second;
		auto derivedIter = derivedMap.find(derivedIndex);
		if (derivedIter == derivedMap.end())
			return{ false,{} };

		return{ true, derivedIter->second };
	}

	template <class F> inline
		static PolymorphicCaster const * lookup(std::type_index const & baseIndex, std::type_index const & derivedIndex, F && exceptionFunc)
	{
		// First phase of lookup - match base type index
		auto const & baseMap = TSingleton<PolymorphicCasters>::GetInstance().map;
		auto baseIter = baseMap.find(baseIndex);
		if (baseIter == baseMap.end())
			exceptionFunc();

		// Second phase - find a match from base to derived
		auto const & derivedMap = baseIter->second;
		auto derivedIter = derivedMap.find(derivedIndex);
		if (derivedIter == derivedMap.end())
			exceptionFunc();

		return derivedIter->second;
	}

	//! Performs a downcast to the derived type using a registered mapping
	template <class Derived> inline
		static const Derived * downcast(const void * dptr, std::type_info const & baseInfo)
	{
		auto const & mapping = lookup(baseInfo, typeid(Derived), [&]() { /*UNREGISTERED_POLYMORPHIC_CAST_EXCEPTION(save)*/ });
		dptr = mapping->downcast(dptr);

		return static_cast<Derived const *>(dptr);
	}

	template <class Derived> inline
		static void * upcast(Derived * const dptr, std::type_info const & baseInfo)
	{
		auto const & mapping = lookup(baseInfo, typeid(Derived), [&]() { UNREGISTERED_POLYMORPHIC_CAST_EXCEPTION(load) });

		void * uptr = dptr;
		uptr = mapping->upcast(uptr);

		return uptr;
	}

};

template <class Base, class Derived>
struct PolymorphicVirtualCaster: PolymorphicCaster
{
	/*! In C++ much more is being determined at runtime before the user's main function runs.
	This is in order to allow proper construction of global and static objects
	//全局变量的初始化，只能通过构造函数初始化，进行绑定关系*/
	PolymorphicVirtualCaster()
	{
		const auto baseKey = std::type_index(typeid(Base));
		const auto derivedKey = std::type_index(typeid(Derived));

		// First insert the relation Base->Derived
		const auto lock = TSingleton<PolymorphicCasters>::lock();
		auto & baseMap = TSingleton<PolymorphicCasters>::GetInstance().map;
		{
			auto & derivedMap = baseMap.insert({ baseKey, PolymorphicCasters::DerivedCasterMap{} }).first->second;
			auto & derivedVec = derivedMap.insert({ derivedKey,{} }).first->second;
			derivedVec = this;
		}
	}

	void const * downcast(void const * const ptr) const override
	{
		return dynamic_cast<Derived const*>(static_cast<Base const*>(ptr));
	}

	void * upcast(void * const ptr) const override
	{
		return dynamic_cast<Base*>(static_cast<Derived*>(ptr));
	}
};


template <class Base, class Derived>
struct RegisterPolymorphicCaster
{
	static PolymorphicCaster const * bind(std::true_type /* is_polymorphic<Base> */)
	{
		return &TSingleton<PolymorphicVirtualCaster<Base, Derived>>::GetInstance();
	}

	static PolymorphicCaster const * bind(std::false_type /* is_polymorphic<Base> */)
	{
		return nullptr;
	}
	static PolymorphicCaster const * bind()
	{
		return bind(typename std::is_polymorphic<Base>::type());
	}
};



template <class T, class Tag = polymorphic_binding_tag>
struct bind_to_archives
{
	//! Binding for non abstract types
	void bind(std::false_type) const
	{
		instantiate_poly_bind(static_cast<T*>(nullptr), 0, Tag{}, adl_tag{});
	}

	//! Binding for abstract types
	void bind(std::true_type) const
	{ }

	//! Binds the type T to all registered archives
	/*! If T is abstract, we will not serialize it and thus
	do not need to make a binding */
	bind_to_archives const & bind() const
	{
		static_assert(std::is_polymorphic<T>::value,
			"Attempting to register non polymorphic type");
		bind(std::is_abstract<T>());
		return *this;
	}
};


template <class Archive>
struct BindingMap
{
	typedef std::function<void(void*, void const *, std::type_info const &)> Serializer;

	struct Serializers
	{
		Serializer cast2derived; //!< 类型转换及序列化
	};
	std::unordered_map<std::type_index, Serializers> map;
};


template <class Archive, class T>
struct BindingCreator
{
	//! Initialize the binding
	BindingCreator()
	{
		auto & map = TSingleton<BindingMap<Archive> >::GetInstance().map;
		auto key = std::type_index(typeid(T));
		auto ret = map.find(key);

		if (ret != map.end())
			return;

		typename BindingMap<Archive>::Serializers serializers;

		serializers.cast2derived =
			[&](void * arptr, void const * dptr, std::type_info const & baseInfo)
		{
			Archive & ar = *static_cast<Archive*>(arptr);
			auto ptr = PolymorphicCasters::template downcast<T>(dptr, baseInfo);
			ar(*ptr);
		};

		map.insert({ std::move(key), std::move(serializers) });
	}
};

//! Causes the static object bindings between an archive type and a serializable type T
template <class Archive, class T>
struct create_bindings
{
	static void bind()
	{
		TSingleton<BindingCreator<Archive, T> >::GetInstance();
	}
};


//! When specialized, causes the compiler to instantiate its parameter
template <void(*)()>
struct instantiate_function {};

template <class Archive, class T>
struct polymorphic_serialization_support
{
#if defined(_MSC_VER) && !defined(__INTEL_COMPILER)
	//! Creates the appropriate bindings depending on whether the archive supports
	//! saving or loading
	virtual DLL_EXPORT void instantiate() USED;
#else // NOT _MSC_VER
	//! Creates the appropriate bindings depending on whether the archive supports
	//! saving or loading
	static DLL_EXPORT void instantiate() USED;
	//! This typedef causes the compiler to instantiate this static function
	typedef instantiate_function<instantiate> unused;
#endif // _MSC_VER
};

// instantiate implementation
template <class Archive, class T>
DLL_EXPORT void polymorphic_serialization_support<Archive, T>::instantiate()
{
	printf("polymorphic_serialization_support\n");
	create_bindings<Archive, T>::bind();
}

