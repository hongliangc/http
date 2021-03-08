#pragma once
#include <type_traits>
#include <typeindex>


#ifndef SERIALIZE_FUNCTION_NAME
//! The serialization/deserialization function name to search for.
#define SERIALIZE_FUNCTION_NAME serialize
#endif

#ifndef SERIALIZE_ARR_FUNCTION_NAME
//! The serialization/deserializatio function name to search for.
#define SERIALIZE_ARR_FUNCTION_NAME serialize_array
#endif 
namespace traits
{
	/*! A class that can be made a friend to give access to non public member functions
		@code{.cpp}
		class MyClass
		{
			private:
			friend class cereal::access; // gives access to the private serialize

			template <class Archive>
			void serialize( Archive & ar )
			{
			// some code
			}
		};		
	*/
	class access
	{
	public:
		template<class Archive, class T>
		inline static auto member_serialize(Archive &ar, T &t)->decltype(t.SERIALIZE_FUNCTION_NAME(ar))
		{
			return t.SERIALIZE_FUNCTION_NAME(ar);
		}

	};

	using yes = std::true_type;
	using no = std::false_type;

	//! Return type for SFINAE Enablers
	enum class SFinae {};
	static const SFinae sfinae = {};

	//! Helper functionality for boolean integral constants and Enable/DisableIf
	template<bool H, bool ...T> struct meta_bool_and : std::integral_constant<bool, H & meta_bool_and<T...>::value> {};
	template<bool B> struct meta_bool_and<B> : std::integral_constant<bool, B>{};

	template<bool H, bool ...T> struct meta_bool_or : std::integral_constant<bool, H || meta_bool_or<T...>::value> {};
	template<bool B> struct meta_bool_or<B> : std::integral_constant<bool, B> {};

	template<bool ...Conditions>
	struct EnableIfHelper: std::enable_if<meta_bool_and<Conditions...>::value, SFinae> {};
	template<bool ...Conditions>
	struct DiableIfHelper: std::enable_if<!meta_bool_or<Conditions...>::value, SFinae> {};
	//! Provides a way to enable a function if conditions are met
	template<bool ...Conditions>
	using EnableIf = typename EnableIfHelper<Conditions...>::type;

#define MAKE_HAS_NON_MEMBER_TEST(test_name, fun)														\
	template<class T,class A>																			\
	struct has_##test_name##_impl 																		\
	{																									\
		template<class TT, class AA>																	\
		static auto test(int)->decltype(fun( std::declval<AA&>(),std::declval<TT&>()), yes());			\
		template<class, class>																			\
		static no test(...);																			\
		static bool const value = std::is_same<decltype(test<T, A>(0)), yes>::value;					\
	};																									\
	template<class T,class A>																			\
	struct has_##test_name:std::integral_constant<bool,has_##test_name##_impl<T,A>::value> {};

	MAKE_HAS_NON_MEMBER_TEST(serialize, serialize);
	MAKE_HAS_NON_MEMBER_TEST(serialize_array, serialize_array);



	//########################################################################################
#define MAKE_HAS_MEMBER_SERIALIZE_TEST(test_name)																		    \
																															\
      template <class T, class A>                                                                                           \
      struct has_member_##test_name##_impl																					\
      {                                                                                                                     \
        template <class TT, class AA>                                                                                       \
		static auto test(int) -> decltype(std::declval<TT&>().SERIALIZE_FUNCTION_NAME(std::declval<AA&>()), yes());			\
		template <class, class> static no test(...);                                                                        \
        static const bool value = std::is_same<decltype(test<T, A>(0)), yes>::value;										\
																															\
	    template<class TT,class AA>																							\
		static auto test1(int) -> decltype(access::member_##test_name( std::declval<AA&>(), std::declval<TT&>()), yes());	\
		template<class, class> static no test1(...);																		\
		static const bool value1 = std::is_same<decltype(test1<T, A>(0)), yes>::value;										\
      };																													\
                                                                                                                            \
    template <class T, class A>                                                                                             \
    struct has_member_##test_name : std::integral_constant<bool, (/*has_member_##test_name##_impl<T, A>::value ||*/ has_member_##test_name##_impl<T, A>::value1) > {};
	// ######################################################################
	// Non Member Save
	MAKE_HAS_MEMBER_SERIALIZE_TEST(serialize)

}