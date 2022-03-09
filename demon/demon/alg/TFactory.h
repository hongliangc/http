#pragma once
#include <hwApp/Common.h>
#include "TSingleton.h"
template<typename Product, typename ConcreteProduct>
class ConcreteFactory
{
public:
	static Product* CreateProduct()
	{
		return new ConcreteProduct();
	}
};

template<typename Product>
class Creator
{
public:
	static Creator& Instance()
	{
		static Creator<Product> m_instance;
		return m_instance;
	}
public:
	typedef Product* (*CreateProductDelegate)();
	typedef map<int,CreateProductDelegate> MapRegisterCreatorItem;
	template<typename ConcreteProduct>
	void registerCreator(const int id)
	{
		m_RegisterConcreteItem[id] = ConcreteFactory<Product,ConcreteProduct>::CreateProduct;
	}
	void unregisterAllProduct()
	{
		typename MapRegisterCreatorItem::iterator itr = m_RegisterConcreteItem.begin();
		m_RegisterConcreteItem.clear();
	}
	Product * createProduct(const int id)
	{
		typename MapRegisterCreatorItem::iterator itr = m_RegisterConcreteItem.find(id);
		if (m_RegisterConcreteItem.end() != itr)
		{
			CreateProductDelegate create = itr->second;
			if (NULL != create)
			{
				return create();
			}
		}
		return 0;
	}
public:
	Creator() {}
	Creator(const Creator&){}
	~Creator(){}
private:
	MapRegisterCreatorItem m_RegisterConcreteItem;
};

template<class Base, class Derived, ePacketTypeId Id>
struct RegisterBinding;

//primitive template
template<class Base, class Derived, ePacketTypeId Id>
struct RegisterProduct;

#define REISTER_PRODUCT(Base,Derived,Id)	\
template<>										\
struct RegisterProduct<Base,Derived,Id>		\
{	/*使用register方法会报错，多个存储类型*/\
	static void bind(){ RegisterBinding<Base,Derived,Id>::bind(); }\
};


template<class Base, class Derived, ePacketTypeId Id>
struct RegisterBinding
{
	RegisterBinding()
	{
		TSingleton<Creator<Base> >::GetInstance().registerCreator<Derived>(static_cast<int>(Id));
	}
	static void bind(std::true_type)
	{
		TSingleton<RegisterBinding<Base, Derived, Id>>::GetInstance();
	}
	static void bind(std::false_type) {}
	static void const bind()
	{
		bind(std::is_polymorphic<Base>{});
	}
};
