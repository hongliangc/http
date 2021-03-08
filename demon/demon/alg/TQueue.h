#pragma once
#include <stdio.h>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <chrono>
#include <thread>
#include <functional>
#include <sys/stat.h>
using namespace std;

#define CHECK_STATE(x)	\
if (x == false)			\
{						\
	return false;		\
}						\

#pragma pack(push,1)
typedef struct tagCanDate
{
	unsigned int m_time;
	unsigned short m_speed;
	unsigned int m_mileage;
}CanData,*LPCanData;
#pragma pack(pop)

typedef enum QueueProperty
{
	/* if the queue is full, the new frame will override the first*/
	eQueueOverride,
	/* if the queue is full, the new frame will be discarded*/
	eQueueDrop
}QueueProperty;


template<class _Ty = void>
struct compare
{
	// functor for construct
	compare(_Ty t)
	{
		m_data = t;
	}
	_Ty m_data;
	std::function<int(_Ty, _Ty)> m_fn;

	int operator()(const _Ty& obj) const
	{
		if (m_fn == NULL)
		{
			return -1;
		}
		return m_fn(m_data, obj);
	}
};

template<class T>
class TQueue
{
public:
	TQueue();
	~TQueue() = default;
public:
	bool Initial(unsigned int size, QueueProperty property = eQueueOverride);
	void Destroy();
	bool WriteData(T data);
	bool ReadData(T &data);
	bool Reset();
	bool Pop(unsigned int count = 1);
	bool IsFull();
	bool IsEmpty();
	unsigned int GetQueueUsedSize();
	unsigned int GetQueueSize();
	const T* operator[](unsigned int index);

	//get the first frame
	const T* head();

	//get the tail frame
	const T* tail();
	
	bool SaveFile(string path);

	bool LoadFile(string path);

	/*binary search all elements */
	template<class _Pr = compare<T> >
	const int BinarySearch(_Pr _Pred)
	{
		CHECK_STATE(m_state);
		std::unique_lock<Mutex> lock(m_mutex);
		unsigned int middle = 0, low = 0, high = m_used -1;
		int count = 0;
		while (low <= high)
		{
			count++;
			middle = (low + high) / 2;
			const T &data = m_frameQ[(m_head + middle) % m_size];
			int ret = _Pred(data);
			if (ret == 0){
				return middle;
			}
			else {
				if (low == high) {
					break;
				}

				if (ret > 0) {
					high = middle;
				}
				else {
					low = middle + 1;
				}
			}

			if (count > 1000) {
				break;
			}
		}
		return -1;
	}

	/*iterate over all elements */
	template<class _Pr = compare<T> >
	const int Search(_Pr _Pred)
	{
		CHECK_STATE(m_state);
		std::unique_lock<Mutex> lock(m_mutex);
		for (int i = 0; i < m_used; i++)
		{
			const T &data = m_frameQ[(m_head + i) % m_size];
			if (_Pred(data) == 0) {
				return i;
			}
		}
		return -1;
	}
private:
	/* std::mutex is not reentrant, the exception is thrown if we are trying to 
	lock mutex while the mutex is already owned by calling thread*/
	typedef std::recursive_mutex Mutex;
	bool			m_state;
	unsigned int	m_tail;
	unsigned int	m_head;
	unsigned int	m_size;
	unsigned int	m_used;
	QueueProperty	m_property;
	Mutex			m_mutex;
	T*				m_frameQ;
};

template<class T>
TQueue<T>::TQueue()
{
	m_size = 0;
	m_head = 0;
	m_tail = 0;
	m_used = 0;
	m_state = false;
	m_frameQ = NULL;
}


template<class T>
const T* TQueue<T>::operator[](unsigned int index)
{
	CHECK_STATE(m_state);
	std::unique_lock<Mutex> lock(m_mutex);
	if (index >= m_used)
	{
		return NULL;
	}
	return &(m_frameQ[(m_head + index) % m_size]);
}

//get the first frame
template<class T>
const T* TQueue<T>::head()
{
	CHECK_STATE(m_state);
	std::unique_lock<Mutex> lock(m_mutex);
	if (m_used == 0)
	{
		return NULL;
	}
	return &(m_frameQ[m_head % m_size]);
}

//get the tail frame
template<class T>
const T* TQueue<T>::tail()
{
	CHECK_STATE(m_state);
	std::unique_lock<Mutex> lock(m_mutex);
	if (m_used == 0)
	{
		return NULL;
	}
	return &(m_frameQ[(m_head + m_used - 1) % m_size]);
}

template<class T>
bool TQueue<T>::Initial(unsigned int size, QueueProperty property)
{
	CHECK_STATE(!m_state);
	if (size == 0)
	{
		return false;
	}
	m_size = size;
	m_frameQ = new T[m_size];
	if (m_frameQ == NULL)
	{
		return false;
	}
	m_state = true;
	Reset();
	m_property = property;
	return true;
}

template<class T>
void TQueue<T>::Destroy()
{
	std::unique_lock<Mutex> lock(m_mutex);
	Reset();
	m_state = false;
	if (!m_frameQ)
	{
		delete[] m_frameQ;
		m_frameQ = NULL;
	}
}

template<class T>
bool TQueue<T>::WriteData(T data)
{
	CHECK_STATE(m_state);
	std::unique_lock<Mutex> lock(m_mutex);
	if (IsFull())
	{
		if (m_property == eQueueOverride)
		{
			//the incoming frame will override the first if the queue is full
			m_head = (m_head + 1) % m_size;
			--m_used;
		}
		else
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
			return false;
		}
	}
	m_frameQ[m_tail] = data;
	++m_used;
	m_tail = (m_tail + 1) % m_size;
	return true;
}

template<class T>
bool TQueue<T>::ReadData(T &data)
{
	CHECK_STATE(m_state);
	std::unique_lock<Mutex> lock(m_mutex);
	if (IsEmpty())
	{
		//it will return if the queue is empty
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		return false;
	}
	data = m_frameQ[m_head];
	--m_used;
	m_head = (m_head + 1) % m_size;
	return true;
}

template<class T>
bool TQueue<T>::Reset()
{
	try
	{
		CHECK_STATE(m_state);
		std::unique_lock<Mutex> lock(m_mutex);
		if (m_frameQ != NULL)
		{
			memset(m_frameQ, 0, m_size * sizeof(T));
		}
		m_head = 0;
		m_tail = 0;
		m_used = 0;
	}
	catch (const std::exception &e)
	{
		std::cout << e.what() << endl;
		throw e;
	}
	return true;
}


template<class T>
bool TQueue<T>::Pop(unsigned int count)
{
	CHECK_STATE(m_state);
	std::unique_lock<Mutex> lock(m_mutex);
	//calculate how many frame to drop
	unsigned int popCount = m_used > count ? count : m_used;
	if (popCount < 1)
	{
		//the function returns if the count of pop frames is less than 1
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		return false;
	}
	m_used -= popCount;
	m_head = (m_head + popCount) % m_size;
	return true;
}

template<class T>
unsigned int TQueue<T>::GetQueueUsedSize()
{
	return m_used;
}

template<class T>
unsigned int TQueue<T>::GetQueueSize()
{
	return m_size;
}

template<class T>
bool TQueue<T>::IsFull()
{
	return  (m_used == m_size);
}

template<class T>
bool TQueue<T>::IsEmpty()
{
	return (m_used == 0);
}

template<class T>
bool TQueue<T>::SaveFile(string path)
{
	try
	{
		CHECK_STATE(m_state);
		std::unique_lock<Mutex> lock(m_mutex);
		if (path.length() == 0)
		{
			return false;
		}
		bool ret = true;
		FILE * fd = NULL;
#ifdef WIN32
	fopen_s(&fd, path.c_str(), "wb");
#else
	fd = fopen(path.c_str(), "wb");
#endif
		if (NULL != fd)
		{
			int total_len = 0;
			int len = 0;
			int offset = 0;
			int data_len = sizeof(T);
			int try_count = 0;
			for (int i = 0; i < m_used; i++)
			{
			const T &data = m_frameQ[(m_head + i) % m_size];
				while (offset != data_len)
				{
					len = fwrite(&data + offset, 1, data_len - offset, fd);
					if (len == -1)
					{
						if (++try_count > 3)
						{
							ret = false;
							break;
						}
						else
						{
							printf("SaveFile fwrite err:%d\n", errno);
						   std::this_thread::sleep_for(std::chrono::milliseconds(1));
							continue;
						}
					}
					offset += len;
					total_len += len;
				}
				try_count = 0;
				len = 0;
				offset = 0;
			}
			fflush(fd);
			fclose(fd);
		}
		else
		{
			printf("SaveFile fopen err:%d\n", errno);
			ret = false;
		}
		return ret;
	}
	catch (const std::exception& e)
	{
		cout << e.what() << endl;
		return false;
	}
}

template<class T >
bool TQueue<T>::LoadFile(string path)
{
	CHECK_STATE(m_state);
	std::unique_lock<Mutex> lock(m_mutex);
	if (path.length() == 0)
	{
		return false;
	}
	bool ret = true;
	struct stat st;
	if (::stat(path.c_str(), &st) != 0)
	{
		printf("LoadFile file is not exist!\n");
		return false;
	}
	FILE * fd = NULL;
#ifdef WIN32
	_off_t file_size = st.st_size;
	fopen_s(&fd, path.c_str(), "rb+");
#else
	off_t file_size = st.st_size;
	fd = fopen(path.c_str(), "rb+");
#endif
	if (NULL != fd)
	{
		int total_len = 0;
		int len = 0;
		int offset = 0;
		int try_count = 0;
		int data_len = sizeof(T);
		T data;
		Reset();
		for (; file_size >= total_len + data_len; )
		{
			memset(&data, 0, data_len);
			while (offset != data_len)
			{
				len = fread(&data + offset, 1, data_len - offset, fd);
				if (len == -1)
				{
					if (++try_count > 3)
					{
						ret = false;
						break;
					}
					else
					{
						printf("LoadFile fread err:%d\n", errno);
						std::this_thread::sleep_for(std::chrono::milliseconds(1));
						continue;
					}
				}
				offset += len;
				total_len += len;
				if (feof(fd) && offset != data_len)
				{
					//the function is return when the end indicator of file is set and offset is not equal data_len
					Reset();
					fclose(fd);
					printf("LoadFile file is end, the length is not right!\n");
					return ret;
				}
			}
			WriteData(data);
			try_count = 0;
			len = 0;
			offset = 0;
		}
		fclose(fd);
	}
	else
	{
		if(NULL != fd){
			fclose(fd);
		}
		ret = false;
	}
	return ret;
}