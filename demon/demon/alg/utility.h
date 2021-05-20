#pragma once
#include <chrono>
#include <ctime>
#include <string>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <sstream>
namespace _utility
{

	static string ToHex(const string& s, bool upper_case = true)
	{
		ostringstream ret;
		ret << std::hex << std::setfill('0');
		for (unsigned char c : s)
			ret << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << int(c);

		cout << ret.str() << endl;
		return ret.str();
	}

	//transform strings to hex
	static bool ConvertStr2Hex(const unsigned char *in, int ilen, string &out)
	{
		if (ilen == 0 || in == NULL)
		{
			return false;
		}
		std::stringstream ss;
		for (int i = 0; i < ilen; i++)
		{
			//字符转换成16进制存放在ss中
			ss << std::hex << (in[i] >> 4) << (in[i] & 0x0f);
		}
		ss >> out;
		return true;
	}
	//transform hex to strings
	static bool ConvertHex2Str(const unsigned char *in, int ilen, string &out)
	{
		if (ilen == 0 || ilen % 2 != 0 || in == NULL)
		{
			return false;
		}
		out.resize(ilen / 2);
		std::stringstream s1;
		int temp = 0;
		for (int i = 0; i < ilen; i += 2)
		{
			//字符转换成16进制存放在ss中
			s1 << std::hex << in[i] << in[i + 1];
			//将16进制字符重定向到int数据中
			s1 >> temp;
			s1.clear();
			//字符串保存数据
			out[i / 2] = temp;
		}
		return true;
	}

	/*! 格式化数据*/
	template<typename ...Args>
	static string format(const std::string &format, Args ...args)
	{
		auto len = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
		std::unique_ptr<char[]> buf(new(std::nothrow) char[len]);
		if (!buf)
			return std::string("");
		std::snprintf(buf.get(), len, format.c_str(), args...);
		return std::string(buf.get(), buf.get() + len - 1);
	}

	enum class TimeType :uint8_t {
		year,
		month,
		day,
		hour,
		min,
		sec
	};
	class CDataTime
	{
	public:
		// 日期时间格式化的常量字符串"%Y-%m-%d %H:%M:%S";
		// 重命名system_clock名称空间
		using system_clk = std::chrono::system_clock;
		// 重命名time_point类型
		using _time_point = std::chrono::time_point<system_clk>;
	public:
		CDataTime() : m_begin(system_clk::now()) {}

		void reset() {
			m_begin = system_clk::now();
		}

		//std::chrono::microseconds,std::chrono::seconds
		template<class T>
		int64_t elapsed() const {
			return std::chrono::duration_cast<T>(system_clk::now() - m_begin).count();
		}

		time_t to_time() {
			return std::chrono::system_clock::to_time_t(m_begin);
		}

		// 将时间点信息转换为字符串的函数
		static string to_string(const _time_point& t, const std::string& date_fmt) {
			std::string result;
			std::time_t c_time_t = system_clk::to_time_t(t);
			char mbstr[100];

			struct tm  cur;
#ifdef WIN32
			if (localtime_s(&cur, &c_time_t) != 0)
#else
			if (localtime_r(&c_time_t, &cur) == NULL)
#endif
			{
				return "";
			}
			size_t size = std::strftime(mbstr, sizeof(mbstr), date_fmt.c_str(), &cur);
			if (size) {
				result = mbstr;
				return result;
			}
			return "";
		}

		// 将时间点信息转换为字符串的函数
		static string to_string(time_t c_time_t) {
			char mbstr[100];
			struct tm  cur;
#ifdef WIN32
			if (localtime_s(&cur, &c_time_t) != 0)
#else
			if (localtime_r(&c_time_t, &cur) == NULL)
#endif
			{
				return "";
			}
			size_t size = std::strftime(mbstr, sizeof(mbstr), "%Y-%m-%d %H:%M:%S", &cur);
			if (size) {
				string result = mbstr;
				return result;
			}
			return "";
		}
		

		// 将字符串转换为time_point的函数,默认时间格式"%Y-%m-%d %H:%M:%S"
		static _time_point from_string(const std::string &src_str) {
			std::stringstream ss;
			ss << src_str;
			//printf("%s,%d\n", ss.str().c_str(), ss.str().length());
			std::tm dt = {};
			ss >> std::get_time(&dt, "%Y-%m-%d %H:%M:%S");
			time_t c_time_t = std::mktime(&dt);
			auto time_pt = system_clk::from_time_t(c_time_t);
			return time_pt;
		}


		// 将字符串转换为time_point的函数
		static _time_point from_string(const std::string &src_str, const std::string& date_fmt) {
			std::stringstream ss;
			ss << src_str;
			//printf("%s,%d\n", ss.str().c_str(), ss.str().length());
			std::tm dt = {};
			ss >> std::get_time(&dt, date_fmt.c_str());
			time_t c_time_t = std::mktime(&dt);
			auto time_pt = system_clk::from_time_t(c_time_t);
			return time_pt;
		}


		/*将年月日，时分秒转换成 epoch time(the Unix epoch is 00:00:00 UTC on 1 January 1970 (an arbitrary date);) 时间*/
		static time_t to_epoch_time(uint16_t year, uint16_t month, uint16_t day, uint16_t hour, uint16_t min, uint16_t sec) {
			std::stringstream ss;
			ss << _utility::format("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec);
			printf("%s,%d\n", ss.str().c_str(), ss.str().length());
			std::tm dt = {};
			ss >> std::get_time(&dt, "%Y-%m-%d %H:%M:%S");
			time_t c_time_t = std::mktime(&dt);
			return c_time_t;
		}

		/*获取 epoch time时间(the Unix epoch is 00:00:00 UTC on 1 January 1970 (an arbitrary date);) */
		static time_t CurrentTime()
		{
			return std::chrono::duration_cast<std::chrono::seconds>(system_clk::now().time_since_epoch()).count();
		}

		static bool CheckValidTime(time_t c_time_t)
		{
			_time_point time = system_clk::from_time_t(c_time_t);
			/*debug调试时格式串需要补齐否则会有断言错误，std::get_time doesn't stop parsing the input stream 
			as soon as a mismatch is found or stream is eof, but continues until the format string is exhausted instead.
			This provokes a dereference of the input stream iterator even when it is at the eof.
			In debug builds it raises an assert. In release builds it is silently ignored.*/
			if (time < from_string("2020-01-01 00:00:00") || time > from_string("2040-1-1 00:00:00"))
			{
				return false;
			}
			return true;
		}


		/*将时间转换成年月日，时分秒*/
		template<TimeType type>
		static uint32_t to_datatime(std::time_t c_time_t) 
		{
			char mbstr[5];
			struct tm  cur;
			string format;
#ifdef WIN32
			localtime_s(&cur, &c_time_t);
#else
			localtime_r(&c_time_t, &cur);
#endif
			switch (type)
			{
			case TimeType::year:
				format = "%Y";
				break;
			case TimeType::month:
				format = "%m";
				break;
			case TimeType::day:
				format = "%d";
				break;
			case TimeType::hour:
				format = "%H";
				break;
			case TimeType::min:
				format = "%M";
				break;
			case TimeType::sec:
				format = "%S";
				break;
			default:
				break;
			}
			size_t size = std::strftime(mbstr, sizeof(mbstr), format.c_str(), &cur);
			if (size) {
				return stoi(mbstr);
			}
			return 0;
		}
	private:
		_time_point m_begin;
	};

}