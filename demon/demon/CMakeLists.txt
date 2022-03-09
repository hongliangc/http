#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#PLATFORM 定义编译平台，Linux、Linux_ARM、Linux_Android、Win32_ARM、Win32_Android
#VERSION  定义编译版本，Debug、Release

#定义依赖的App平台目录，当前目录为app运行目录
set(APP_CONTENT_PATH ${CMAKE_CURRENT_LIST_DIR})

#设定编译器配置和编译选项
#set(CMAKE_TOOLCHAIN_FILE "${APP_CONTENT_PATH}/toolchain.cmake")
#set(CMAKE_TOOLCHAIN_FILE "Toolchain file" CACHE FILEPATH "${APP_CONTENT_PATH}/toolchain.cmake")
#set(CMAKE_TOOLCHAIN_FILE "${APP_CONTENT_PATH}/toolchain.cmake")


#引用编译器自带配置
if(0)
set(CMAKE_C_COMPILER   "gcc")
set(CMAKE_CXX_COMPILER   "g++")

endif()

SET(CMAKE_BUILD_TYPE "Debug")

#项目名称
project(test)

if(1)
	# 检查c++编译器标志，设置c++11支持变量
	include(CheckCXXCompilerFlag)
	CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
	CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)

	# 使用变量设置编译标志
	if(COMPILER_SUPPORTS_CXX11)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
	elseif(COMPILER_SUPPORTS_CXX0X)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
	else()
		message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
	endif()


	if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -w ")  
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -w")
	else()
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")  
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
	endif()
endif()

message("**************************************before CMAKE_C_FLAGS:${CMAKE_C_FLAGS}")
message("**************************************before CMAKE_CXX_FLAGS:${CMAKE_CXX_FLAGS}")

#配置工程输出位置
set(LIBRARY_OUTPUT_PATH "${APP_CONTENT_PATH}")
set(EXECUTABLE_OUTPUT_PATH "${APP_CONTENT_PATH}")

message("LIBRARY_OUTPUT_PATH is:" ${LIBRARY_OUTPUT_PATH})
message("EXECUTABLE_OUTPUT_PATH is:" ${EXECUTABLE_OUTPUT_PATH})



#增加子目录
add_subdirectory(${APP_CONTENT_PATH}/alg)

