#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


#定义依赖的App平台目录，当前目录为app运行目录
set(APP_CONTENT_PATH ${CMAKE_CURRENT_LIST_DIR})

message("**************************************before CMAKE_C_FLAGS:${CMAKE_C_FLAGS}")
message("**************************************before CMAKE_CXX_FLAGS:${CMAKE_CXX_FLAGS}")
#项目名称
project(test)

#设定编译器配置和编译选项

if(0)
	#if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
	if(1)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -w -m32")  
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -w -m32")
	else()
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -m32")  
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -m32")
	endif()
#附加链接库目录
include_directories(${APP_CONTENT_PATH}/sdk/include)
link_directories(${APP_CONTENT_PATH}/sdk/)
else()
	#if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
	if(1)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -w")  
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -w")
	else()
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")  
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
	endif()
#附加链接库目录
include_directories(${APP_CONTENT_PATH}/sdk_x86/include)
link_directories(${APP_CONTENT_PATH}/sdk_x86/)
endif()



#配置工程输出位置
set(LIBRARY_OUTPUT_PATH "${APP_CONTENT_PATH}")
set(EXECUTABLE_OUTPUT_PATH "${APP_CONTENT_PATH}")

message("LIBRARY_OUTPUT_PATH is:" ${LIBRARY_OUTPUT_PATH})
message("EXECUTABLE_OUTPUT_PATH is:" ${EXECUTABLE_OUTPUT_PATH})


message("**************************************after CMAKE_C_FLAGS:${CMAKE_C_FLAGS}")
message("**************************************after CMAKE_CXX_FLAGS:${CMAKE_CXX_FLAGS}")

#增加子目录
add_subdirectory(${APP_CONTENT_PATH}/src)

