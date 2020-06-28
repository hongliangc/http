#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)

#PLATFORM 定义编译平台，Linux、Linux_ARM、Linux_Android、Win32_ARM、Win32_Android
#VERSION  定义编译版本，Debug、Release


#定义依赖的App平台目录
if (UNIX)
	set(APP_CONTENT_PATH "/home/hongliangc/Dev/test")
	set(APP_PLATFORM_PATH "/home/hongliangc/Dev/VW510S2/07_APP/05_IMPLEMENT")
else()
	message(FATAL_ERROR "PlatForm is unknown!")	 
endif()

#设定编译器配置和编译选项

if(UNIX)
	STRING(TOLOWER "${PLATFORM}" PLATFORM)
	STRING(TOLOWER "${VERSION}" VERSION)
	message(WARNING " : " ${PLATFORM})
	message(WARNING "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	set(CMAKE_TOOLCHAIN_FILE "/home/hongliangc/Dev/test/toolchain.cmake")
	#message(WARNING "make target Platform:Linux_arm, Version:Release")
	#message(WARNING "toolchain : " ${CMAKE_TOOLCHAIN_FILE})
	#message(WARNING "CMAKE_CXX_COMPILER : " ${CMAKE_CXX_COMPILER})
else()
	message(FATAL_ERROR "PlatForm is unknown!")
endif()
	

message("**************************************before CMAKE_C_FLAGS:${CMAKE_C_FLAGS}")
message("**************************************before CMAKE_CXX_FLAGS:${CMAKE_CXX_FLAGS}")
#项目名称
project(Hello)
message("**************************************after ")

#配置工程输出位置
set(LIBRARY_OUTPUT_PATH "${APP_CONTENT_PATH}/Bin/${PLATFORM}/${VERSION}")
set(EXECUTABLE_OUTPUT_PATH "${APP_CONTENT_PATH}/Bin/${PLATFORM}/${VERSION}")

message("LIBRARY_OUTPUT_PATH is:" ${LIBRARY_OUTPUT_PATH})
message("EXECUTABLE_OUTPUT_PATH is:" ${EXECUTABLE_OUTPUT_PATH})


#附加链接库目录
#link_directories(${LIBRARY_OUTPUT_PATH})
if (${PLATFORM} MATCHES "Linux_ARM")
	link_directories(${APP_CONTENT_PATH}/lib)
	link_directories(${APP_CONTENT_PATH}/lib/gcc)
endif()


#增加子目录
add_subdirectory(${APP_CONTENT_PATH}/wayland)

