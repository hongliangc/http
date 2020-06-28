#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)

#PLATFORM 定义编译平台，Linux、Linux_ARM、Linux_Android、Win32_ARM、Win32_Android
#VERSION  定义编译版本，Debug、Release

#定义依赖的App平台目录，当前目录为app运行目录
set(APP_CONTENT_PATH ${CMAKE_CURRENT_LIST_DIR})

#设定编译器配置和编译选项
set(CMAKE_TOOLCHAIN_FILE "toolchain.cmake")

message("**************************************before CMAKE_C_FLAGS:${CMAKE_C_FLAGS}")
message("**************************************before CMAKE_CXX_FLAGS:${CMAKE_CXX_FLAGS}")
#项目名称
project(test)

#配置工程输出位置
set(LIBRARY_OUTPUT_PATH "${APP_CONTENT_PATH}")
set(EXECUTABLE_OUTPUT_PATH "${APP_CONTENT_PATH}")

message("LIBRARY_OUTPUT_PATH is:" ${LIBRARY_OUTPUT_PATH})
message("EXECUTABLE_OUTPUT_PATH is:" ${EXECUTABLE_OUTPUT_PATH})



#增加子目录
add_subdirectory(${APP_CONTENT_PATH}/sdk)
add_subdirectory(${APP_CONTENT_PATH}/src)

