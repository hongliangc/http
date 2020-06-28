#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)


#项目名称
project(module)

#增加编译宏
#add_definitions(-DXXX)

#附加包含目录
include_directories(${APP_CONTENT_PATH}/sdk)

#参与编译的源文件

aux_source_directory(. ROOT_SRC)

set(_src
	${ROOT_SRC}
)

#附加编译选项
add_definitions(-fPIC)

#生成库
add_library(module SHARED ${_src})




