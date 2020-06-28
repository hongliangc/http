#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)

#PLATFORM 定义编译平台，Linux、Linux_ARM、Linux_Android、Win32_ARM、Win32_Android
#VERSION  定义编译版本，Debug、Release

#项目名称
project(test)

#附加链接库目录
include_directories(${APP_CONTENT_PATH}/sdk)
link_directories(${APP_CONTENT_PATH})

#参与编译的源文件
aux_source_directory(. ROOT_SRC)

set(_SRC
	${ROOT_SRC}
)

#附加编译选项
add_definitions(-fPIC)
#生成库
add_executable(test ${_SRC})
add_dependencies(test  module)
target_link_libraries(test  module)
