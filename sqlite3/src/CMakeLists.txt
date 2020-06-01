#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)

#PLATFORM 定义编译平台，Linux、Linux_ARM、Linux_Android、Win32_ARM、Win32_Android
#VERSION  定义编译版本，Debug、Release

#项目名称
project(sqlite_test)

#附加链接库目录
include_directories(${APP_CONTENT_PATH}/sdk/include)
link_directories(${APP_CONTENT_PATH}/sdk/lib)

#参与编译的源文件
aux_source_directory(. ROOT_SRC)

set(SQLITE_SRC
	${ROOT_SRC}
)

#附加编译选项
add_definitions(-fPIC)
#生成库
add_executable(sqlite_test ${SQLITE_SRC})
add_dependencies(sqlite_test pthread sqlite3)
target_link_libraries(sqlite_test pthread sqlite3)
