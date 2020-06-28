#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)

#项目名称
project(glfw)

#增加编译宏
#add_definitions(-D)
add_definitions(-DGLFW_NO_GLU)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w -g -DNDEBUG  -DHAVE_STRUCT_TIMESPEC -std=gnu++11  -DLINUX")  
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w -g -DNDEBUG -DHAVE_STRUCT_TIMESPEC -std=gnu++11 -DLINUX")
message("glfw CMakeLists")
message("glfw CMAKE_CXX_FLAGS is ${CMAKE_CXX_FLAGS}")
message("glfw CMAKE_C_FLAGS is ${CMAKE_C_FLAGS}")

#add_library(sdk STATIC IMPORTED)
#set_property(TARGET sdk PROPERTY IMPORTED_LOCATION ./libsdk.a)

#sdk include
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/linux)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/iconv)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/zlib)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/libpng)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/libjpeg)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/libtiff)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/libxml2)
#include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/pthread)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/OGLES)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/glfw/include)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/libttf)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/android/iconv)

include_directories(${APP_CONTENT_PATH}/glfw)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/glfw/include)
include_directories(${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/OGLES)


aux_source_directory(GLEW_SRC ${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/OGLES)
message("**********Update GLEW_SRC:${GLEW_SRC}")

aux_source_directory(glfw_SRC ${APP_PLATFORM_PATH}/src/KernalCore/cocos2dx/platform/third_party/linux/glfw/src/*)
message("**********Update glfw_SRC:${glfw_SRC}")
#sdk lib
link_directories(${APP_CONTENT_PATH}/glfw)
link_directories(${APP_CONTENT_PATH}/zlib_sdk/lib)
#参与编译的源文件
#root source files
aux_source_directory(. ROOT_SRC)

set(HELLO_SRC
	${GLEW_SRC}
	${glfw_SRC}
	${ROOT_SRC}
)

#附加编译选项
add_definitions(-fPIC)
message("HELLO_SRC:${HELLO_SRC}")
#生成库
add_executable(glfw ${HELLO_SRC})
add_dependencies(glfw pthread EGL GLESv2)
target_link_libraries(glfw pthread EGL GLESv2)


