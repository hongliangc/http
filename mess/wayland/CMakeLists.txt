#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)

#项目名称
project(wayland_demon)

#增加编译宏
#add_definitions(-D)
add_definitions(-DGLFW_NO_GLU)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w -g -DNDEBUG  -DHAVE_STRUCT_TIMESPEC -std=gnu++11  -DLINUX")  
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w -g -DNDEBUG -DHAVE_STRUCT_TIMESPEC -std=gnu++11 -DLINUX")
message("wayland_demon CMAKE_CXX_FLAGS is ${CMAKE_CXX_FLAGS}")
message("wayland_demon CMAKE_C_FLAGS is ${CMAKE_C_FLAGS}")

#add_library(sdk STATIC IMPORTED)
#set_property(TARGET sdk PROPERTY IMPORTED_LOCATION ./libsdk.a)


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
add_executable(wayland_demon ${HELLO_SRC})
add_dependencies(wayland_demon pthread EGL GLESv2 wayland-client)
target_link_libraries(wayland_demon pthread EGL GLESv2 wayland-client)


