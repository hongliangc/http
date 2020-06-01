#声明要求的最小版本   
cmake_minimum_required(VERSION 2.6)

STRING(TOLOWER "${PLATFORM}" PLATFORM)
STRING(TOLOWER "${VERSION}" VERSION)

message(WARNING "##################################TOOLCHAIN PLATFORM : " ${PLATFORM})
message(WARNING "###################################TOOLCHAIN VERSION : " ${VERSION})


#根据平台及编译版本配置编译器及编译选项	

	ADD_DEFINITIONS("-DLINUX")
    ADD_DEFINITIONS("-DHAVE_PTHREADS")
    
    SET(CMAKE_SYSTEM_NAME Linux)
    set( CMAKE_C_FLAGS $ENV{CFLAGS} CACHE STRING "" FORCE )
    set( CMAKE_CXX_FLAGS $ENV{CXXFLAGS}  CACHE STRING "" FORCE )
    set( CMAKE_ASM_FLAGS ${CMAKE_C_FLAGS} CACHE STRING "" FORCE )
    set( CMAKE_LDFLAGS_FLAGS ${CMAKE_CXX_FLAGS} CACHE STRING "" FORCE )
	#引用编译器自带配置
    set(CMAKE_C_COMPILER   "gcc")
    set(CMAKE_CXX_COMPILER   "g++")
    message(WARNING "222222222222222222222222222222222222222222222222222222222, ${CMAKE_FIND_ROOT_PATH}")
	
	# where is the target environment 
	set(CMAKE_FIND_ROOT_PATH $ENV{OECORE_TARGET_SYSROOT} $ENV{OECORE_NATIVE_SYSROOT} )
	# search for programs in the build host directories
	set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER )
	# for libraries and headers in the target directories
	set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY )
	set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY )
	set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY )


	#配置编译命令选项
	if (${VERSION} MATCHES "debug")
		SET(PLATFORM Linux_ARM)
		SET(VERSION Debug)
		SET(CMAKE_BUILD_TYPE Debug)

		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEGL_API_FB -std=gnu++11  -g -w  –DDEBUG  -DLINUX")  
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DEGL_API_FB -std=gnu++11  -g -w  –DDEBUG  -DLINUX")
		message(WARNING "333333333333333333333333333333333333333333333333333333 debug")
	else()
		SET(PLATFORM Linux_ARM)
		SET(VERSION Release)
		SET(CMAKE_BUILD_TYPE Release)
		
		#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w  -O3 -DNDEBUG  -DLINUX")  
		#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w  -O3 -DNDEBUG  -DLINUX")
		message(WARNING "1111111111111111111111111111111111111111111111111111111 release")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEGL_API_FB -std=gnu++11  -w -g -O3 -rdynamic -DNDEBUG  -DLINUX")  
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DEGL_API_FB -std=gnu++11 -w -g -O3 -rdynamic -DNDEBUG  -DLINUX")
		
	message("**************************************toolchain CMAKE_C_FLAGS:${CMAKE_C_FLAGS}")
	message("**************************************toolchain CMAKE_CXX_FLAGS:${CMAKE_CXX_FLAGS}")
	endif()
	

if(NOT DEFINED CONFIG_TRACE)
    set(CONFIG_TRACE "complete")
	message("PLATFORM is:" ${PLATFORM})
	message("VERSION is:" ${VERSION})
	message("CMAKE_BUILD_TYPE is:" ${CMAKE_BUILD_TYPE})
endif()
