
#define GLEW_STATIC
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <GL/glew.h>
#include <GL/glfw.h>
#include <assert.h>

bool initGL()
{
	GLenum GlewInitResult = glewInit();
	if (GLEW_OK != GlewInitResult) 
	{
		fprintf(stderr,"ERROR: %s\n",glewGetErrorString(GlewInitResult));
		return false;
	}

	if (GLEW_ARB_vertex_shader && GLEW_ARB_fragment_shader)
	{
		printf("Ready for GLSL\n");
	}
	else 
	{
		printf("Not totally ready :( \n");
	}

	if (glewIsSupported("GL_VERSION_2_0"))
	{
		printf("Ready for OpenGL 2.0\n");
	}
	else
	{
		printf("OpenGL 2.0 not supported\n");
	}
	return true;
}

void mouseButtonEventHandle(int iMouseID,int iMouseState) {
	printf("mouseButtonEventHandle\n");
	if (iMouseID == GLFW_MOUSE_BUTTON_LEFT) {
		//get current mouse pos
		int x,y;
		glfwGetMousePos(&x, &y);
		if (iMouseState == GLFW_PRESS) {
			printf("mouse is pressed, point x:%d,y:%d\n",x,y);

		} else if (iMouseState == GLFW_RELEASE) {
			printf("mouse is release, point x:%d,y:%d\n",x,y);
		}
	}
}

void mousePosEventHandle(int iPosX,int iPosY) {

	int iButtonState = 0;
	printf("mousePosEventHandle point x:%d,y:%d\n",iPosX,iPosY);
	
}

bool initExtensions() {
#define LOAD_EXTENSION_FUNCTION(TYPE, FN)  FN = (TYPE)glfwGetProcAddress(#FN);
	bool bRet = false;
	do {

		//		char* p = (char*) glGetString(GL_EXTENSIONS);
		//		printf(p);

		/* Supports frame buffer? */
		if (glfwExtensionSupported("GL_EXT_framebuffer_object") != GL_FALSE)
		{

			/* Loads frame buffer extension functions */
			LOAD_EXTENSION_FUNCTION(PFNGLGENERATEMIPMAPEXTPROC,
				glGenerateMipmapEXT);
			LOAD_EXTENSION_FUNCTION(PFNGLGENFRAMEBUFFERSEXTPROC,
				glGenFramebuffersEXT);
			LOAD_EXTENSION_FUNCTION(PFNGLDELETEFRAMEBUFFERSEXTPROC,
				glDeleteFramebuffersEXT);
			LOAD_EXTENSION_FUNCTION(PFNGLBINDFRAMEBUFFEREXTPROC,
				glBindFramebufferEXT);
			LOAD_EXTENSION_FUNCTION(PFNGLCHECKFRAMEBUFFERSTATUSEXTPROC,
				glCheckFramebufferStatusEXT);
			LOAD_EXTENSION_FUNCTION(PFNGLFRAMEBUFFERTEXTURE2DEXTPROC,
				glFramebufferTexture2DEXT);

		} else {
			break;
		}

		if (glfwExtensionSupported("GL_ARB_vertex_buffer_object") != GL_FALSE) {
			LOAD_EXTENSION_FUNCTION(PFNGLGENBUFFERSARBPROC, glGenBuffersARB);
			LOAD_EXTENSION_FUNCTION(PFNGLBINDBUFFERARBPROC, glBindBufferARB);
			LOAD_EXTENSION_FUNCTION(PFNGLBUFFERDATAARBPROC, glBufferDataARB);
			LOAD_EXTENSION_FUNCTION(PFNGLBUFFERSUBDATAARBPROC,
				glBufferSubDataARB);
			LOAD_EXTENSION_FUNCTION(PFNGLDELETEBUFFERSARBPROC,
				glDeleteBuffersARB);
		} else {
			break;
		}
		bRet = true;
	} while (0);
	return bRet;
}


int main( int argc,char *argv[] )
{
#if 1
	float width = 640;
	float height = 480;
	bool eResult = false;
	int u32GLFWFlags = GLFW_WINDOW;
	//create the window by glfw.

	//Inits GLFW
	eResult = glfwInit() != GL_FALSE;

	if (!eResult) {
		printf("fail to init the glfw");
	}

	/* Updates window hint */
	glfwOpenWindowHint(GLFW_WINDOW_NO_RESIZE, GL_TRUE);

	int iDepth = 16; // set default value
	eResult = (glfwOpenWindow(width, height, 5, 6, 5, 0, 16, 0, (int)u32GLFWFlags) != false) ? true : false;
	if(eResult)
	{

		/* Updates actual size */
		//		glfwGetWindowSize(&width, &height);

		/* Updates its title */
		glfwSetWindowTitle("hello egl");

		//register the glfw mouse event
		glfwSetMouseButtonCallback(mouseButtonEventHandle);
		//register the glfw mouse pos event
		glfwSetMousePosCallback(mousePosEventHandle);

		//Inits extensions
		//eResult = initExtensions();

		if (!eResult) {
			printf("fail to init the extensions of opengl");
		}
		initGL();
		while(1)
		{
			//drawScene();
			glfwSwapBuffers();
			glfwPollEvents();
		}
	}
	glfwTerminate();
	exit(EXIT_SUCCESS);
	return 0;
#else
	glfwSetErrorCallback(error_callback);
	if( !glfwInit() )
		{
			exit(EXIT_FAILURE);
		}
	window = glfwCreateWindow( 640, 480, "opengl tutorial 002-color box", NULL, NULL);
	if( window == NULL )
		{
			glfwTerminate();
			exit(EXIT_FAILURE);
		}
	glfwSetKeyCallback(window, key_callback);
	glfwSetFramebufferSizeCallback(window, framebuffer_size_callback);
	glfwSetMouseButtonCallback(window, mouse_button_callback);
	glfwSetCursorPosCallback(window, cursor_position_callback);
	glfwSetScrollCallback(window, scroll_callback);
	glfwMakeContextCurrent(window);
	glfwGetFramebufferSize(window, &width, &height);
	framebuffer_size_callback(window, width, height);
	glewExperimental = true; // Needed for core propbmpfile
	if (glewInit() != GLEW_OK)
		{
			exit(EXIT_FAILURE);
		}
	//initialize opengl
	init_opengl();
 
	while(!glfwWindowShouldClose(window))
		{
			draw_scene(window);
			glfwSwapBuffers(window);
			glfwPollEvents();
		}
	glfwTerminate();
	exit(EXIT_SUCCESS);
#endif
}
