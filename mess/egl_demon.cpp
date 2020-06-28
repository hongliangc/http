 #include <EGL/egl.h>
 #include <stdio.h>
 #include <stdlib.h>

  static const EGLint configAttribs[] = {
          EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
          EGL_BLUE_SIZE, 8,
          EGL_GREEN_SIZE, 8,
          EGL_RED_SIZE, 8,
          EGL_DEPTH_SIZE, 8,
          EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
          EGL_NONE
  };    

  static const int pbufferWidth = 9;
  static const int pbufferHeight = 9;

  static const EGLint pbufferAttribs[] = {
        EGL_WIDTH, pbufferWidth,
        EGL_HEIGHT, pbufferHeight,
        EGL_NONE,
  };

int main(int argc, char *argv[])
{
	int a =0;
	void *p = &a;
	int b = *(int*)(p);
  // 1. Initialize EGL
  EGLDisplay eglDpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  if (eglDpy == EGL_NO_DISPLAY || eglGetError() != EGL_SUCCESS)
  {
	  printf("eglGetDisplay failed ,m_glesDisplay:%d eglGetError:%d\n",  (unsigned int)eglDpy,eglGetError());
	  return false;
  }

  EGLint major, minor;

  if(!eglInitialize(eglDpy, &major, &minor))
  {
	  printf("eglInitialize failed eglGetError:%d\n",  (unsigned int)eglDpy,eglGetError());
	  return false;
  }

  // 2. Select an appropriate configuration
  EGLint numConfigs;
  EGLConfig eglCfg;

  if(!eglChooseConfig(eglDpy, configAttribs, &eglCfg, 1, &numConfigs))
  {
	  printf("eglChooseConfig failed eglGetError:%d\n",  (unsigned int)eglDpy,eglGetError());
	  return false;
  }

  // 3. Create a surface
  EGLSurface eglSurf = eglCreatePbufferSurface(eglDpy, eglCfg, 
                                               pbufferAttribs);
  if(!eglSurf || eglGetError() != EGL_SUCCESS)
  {

	  printf("eglCreatePbufferSurface failed, eglGetError:%d\n", eglGetError());
	  return false;
  }

  // 4. Bind the API
  eglBindAPI(EGL_OPENGL_API);

  // 5. Create a context and make it current
  EGLContext eglCtx = eglCreateContext(eglDpy, eglCfg, EGL_NO_CONTEXT, 
                                       NULL);

  eglMakeCurrent(eglDpy, eglSurf, eglSurf, eglCtx);

  // from now on use your OpenGL context
	
  // 6. Terminate EGL when finished
  eglTerminate(eglDpy);

  printf(" Terminate EGL when finished**********************\n");
  return 0;
}