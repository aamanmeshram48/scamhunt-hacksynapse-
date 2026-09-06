@if "%DEBUG%"=="" @echo off
@setlocal
set DIRNAME=%~dp0
if "%DIRNAME%"=="" set DIRNAME=.
set APP_BASE_NAME=%~n0
set APP_HOME=%DIRNAME%

@rem Resolve Java executable
if defined JAVA_HOME goto execute
set JAVA_EXE=java.exe
goto execute
:execute
if defined JAVA_HOME set JAVA_EXE=%JAVA_HOME%\bin\java.exe
"%JAVA_EXE%" -Dorg.gradle.appname=%APP_BASE_NAME% -classpath "%APP_HOME%gradle\wrapper\gradle-wrapper.jar;%APP_HOME%gradle\wrapper\gradle-wrapper-shared-9.2.0.jar;%APP_HOME%gradle\wrapper\gradle-cli-9.2.0.jar" org.gradle.wrapper.GradleWrapperMain %*
exit /b %ERRORLEVEL%
endlocal
