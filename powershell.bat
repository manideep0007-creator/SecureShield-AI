@echo off
if "%~1"=="-Command" (
    cmd /c %~2
) else (
    cmd /c %*
)
