@echo off
set "args=%*"
set "args=%args:-Command =%"
cmd /c %args%
