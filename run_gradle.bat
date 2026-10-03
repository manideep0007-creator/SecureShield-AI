@echo off
cd android
call gradlew.bat clean test assembleDebug
