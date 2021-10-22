@SETLOCAL

pushd %~dp0
@SET COMPILER_DEFINES=-DARCH_X64=1 -DPLATFORM_WINDOWS=1 -DBUILD_DEBUG=1
@SET COMPILER_FLAGS=-Fe:"out.exe" -W3 -WX -MTd -Zi -D_CRT_SECURE_NO_WARNINGS=1 %COMPILER_DEFINES% %COMPILER_INCLUDES%
@SET LINKER_LIBRARIES=shell32.lib ws2_32.lib
@SET LINKER_FLAGS=-subsystem:console -incremental:no -opt:ref -dynamicbase %LINKER_LIBRARIES%

@SET SRC="../blake2b.cc" "../btcz.cc" "../btcz_stratum.cc" "../common.cc" "../equihash.cc" "../json.cc" "../sha256.cc"

@REM @SET SRC="../proxy.cc"

mkdir .\build
pushd .\build
del .\*.dll .\*.exe .\*.exp .\*.ilk .\*lib .\*.obj .\*.pdb
cl -O2 %COMPILER_FLAGS% %SRC% /link %LINKER_FLAGS%
popd
popd

@ENDLOCAL
