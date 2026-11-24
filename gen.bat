@echo off
setlocal
cd /d "%~dp0"

if exist ".venv_old\Scripts\python.exe" (
    set "PY=.venv_old\Scripts\python.exe"
) else if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else if exist "..\muse-old-proxy\.venv_old\Scripts\python.exe" (
    set "PY=..\muse-old-proxy\.venv_old\Scripts\python.exe"
) else (
    set "PY=python"
)

if exist "gen\gen.py" (
    "%PY%" gen\gen.py %* || goto :err
) else if exist "..\muse-gen\gen\gen.py" (
    "%PY%" ..\muse-gen\gen\gen.py %* || goto :err
) else (
    echo [i] Generator lokal tidak ditemukan ^(gen\gen.py / ..\muse-gen\gen\gen.py^) - cek perubahan input/ saja.
)

if not exist "input\" goto :nochange
git rev-parse --is-inside-work-tree >nul 2>&1 || goto :nochange
git remote get-url origin >nul 2>&1 || goto :noremote
for /f "delims=" %%B in ('git rev-parse --abbrev-ref HEAD 2^>nul') do set "CUR_BR=%%B"
if "%CUR_BR%"=="" set "CUR_BR=main"

git add -- input/ || goto :gitwarn
git diff --cached --quiet -- input/
if errorlevel 2 goto :gitwarn
if not errorlevel 1 goto :nochange

echo [*] Pull ^& push folder input/ ke origin/%CUR_BR%...
git pull --rebase --autostash origin "%CUR_BR%" || (
    git rebase --abort >nul 2>&1
    goto :gitwarn
)
git commit -m "update input combos" -- input/ || goto :gitwarn
git push origin "%CUR_BR%" || goto :gitwarn
echo [OK] input/ berhasil di-commit ^& push.
goto :end

:noremote
echo [i] Remote origin belum diset ^(jalankan git remote add origin ^<url^>^) - push dilewati.
goto :end

:gitwarn
echo [!] Selesai, namun auto-push git dilewati/gagal.
goto :end

:nochange
echo [*] Tidak ada perubahan baru di folder input/.
goto :end

:err
echo [!] Gagal menjalankan gen.bat.
if "%~1"=="" pause
exit /b 1

:end
if "%~1"=="" pause
exit /b 0
