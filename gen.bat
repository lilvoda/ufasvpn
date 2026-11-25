@echo off
setlocal
cd /d "%~dp0"

if not exist "input\" (
    echo [!] Folder input\ tidak ditemukan.
    goto :err
)
git rev-parse --is-inside-work-tree >nul 2>&1 || (
    echo [!] Direktori ini bukan git repo.
    goto :err
)
git remote get-url origin >nul 2>&1 || (
    echo [!] Remote origin belum diset ^(jalankan: git remote add origin ^<url^>^).
    goto :err
)

for /f "delims=" %%B in ('git rev-parse --abbrev-ref HEAD 2^>nul') do set "CUR_BR=%%B"
if "%CUR_BR%"=="" set "CUR_BR=main"

git add -A -- input/ || goto :err
git diff --cached --quiet -- input/
if errorlevel 2 goto :err
if not errorlevel 1 (
    echo [*] Tidak ada perubahan baru di folder input/.
    goto :end
)

echo [*] Commit ^& push folder input/ ke origin/%CUR_BR%...
git commit -m "sync input combos" -- input/ || goto :err
git pull --rebase --autostash origin "%CUR_BR%" || (
    git rebase --abort >nul 2>&1
    goto :err
)
git push origin "%CUR_BR%" || goto :err
echo [OK] Folder input/ berhasil di-push ke origin/%CUR_BR%.
goto :end

:err
echo [!] Sinkronisasi input/ gagal.
if "%~1"=="" pause
exit /b 1

:end
if "%~1"=="" pause
exit /b 0
