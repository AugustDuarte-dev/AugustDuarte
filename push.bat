@echo off
echo ============================================
echo  AugustDuarte - Git Push Script
echo ============================================
echo.
set /p TOKEN="Paste your GitHub token then press Enter: "
echo.
echo Setting remote URL...
git -C "C:\Users\augustd_createme\Desktop\FTP" remote set-url origin https://%TOKEN%@github.com/AugustDuarte-dev/AugustDuarte.git

echo Staging all files...
git -C "C:\Users\augustd_createme\Desktop\FTP" add -A

echo Committing...
git -C "C:\Users\augustd_createme\Desktop\FTP" commit -m "Rewrite: Cloudflare Pages + Functions, remove Express server"

echo Pushing to GitHub...
git -C "C:\Users\augustd_createme\Desktop\FTP" push -u origin main

echo.
echo ============================================
echo Stripping token from remote URL for safety...
git -C "C:\Users\augustd_createme\Desktop\FTP" remote set-url origin https://github.com/AugustDuarte-dev/AugustDuarte.git
echo Done! Check github.com/AugustDuarte-dev/AugustDuarte
echo ============================================
pause
