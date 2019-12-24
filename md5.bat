@ECHO OFF
set ROOT=%_CWD
copy /z /q md5.log md5-old.log
copy c:\applications\cmdline\blank.txt "%ROOT\md5.log"
global /i for %n in (*.jpg *.png *.bmp *.arw *.mp3 *.wav *.flac *.zip *.rar *.avi *.mpg *.flv *.asf *.wmv *.mp4 *.mkv *.m2ts *.mts *.ts *.rmvb *.iso) do md5hash %1 -min 16KB -target "%n" >> "%ROOT\md5.log"
REM global /i for %n in (*.jpg *.png *.bmp *.arw *.mp3 *.wav *.flac *.zip *.rar *.avi *.mpg *.flv *.asf *.wmv *.mp4 *.mkv *.m2ts *.mts *.ts *.rmvb *.iso) do md5hash %1 -min  -target "%n"
