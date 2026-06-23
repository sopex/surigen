# surigen
Suricata Rulegenerator

This software is forked from bl2ru2 https://github.com/conix-security/bl2ru2

Feel free to fork, push PRs or do whatever with it! 


How to build the OPNsense rules:

python3 surigen.py -o opnsense.social_media.rules -s 51000000 -e OPN_Social_Media social-media.lst

python3 surigen.py -o opnsense.messaging.rules -s 52000000 -e OPN_Messaging messaging.lst

python3 surigen.py -o opnsense.file_transfer.rules -s 53000000 -e OPN_File_Transfer file-transfer.lst

python3 surigen.py -o opnsense.mail.rules -s 54000000 -e OPN_Mail mail.lst

python3 surigen.py -o opnsense.media_streaming.rules -s 55000000 -e OPN_Media_Streaming streaming-media.lst

python3 surigen.py -o opnsense.adult.rules -s 56000000 -e OPN_Uncategorized uncategorized.lst
