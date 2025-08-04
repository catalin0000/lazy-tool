
# A tool that automates some boring stuff.


Basically here is what it does:

- it can start responder on a jumpbox(over ssh)
- it can grab smb signing off systems and start responder+ntlmrelayx on a jumpbox(over ssh) 
- grabs ntds.dit and system files from the target system over a jumpbox(using ssh) after that it will also attempt to dump it using secretsdump locally
- it can do roasting over a jumpbox(using ssh)
- dumps the users(normal enabled users, high priv users separated) over a jumpbox(using ssh)
- it can also start some nmap scans on the jumpbox if you use the yaml file


For instructions on how to use, just run it with `-h` option. additionally you can run each module witt `-h` option.

I've added a requirements file with what i believed it's not by default just in case but honestly just run the script and if something is missing it should tell you what :). 



