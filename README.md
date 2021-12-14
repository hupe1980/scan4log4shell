# scan4log4shell
> Scanner to send specially crafted requests and catch callbacks of systems that are impacted by Log4J Log4Shell vulnerability

CVE-2021-44228 is a remote code execution (RCE) vulnerability in Apache Log4j 2. An unauthenticated, remote attacker could exploit this flaw by sending a specially crafted request to a server running a vulnerable version of log4j. The crafted request uses a Java Naming and Directory Interface (JNDI) injection via a variety of services including:
- Lightweight Directory Access Protocol (LDAP)
- Secure LDAP (LDAPS)
- Remote Method Invocation (RMI)
- Domain Name Service (DNS)

:warning: The scanner is still in an early phase.

## Usage 
```bash
Usage of scan4log4shell:
  -caddr string
    	address to catch the callbacks (eg. ip:port)
  -cidr string
    	subnet to scan (default 192.168.1.0/28) (default "192.168.1.0/28")
  -listen
    	start a listener to catch callbacks (default false)
  -no-user-agent-fuzzing
    	exclude User-Agent header from fuzzing (default false)
  -ports string
    	ports (comma separated) to scan (default 8080) (default "8080")
  -schema string
    	schema to use for requests (default "https")
  -waf-bypass
    	extend scans with WAF bypass payload (default false)
```

## Example
```bash
make run-test

scanner_1  | 2021/12/14 06:20:06 [i] Log4Shell CVE-2021-44228 Vulnerability Scanner dev
scanner_1  | 2021/12/14 06:20:06 [i] Listening on 172.20.0.30:4444
scanner_1  | 2021/12/14 06:20:06 [i] Start scanning 172.20.0.0/24 CIDR
scanner_1  | ---------
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.0:8080
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.1:8080
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.2:8080
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.3:8080
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.4:8080
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.5:8080
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.6:8080
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.7:8080
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.8:8080
scanner_1  | 2021/12/14 06:20:06 [i] Checking http://172.20.0.9:8080
scanner_1  | 2021/12/14 06:20:07 [i] Checking http://172.20.0.10:8080
scanner_1  | 2021/12/14 06:20:07 [i] Checking http://172.20.0.11:8080
scanner_1  | 2021/12/14 06:20:07 [i] Checking http://172.20.0.12:8080
scanner_1  | 2021/12/14 06:20:07 [i] Checking http://172.20.0.13:8080
scanner_1  | 2021/12/14 06:20:07 [i] Checking http://172.20.0.14:8080
scanner_1  | 2021/12/14 06:20:07 [i] Checking http://172.20.0.15:8080
scanner_1  | 2021/12/14 06:20:07 [!] Possibly vulnerable host identified: 172.20.0.15:45948
```

## References
- https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228


## License
[MIT](LICENCE)
