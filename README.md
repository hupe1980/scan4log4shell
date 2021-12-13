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
    	address to catch the callbacks
  -cidr string
    	subnet to scan (default "192.168.1.0/28")
  -listen
    	start a listener to receiving callbacks (default false)
  -ports string
    	ports (comma separated) to scan (default "8080")
```

## Reference
https://nvd.nist.gov/vuln/detail/CVE-2021-44228


## License
[MIT](LICENCE)
