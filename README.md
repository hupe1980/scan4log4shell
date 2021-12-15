# scan4log4shell
> Scanner to detect vulnerable log4j versions on your file-system or to send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability (CVE-2021-44228)

CVE-2021-44228 is a remote code execution (RCE) vulnerability in Apache Log4j 2. An unauthenticated, remote attacker could exploit this flaw by sending a specially crafted request to a server running a vulnerable version of log4j. The crafted request uses a Java Naming and Directory Interface (JNDI) injection via a variety of services including:
- Lightweight Directory Access Protocol (LDAP)
- Secure LDAP (LDAPS)
- Remote Method Invocation (RMI)
- Domain Name Service (DNS)

:warning: The scanner is still in an early phase.

## Usage 
```bash
Usage:
  scan4log4shell [command]

Available Commands:
  completion  Prints shell autocompletion scripts for scan4log4shell
  help        Help about any command
  local       Detect vulnerable log4j versions on your file-system
  remote      Send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability

Flags:
  -h, --help      help for scan4log4shell
  -v, --verbose   print detailed logging messages
      --version   version for scan4log4shell

Use "scan4log4shell [command] --help" for more information about a command.
```

## Local
Detect vulnerable log4j versions on your file-system
```bash
Usage:
  scan4log4shell local [paths] [flags]

Flags:
  -h, --help                     help for local
      --ignore-ext stringArray   ignore .jar | .zip | .war | .ear | .aar
      --ignore-v1                ignore log4j 1.x versions

Global Flags:
  -v, --verbose   print detailed logging messages
```

### Example
```bash
make run-local

2021/12/15 23:46:25 [i] Log4Shell CVE-2021-44228 Local Vulnerability Scan
2021/12/15 23:50:24 [i] Start scanning path ./testdata/filewalk
---------
2021/12/15 23:46:25 [i] Inspecting testdata/filewalk/log4j-1.2.8.jar...
2021/12/15 23:46:25 [!] Log4j V1 identified: /hupe1980/.../log4j-1.2.8.jar
2021/12/15 23:46:25 [i] Inspecting testdata/filewalk/log4j-api-2.14.0.jar...
2021/12/15 23:46:25 [i] Inspecting testdata/filewalk/log4j-core-2.14.0.jar...
2021/12/15 23:46:25 [!] Possibly vulnerable file identified: /hupe1980/.../log4j-core-2.14.0.jar
2021/12/15 23:46:25 [i] Completed scanning

```
## Remote
Send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability
```
Usage:
  scan4log4shell remote [flags]

Flags:
      --caddr string            address to catch the callbacks (eg. ip:port)
      --cidr string             subnet to scan (default "192.168.1.0/28")
  -h, --help                    help for remote
      --listen                  start a listener to catch callbacks
      --no-user-agent-fuzzing   exclude user-agent header from fuzzing
  -p, --port stringArray        port to scan (default [8080])
      --proxy string            proxy url
      --schema string           schema to use for requests (default "https")
  -t, --type string             get, post or json (default "get")
      --waf-bypass              extend scans with WAF bypass payload

Global Flags:
  -v, --verbose   print detailed logging messages
```
### Example
```bash
make run-remote

scanner_1  | 2021/12/15 22:28:57 [i] Log4Shell CVE-2021-44228 Remote Vulnerability Scan
scanner_1  | 2021/12/15 22:28:57 [i] Listening on 172.20.0.30:4444
scanner_1  | 2021/12/15 22:28:57 [i] Start scanning CIDR 172.20.0.0/24
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
