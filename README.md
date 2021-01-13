# UAC
User Access Check - PAM Module to check user logon accessibility

This project provides 2 bash utilities to control when a user logons via SSH.

The main module is uac-check, which should be referrenced on the PAM sshd module, and is the responsible for identifying the user and check its accessibility against the configured UAC database, being this based on the user and from where the users connects to the server.

The other script -- compile-uac-db -- is an utility script that compiles a more human readeable text file into the UAC DB format.

## Model
The UAC module is a PAM module, to be used on the SSH session setup, invoked with pam_exec.so. It should be declared *after* the SELinux checks, on the ```/etc/pam.d/sshd``` file.

```
...
# SELinux needs to be the first session rule.  This ensures that any
# lingering context has been cleared.  Without this it is possible that a
# module could execute code in the wrong domain.
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close

# UAC check goes here
session required pam_exec.so /sbin/uac-check /var/pam.db

# Set the login uid process attribute.
...
```
The ```uac-check``` gets its rules from the user aceess database, which is a directory full of text files, all processed by alphabetic order, and containing _user mask_ and _action rules_.

In the example above, the user access database is the ```/etc/uac/pam.db``` directory.

## UAC Database File Format
The UAC database is a directory that contains multiple ```*.uac``` files, each one with multiple validation rules.
The files are processed by alphabetic order by the _uac-check_ script.

Each file contains multiple UAC blocks; each block is a set of _user match rules_ followed by a block of _action rules_, with the following format:

```
uac-file  ::= <uac-block>+ <md5> <eol>
uac-block ::= <m-rule>+ <x-rule>+
m-rule    ::= 'U' <blank>+ <regexp> <eol>
x-rule    ::= <a-rule> | <r-rule> | <n-rule> | <d-rule>
a-rule    ::= 'A' <blank>+ <addr> <blank>+ <access> <eol>
r-rule    ::= 'R' <blank>+ <addr> <blank>+ <addr> <blank>+ <access> <eol>
n-rule    ::= 'N' <blank>+ <netw> <blank>+ <mask> <blank>+ <access> <eol>
d-rule    ::= 'D' <blank>+ <regexp> <eol>
blank     ::= [ \t]
eol       ::= \r?\n
addr      ::= [1-9][0-9]+ # value must between 0x80000000 (incl) and 0xe0000000 (excl.)
netw      ::= [1-9][0-9]+ # value must be between 0 (incl) and 0xffffffff (incl)
mask      ::= [1-9][0-9]+ # value must be between 0 (incl) and 0xffffffff (incl)
access    ::= [AD]
regexp    ::= `regular expression`
<md5>     ::= [0-9a-f]{32}
```

The only difference between ```addr```, ```netw``` and ```mask``` are the ranges of these values.
All are generated from IP addresses, from its dotted version, where each IP is see as a base-256 number. For example, the value ```a.b.c.d``` is converted to ```((256*a+b)*256+c)*256+d```.

The ```regexp``` is a Perl regular expression; however, has it is formed from a glob-like pattern, not all possibilities are considered. In particur, blanks are not expected (also, these are never used neither in user names aneither in FQDN's, only situations where they are used).

### User Match Rules
The user match rules are used to bind an UAC block to the current user. Multiple user match rules can be placed in sequence and the script will check the current user againts them, until one matches or all are checked.
After a user match rule block there are action rules; these are checked *if and only if* there is at least 1 matching user match rule preceding the action rules.
If not, the action rules are ignored, and the script will search for the next user match rule block or next UAC database file.

A User match rule starts with an 'U' and is followed by a regular expression.

### Action Rules
The action rules determine if a specific user can or not proceed with the login, based on its source IP or domain.
If an action rule matches the user, the the designated action (allow or deny) takes place and the script is terminated; otherwise, the script will continue to look for a matching action rule.

If after processing the full UAC database, no rules are matched, the ```uac-check``` denies the access.

There are 4 Action Rules' cases: the ```a-rule```, ```r-rule```, ```n-rule``` and ```d-rule``` rules, used to distinguish different scenarios.

#### Single Address Rule (```a-rule````)
The ```a-rule``` starts with an 'A' and is followed by the match IP address and the access action.

#### Address Range Rule (```r-rule```)
The ```r-rule``` starts with an 'R' and is followed by 2 IP addresses and the access action.
The IP addresses represent a range of addresses (both included) to which the source IP should belong to. The first specified address should be less or equal to the second. In case they are the same address, this behaves like an ```a-rule```.

#### Network Rule (```n-rule```)
The ```n-rule``` starts with a 'N' and is followed by a normalized network address followed by the network mask and the access.
To validate this rule, the source IP must belowng to this network.
The normalized network address is such that ```normalized-network-address bitwise-AND network-mask = normalized-network-address```.

This representation allows the use of the 0/0 network to represent *all IP's*

#### Domain Rule (```d-rule```)
The ```d-rule``` starts with a 'D' and is followed by a regular expression, followed by the access.
The regular expression is used to match the source host FQDN.

### UAC Block Example

```
U       u[0-9]{5}|x[a-z0-9]{3}[0-9]{2}
A       3232240685      A
R       3232240770      3232240775      D
N       3232240768      4294967168      A
U       x[a-z0-9]{3}.*
U       usr[0-9]{3,5}
D       .*poc..\.x\-domain\.com    A
D       .*\.x\-domain\.com D
U       admin..
N       0       0       A
```
## Creating a UAC block
To minimize the chance of errors while creating a UAC block, another script -- ```compile-uac-db``` -- was created, which allows the generation of a UAC block from a more human-readeable format.

## UAC Block Definition Language
A UAC block, is defined through text file, with a line-oriented language, have the following rules:
* The charcater '#' marks a line comment
* User Match Rules are defined using a glob-like format
** multiple rules can be placed on the same line, separated by semi-colon ';'
** each line must finish with a column ':' character
* The action rules are defined as follows:
** Every rule starts with a + (allow) or - (deny) access, followed by the rule
** A-Rules are made only by the source IP, in dotted format
** R-Rules are made by both IP's, separated by an hiphen (-). The second IP, can be only an IP fragment. For example, ```192.168.10.10 - 192.168.12.17``` is the same as ```192.168.10.10 - 12.17```
** N-Rules are made by the network IP (not mandatorially normalized), a slash (/) and the network mask (dotted format) *OR* the network CIDR
** D-Rules are made only by the glob that defines the domain

An example for the UAC block defined above:

```
### Sample UAC block
u[0-9]{5}; x[a-z0-9]{3}[0-9]{2}:
	+ 192.168.20.45				# allow this address
	- 192.168.20.130- 135		# reject this range
	- 192.168.20.110 /25		# allow this network 

x[a-z0-9]{3}.*:
usr[0-9]{3,5}:
	+*poc??.x-domain.com    
	- *.x-domain.com
	
admin??:
	+ 0/0
```

### Examples
Using these rules, user u12345 from 192.168.20.134 will be rejected access; the same if this user connects from 192.168.20.50.
However, when connecting from 192.168.20.150 access will be granted.

User usr4444 will be denied access if trying to connect from my-pc02.x-domain.com, but will be allowed when connecting from my-poc02.x-domain.com.

adminzn can access from any IP, as adminxx.

## Compiling the UAC definition
To compile the UAC definitions, one uses the ```compile-uac-db``` utility.

### Example

```compile-uac-db definitions.txt uac.db```

Compiles the definitions.txt file and generates the uac.db compiled file.

For more information, do ```compile-uac-db --help```

# Setup

There are no restrictions other than the PAM module being able to access the ```uac-check``` script and the UAC database directory and UAC control files.
