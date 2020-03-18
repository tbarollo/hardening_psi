#!/bin/bash

# Scripts para verificação de pendencias de Hardening
# Fase 1 - Validar valores atuais e gerar report sobre comando executado, valor atual e se está em compliance;
# Fase 2 - Validar possíveis melhorias;
# Fase 3 - Aplicar melhorias e rodar novamente as checagens da Fase 1;
# 

# Source function library.
. /etc/rc.d/init.d/functions

arquivodelog="hardening.log"

if [[ -f "$arquivodelog" ]]; then
	arquivologsemsulfixo=$(ls $arquivodelog | sed 's/\..*//g')
	cp $arquivodelog $arquivologsemsulfixo-$(date +%Y%m%d-%H%M%S).log
fi
> $arquivodelog

curitem=/dev/null

default="\033[01;0m"
verde="\033[01;32m"
ciano="\033[01;36m"

mudacor(){
	case "$1" in
    	default)
        	echo -en "$default" | tee -a $arquivodelog
        	;;
    	verde)
        	echo -en $verde | tee -a $arquivodelog
        	;;
    	ciano)
        	echo -en "$ciano" | tee -a $arquivodelog
        	;;
	esac
}

check-conformidade() {
	if [ $? -eq 0 ]
	then
		mudacor ciano
        	echo -n "Item '$curitem' em conformidade:" | tee -a $arquivodelog
		success | tee -a $arquivodelog
	else
		mudacor ciano
        	echo -n "Item '$curitem' em conformidade:" | tee -a $arquivodelog
		failure | tee -a $arquivodelog
		((ret+=1))
	fi
}

check-warning() {
	if [ $? -eq 0 ]
	then
		mudacor ciano
        	echo -n "Item '$curitem' em conformidade:" | tee -a $arquivodelog
		success | tee -a $arquivodelog
	else
		mudacor ciano
        	echo -n "Item '$curitem' em conformidade:" | tee -a $arquivodelog
		warning | tee -a $arquivodelog
		((ret+=1))
	fi
}

## 00 - Checagem geral

check-1all() {
	local ret=0
	
	mudacor ciano; echo "	-	Checando item requerido 1.01 - Disable Automounting" | tee -a $arquivodelog
	mudacor default
	check-101
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 1.02 - Ensure SELinux is installed" | tee -a $arquivodelog
	mudacor default
	check-102
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 1.03 - Ensure local login warning banner is configured properly" | tee -a $arquivodelog
	mudacor default
	check-103
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 1.04 - Ensure permissions on /etc/motd are configured" | tee -a $arquivodelog
	mudacor default
	check-104
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 1.05 - Ensure permissions on /etc/issue are configured" | tee -a $arquivodelog
	mudacor default
	check-105
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 1.06 - Ensure permissions on /etc/issue.net" | tee -a $arquivodelog
	mudacor default
	check-106
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor verde
	echo -n "1 - Configuração de Sistemas de arquivos:" | tee -a $arquivodelog
	mudacor default

	if [ $ret -eq 0 ]
        then
                success | tee -a $arquivodelog
        else
                failure | tee -a $arquivodelog
    fi
	echo | tee -a $arquivodelog
	return $ret
}

apply-1all() {
	local ret=0

	echo "	Aplicando item requerido 1.01 - Disable Automounting"
	apply-101
	echo
	echo "	Aplicando item requerido 1.02 - Ensure SELinux is installed"
	apply-102
	echo
	echo "	Aplicando item requerido 1.03 - Ensure local login warning banner is configured properly"
	apply-103
	echo
	echo "	Aplicando item requerido 1.04 - Ensure permissions on /etc/motd are configured"
	apply-104
	echo
	echo "	Aplicando item requerido 1.05 - Ensure permissions on /etc/issue are configured"
	apply-105
	echo
	echo "	Aplicando item requerido 1.06 - Ensure permissions on /etc/issue.net"
	apply-106
	echo

	echo -n "Em conformidade completa:"
	[ $ret -eq 0 ] && success || failure; echo
	return $ret
}

check-2all() {
	local ret=0
	
	mudacor ciano; echo "	-	Checando item requerido 2.01 - Ensure updates, patches, and additional security software are installed" | tee -a $arquivodelog
	mudacor default
	check-201
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.02 - Ensure chargen services are not enabled" | tee -a $arquivodelog
	mudacor default
	check-202
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.03 - Ensure daytime services are not enabled" | tee -a $arquivodelog
	mudacor default
	check-203
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 2.04 - Ensure discard services are not enabled" | tee -a $arquivodelog
	mudacor default
	check-204
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.05 - Ensure tftp services are not enabled" | tee -a $arquivodelog
	mudacor default
	check-205
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 2.06 - Ensure time synchronization is in use (chrony)" | tee -a $arquivodelog
	mudacor default
	check-206
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.07 - Ensure ntp is configured" | tee -a $arquivodelog
	mudacor default
	check-207
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.08 - Ensure CUPS is not enabled" | tee -a $arquivodelog
	mudacor default
	check-208
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.09 - Ensure DHCP Server is not enabled" | tee -a $arquivodelog
	mudacor default
	check-209
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.10 - Ensure LDAP server is not enabled" | tee -a $arquivodelog
	mudacor default
	check-210
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.11 - Ensure NFS and RPC are not enabled" | tee -a $arquivodelog
	mudacor default
	check-211
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.12 - Ensure DNS Server is not enabled" | tee -a $arquivodelog
	mudacor default
	check-212
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.13 - Ensure FTP Server is not enabled" | tee -a $arquivodelog
	mudacor default
	check-213
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.14 - Ensure HTTP server is not enabled" | tee -a $arquivodelog
	mudacor default
	check-214
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.15 - Ensure IMAP and POP3 server is not enabled" | tee -a $arquivodelog
	mudacor default
	check-215
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.16 - Ensure Samba is not enabled" | tee -a $arquivodelog
	mudacor default
	check-216
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.17 - Ensure HTTP Proxy Server is not enabled" | tee -a $arquivodelog
	mudacor default
	check-217
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.18 - Ensure tftp server is not enabled" | tee -a $arquivodelog
	mudacor default
	check-218
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.19 - Ensure IPv6 is disabled" | tee -a $arquivodelog
	mudacor default
	check-219
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 2.20 - Ensure auditd service is enabled" | tee -a $arquivodelog
	mudacor default
	check-220
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor verde
	echo -n "2 - Desabilitar ou remover serviços não utilizados:" | tee -a $arquivodelog
	mudacor default

	if [ $ret -eq 0 ]
        then
                success | tee -a $arquivodelog
        else
                failure | tee -a $arquivodelog
        fi
	echo | tee -a $arquivodelog
	return $ret
}

apply-2all() {
	local ret=0

	echo "	Aplicando item requerido 1.01 - Disable Automounting"
	apply-101
	echo

	echo -n "Em conformidade completa:"
	[ $ret -eq 0 ] && success || failure; echo
	return $ret
}

check-3all() {
	local ret=0
	
	mudacor ciano; echo "	-	Checando item requerido 3.01 - Set Lockout for Failed Password Attempts" | tee -a $arquivodelog
	mudacor default
	check-301
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.02 - Ensure password hashing algorithm is SHA-512" | tee -a $arquivodelog
	mudacor default
	check-302
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.03 - Ensure system accounts are non-login" | tee -a $arquivodelog
	mudacor default
	check-303
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 3.04 - Ensure permissions on /etc/passwd are configured" | tee -a $arquivodelog
	mudacor default
	check-304
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.05 - Ensure permissions on /etc/group are configured" | tee -a $arquivodelog
	mudacor default
	check-305
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 3.06 - Ensure permissions on /etc/shadow are configured" | tee -a $arquivodelog
	mudacor default
	check-306
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.07 - Ensure permissions on /etc/gshadow are configured" | tee -a $arquivodelog
	mudacor default
	check-307
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.08 - Ensure permissions on /etc/passwd- are configured" | tee -a $arquivodelog
	mudacor default
	check-308
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.09 - Ensure permissions on /etc/shadow- are configured" | tee -a $arquivodelog
	mudacor default
	check-309
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.10 - Ensure permissions on /etc/group- are configured" | tee -a $arquivodelog
	mudacor default
	check-310
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.11 - Ensure permissions on /etc/gshadow- are configured" | tee -a $arquivodelog
	mudacor default
	check-311
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.12 - Ensure user home directories permissions are 750 or more restrictive" | tee -a $arquivodelog
	mudacor default
	check-312
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.13 - Ensure users own their home directories" | tee -a $arquivodelog
	mudacor default
	check-313
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.14 - Ensure all groups in /etc/passwd exist in /etc/group" | tee -a $arquivodelog
	mudacor default
	check-314
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.15 - Ensure no duplicate UIDs exist" | tee -a $arquivodelog
	mudacor default
	check-315
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.16 - Ensure no duplicate GIDs exist" | tee -a $arquivodelog
	mudacor default
	check-316
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.17 - Ensure no duplicate user names exist" | tee -a $arquivodelog
	mudacor default
	check-317
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 3.18 - Ensure no duplicate group names exist" | tee -a $arquivodelog
	mudacor default
	check-318
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor verde
	echo -n "3 - Requisitos de senha:" | tee -a $arquivodelog
	mudacor default

	if [ $ret -eq 0 ]
        then
                success | tee -a $arquivodelog
        else
                failure | tee -a $arquivodelog
        fi
	echo | tee -a $arquivodelog
	return $ret
}

apply-3all() {
	local ret=0

	echo "	Aplicando item requerido 1.01 - Disable Automounting"
	apply-101
	echo

	echo -n "Em conformidade completa:"
	[ $ret -eq 0 ] && success || failure; echo
	return $ret
}

check-4all() {
	local ret=0
	
	mudacor ciano; echo "	-	Checando item requerido 4.01 - Ensure SSH Protocol is set to 2" | tee -a $arquivodelog
	mudacor default
	check-401
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 4.02 - Ensure SSH LogLevel is set to INFO" | tee -a $arquivodelog
	mudacor default
	check-402
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 4.03 - Ensure SSH X11 forwarding is disabled" | tee -a $arquivodelog
	mudacor default
	check-403
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 4.04 - Ensure SSH MaxAuthTries is set to 4 or less" | tee -a $arquivodelog
	mudacor default
	check-404
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 4.05 - Ensure SSH HostbasedAuthentication is disabled" | tee -a $arquivodelog
	mudacor default
	check-405
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 4.06 - Ensure SSH root login is disabled" | tee -a $arquivodelog
	mudacor default
	check-406
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 4.07 - Ensure SSH PermitEmptyPasswords is disabled" | tee -a $arquivodelog
	mudacor default
	check-407
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 4.08 - Ensure SSH PermitUserEnvironment is disabled" | tee -a $arquivodelog
	mudacor default
	check-408
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 4.09 - Ensure only approved ciphers are used" | tee -a $arquivodelog
	mudacor default
	check-409
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 4.10 - Ensure SSH warning banner is configured" | tee -a $arquivodelog
	mudacor default
	check-410
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 4.11 - Ensure SSH access is limited" | tee -a $arquivodelog
	mudacor default
	check-411
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor verde
	echo -n "4 - Configuração de SSH:" | tee -a $arquivodelog
	mudacor default

	if [ $ret -eq 0 ]
        then
                success | tee -a $arquivodelog
        else
                failure | tee -a $arquivodelog
        fi
	echo | tee -a $arquivodelog
	return $ret
}

apply-4all() {
	local ret=0

	echo "	Aplicando item requerido 1.01 - Disable Automounting"
	apply-101
	echo

	echo -n "Em conformidade completa:"
	[ $ret -eq 0 ] && success || failure; echo
	return $ret
}

check-5all() {
	local ret=0
	
	mudacor ciano; echo "	-	Checando item requerido 5.01 - Configure /etc/rsyslog.conf" | tee -a $arquivodelog
	mudacor default
	check-501
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 5.02 - Configure rsyslog to Send Logs to a Remote Log Host" | tee -a $arquivodelog
	mudacor default
	check-502
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 5.03 - Activate the rsyslog Service" | tee -a $arquivodelog
	mudacor default
	check-503
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 5.04 - Record Events That Modify the Systems Mandatory Access Controls" | tee -a $arquivodelog
	mudacor default
	check-504
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 5.05 - Collect Login and Logout Events" | tee -a $arquivodelog
	mudacor default
	check-505
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 5.06 - Collect Session Initiation Information" | tee -a $arquivodelog
	mudacor default
	check-506
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 5.07 - Collect Discretionary Access Control Permission Modification Events" | tee -a $arquivodelog
	mudacor default
	check-507
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 5.08 - Collect Unsuccessful Unauthorized Access Attemptsto Files" | tee -a $arquivodelog
	mudacor default
	check-508
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 5.09 - Collect Successful File System Mounts" | tee -a $arquivodelog
	mudacor default
	check-509
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 5.10 - Collect Changes to System Administration Scope" | tee -a $arquivodelog
	mudacor default
	check-510
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 5.11 - Collect System Administrator Actions" | tee -a $arquivodelog
	mudacor default
	check-511
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor verde
	echo -n "5 - Log e auditoria:" | tee -a $arquivodelog
	mudacor default

	if [ $ret -eq 0 ]
        then
                success | tee -a $arquivodelog
        else
                failure | tee -a $arquivodelog
        fi
	echo | tee -a $arquivodelog
	return $ret
}

apply-5all() {
	local ret=0

	echo "	Aplicando item requerido 1.01 - Disable Automounting"
	apply-101
	echo

	echo -n "Em conformidade completa:"
	[ $ret -eq 0 ] && success || failure; echo
	return $ret
}

check-6all() {
	local ret=0
	
	mudacor ciano; echo "	-	Checando item requerido 6.01 - Enable TCP SYN Cookies" | tee -a $arquivodelog
	mudacor default
	check-601
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 6.02 - Disable IP Forwarding" | tee -a $arquivodelog
	mudacor default
	check-602
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 6.03 - Ensure packet redirect sending is disabled" | tee -a $arquivodelog
	mudacor default
	check-603
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 6.04 - Ensure source routed packets are not accepted" | tee -a $arquivodelog
	mudacor default
	check-604
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 6.05 - Disable ICMP Redirect Acceptance" | tee -a $arquivodelog
	mudacor default
	check-605
    echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	
	mudacor ciano; echo "	-	Checando item requerido 6.06 - Disable Secure ICMP Redirect Acceptance" | tee -a $arquivodelog
	mudacor default
	check-606
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 6.07 - Ensure broadcast ICMP requests are ignored" | tee -a $arquivodelog
	mudacor default
	check-607
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 6.08 - Enable Bad Error Message Protection" | tee -a $arquivodelog
	mudacor default
	check-608
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 6.09 - Enable RFC-recommended Source Route Validation" | tee -a $arquivodelog
	mudacor default
	check-609
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 6.10 - Ensure TCP SYN Cookies is enabled" | tee -a $arquivodelog
	mudacor default
	check-610
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor ciano; echo "	-	Checando item requerido 6.11 - Deactivate Wireless Interfaces" | tee -a $arquivodelog
	mudacor default
	check-611
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog

	mudacor verde
	echo -n "6 - Configuração de rede:" | tee -a $arquivodelog
	mudacor default

	if [ $ret -eq 0 ]
        then
                success | tee -a $arquivodelog
        else
                failure | tee -a $arquivodelog
        fi
	echo | tee -a $arquivodelog
	return $ret
}

apply-6all() {
	local ret=0

	echo "	Aplicando item requerido 1.01 - Disable Automounting"
	apply-101
	echo

	echo -n "Em conformidade completa:"
	[ $ret -eq 0 ] && success || failure; echo
	return $ret
}

## 01 - Configuração de Sistemas de arquivos

check-101() {
	curitem="1.01"
	echo "-	Comando: systemctl is-enabled autofs" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled autofs | tee -a $arquivodelog
	systemctl is-enabled autofs &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-101() {
	mudacor ciano; echo "Aplicando melhoria para o item requerido 1.01 - Disable Automounting"
	mudacor default
	check-101
	echo | tee -a $arquivodelog; echo | tee -a $arquivodelog
	echo "-	Comando: systemctl disable autofs" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable autofs
	check-conformidade
}

check-102() {
	curitem="1.02"
	echo "-	Comando: rpm -q libselinux" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	rpm -q libselinux | tee -a $arquivodelog
	rpm -q libselinux | egrep -q "^libselinux-[0-9]{1,}\.[0-9]{1,}.*\.el7\.x86_64"
	check-conformidade
}

apply-102() {
	curitem="1.02"
	echo "-	Comando: yum install libselinux -y" | tee -a $arquivodelog
	mudacor default
	
	yum install libselinux -y
	check-conformidade
}

check-103() {
	curitem="1.03"
	echo "-	Comando: egrep '(\\\v|\\\r|\\\m|\\\s)' /etc/issue" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	egrep '(\\v|\\r|\\m|\\s)' /etc/issue | tee -a $arquivodelog
	egrep -q '(\\v|\\r|\\m|\\s)' /etc/issue
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-103() {
	curitem="1.03"
	echo "-	Comando: yum install libselinux -y" | tee -a $arquivodelog
	mudacor default

	check-conformidade
}

check-104() {
	curitem="1.04"
	echo "-	Comando: stat /etc/motd | grep Access" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/motd | grep Uid | tee -a $arquivodelog
	stat /etc/motd | grep Uid | grep -q "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-104() {
	curitem="1.04"
	echo "-	Comando: chmod 644 /etc/motd" | tee -a $arquivodelog
	mudacor default

	chmod 644 /etc/motd
	check-conformidade

	mudacor ciano
	echo "-	Comando: chown root.root /etc/motd" | tee -a $arquivodelog
	mudacor default
	chown root.root /etc/motd
	check-conformidade
}

check-105() {
	curitem="1.05"
	echo "-	Comando: stat /etc/issue | grep Access" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/issue | grep Uid | tee -a $arquivodelog
	stat /etc/issue | grep Uid | grep -q "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-105() {
	curitem="1.05"
	echo "-	Comando: chmod 644 /etc/issue" | tee -a $arquivodelog
	mudacor default
	chmod 644 /etc/issue
	check-conformidade

	mudacor ciano
	echo "-	Comando: chown root.root /etc/issue" | tee -a $arquivodelog
	mudacor default
	chown root.root /etc/issue
	check-conformidade
}

check-106() {
	curitem="1.06"
	echo "-	Comando: stat /etc/issue.net | grep Access" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default
	stat /etc/issue.net | grep Uid | tee -a $arquivodelog
	stat /etc/issue.net | grep Uid | grep -q "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-106() {
	curitem="1.06"
	echo "-	Comando: chmod 644 /etc/issue.net" | tee -a $arquivodelog
	mudacor default
	chmod 644 /etc/issue.net
	check-conformidade

	mudacor ciano
	echo "-	Comando: chown root.root /etc/issue.net" | tee -a $arquivodelog
	mudacor default
	chown root.root /etc/issue.net
	check-conformidade
}

## 02 - Desabilitar ou remover serviços não utilizados

check-201() {
	curitem="2.01"

	echo "Atualizando o repositório yum para checagem..." | tee -a $arquivodelog
	yum clean all &> /dev/null
	yum repolist &> /dev/null

	echo "-	Comando: yum check-update" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default
	yum check-update | tee -a $arquivodelog
	
	mudacor ciano
	echo "-	Comando: yum history" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default
	yum history | tee -a $arquivodelog

	yum check-update &> /dev/null
	check-warning
}

apply-201() {
	curitem="1.06"
	echo "$(yum check-update -q | grep -v "^$" | wc -l) pacotes desatualizados." | tee -a $arquivodelog
	echo "Realizar a verificação dos mesmos manualmente." | tee -a $arquivodelog
	check-conformidade
}

check-202() {
	curitem="2.02"
	echo '-	Comando: systemctl list-units | grep "xinetd\|chargen"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default
	systemctl list-units | grep "xinetd\|chargen" | tee -a $arquivodelog
	systemctl list-units | grep "xinetd\|chargen" &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-202() {
	curitem="2.02"
	echo "-	Comando: systemctl disable xinetd" | tee -a $arquivodelog
	mudacor default
	systemctl disable xinetd
	true
	check-conformidade

	mudacor ciano
	echo "-	Comando: systemctl disable chargen" | tee -a $arquivodelog
	mudacor default
	systemctl disable chargen
	true
	check-conformidade
}

check-203() {
	curitem="2.03"
	echo '-	Comando: systemctl list-units | grep "xinetd\|daytime"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default
	systemctl list-units | grep "xinetd\|daytime" | tee -a $arquivodelog
	systemctl list-units | grep "xinetd\|daytime" &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-203() {
	curitem="2.03"
	echo "-	Comando: systemctl disable xinetd" | tee -a $arquivodelog
	mudacor default
	systemctl disable xinetd
	true
	check-conformidade

	mudacor ciano
	echo "-	Comando: systemctl disable daytime" | tee -a $arquivodelog
	mudacor default
	systemctl disable daytime
	true
	check-conformidade
}

check-204() {
	curitem="2.04"
	echo '-	Comando: systemctl list-units | grep "xinetd\|discard"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default
	systemctl list-units | grep "xinetd\|discard" | tee -a $arquivodelog
	systemctl list-units | grep "xinetd\|discard" &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-204() {
	curitem="2.04"
	echo "-	Comando: systemctl disable xinetd" | tee -a $arquivodelog
	mudacor default
	systemctl disable xinetd
	true
	check-conformidade

	mudacor ciano
	echo "-	Comando: systemctl disable discard" | tee -a $arquivodelog
	mudacor default
	systemctl disable discard
	true
	check-conformidade
}

check-205() {
	curitem="2.05"
	echo '-	Comando: systemctl list-units | grep "xinetd\|tftp"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default
	systemctl list-units | grep "xinetd\|tftp" | tee -a $arquivodelog
	systemctl list-units | grep "xinetd\|tftp" &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-205() {
	curitem="2.05"
	echo "-	Comando: systemctl disable xinetd" | tee -a $arquivodelog
	mudacor default
	systemctl disable xinetd
	true
	check-conformidade

	mudacor ciano
	echo "-	Comando: systemctl disable tftp" | tee -a $arquivodelog
	mudacor default
	systemctl disable tftp
	true
	check-conformidade
}

check-206() {
	curitem="2.06"
	echo '-	Comando: rpm -q chrony' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default
	rpm -q chrony | tee -a $arquivodelog
	check-conformidade
}

apply-206() {
	curitem="2.06"
	echo "Instalando Chrony" | tee -a $arquivodelog
	mudacor default
	yum install -y chrony &> /dev/null
	yum enable chrony &> /dev/null
	check-conformidade
}

check-207() {
	curitem="2.07"
	echo '-	Comando: grep "^server" /etc/chrony.conf' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default
	grep "^server" /etc/chrony.conf | tee -a $arquivodelog
	grep "^server" /etc/chrony.conf | egrep -q "10.1.70.2|10.1.70.3"
	check-conformidade
}

apply-207() {
	curitem="2.07"
	echo "Reconfigurando Chrony" | tee -a $arquivodelog
	mudacor default
	sed -i.bkp-$(date +%Y%m%d-%H%M%S) -e '^s/^server*//g' /etc/chrony.conf
	echo "server 10.1.70.2" >> /etc/chrony.conf
	echo "server 10.1.70.3" >> /etc/chrony.conf
	check-conformidade
}

check-208() {
	curitem="2.08"
	echo "-	Comando: systemctl is-enabled cups" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled cups | tee -a $arquivodelog
	systemctl is-enabled cups &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-208() {
	curitem="2.08"
	echo "-	Comando: systemctl disable cups" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable cups
	check-conformidade
}

check-209() {
	curitem="2.09"
	echo "-	Comando: systemctl is-enabled dhcpd" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled dhcpd | tee -a $arquivodelog
	systemctl is-enabled dhcpd &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-209() {
	curitem="2.09"
	echo "-	Comando: systemctl disable dhcpd" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable dhcpd
	check-conformidade
}

check-210() {
	curitem="2.10"
	echo "-	Comando: systemctl is-enabled slapd" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled slapd | tee -a $arquivodelog
	systemctl is-enabled slapd &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-210() {
	curitem="2.10"
	echo "-	Comando: systemctl disable slapd" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable slapd
	check-conformidade
}

check-211() {
	local retorno=0
	curitem="2.11"
	echo "-	Comando: systemctl is-enabled nfs" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled nfs | tee -a $arquivodelog
	systemctl is-enabled nfs &> /dev/null
	[ $? -eq 1 ] && true || ((retorno++))

	mudacor ciano
	echo "-	Comando: systemctl is-enabled rpcbind" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled rpcbind | tee -a $arquivodelog
	systemctl is-enabled rpcbind &> /dev/null
	[ $? -eq 1 ] && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-conformidade
}

apply-211() {
	curitem="2.11"
	echo "-	Comando: systemctl disable nfs" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable nfs
	check-conformidade

	mudacor ciano
	echo "-	Comando: systemctl disable rpcbind" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable rpcbind
	check-conformidade
}

check-212() {
	curitem="2.12"
	echo "-	Comando: systemctl is-enabled named" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled named | tee -a $arquivodelog
	systemctl is-enabled named &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-212() {
	curitem="2.12"
	echo "-	Comando: systemctl disable named" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable named
	check-conformidade
}

check-213() {
	curitem="2.13"
	echo "-	Comando: systemctl is-enabled vsftpd" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled vsftpd | tee -a $arquivodelog
	systemctl is-enabled vsftpd &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-213() {
	curitem="2.13"
	echo "-	Comando: systemctl disable vsftpd" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable vsftpd
	check-conformidade
}

check-214() {
	curitem="2.14"
	echo "-	Comando: systemctl is-enabled httpd" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled httpd | tee -a $arquivodelog
	systemctl is-enabled httpd &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-214() {
	curitem="2.14"
	echo "-	Comando: systemctl disable httpd" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable httpd
	check-conformidade
}

check-215() {
	curitem="2.15"
	echo "-	Comando: systemctl is-enabled dovecot" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled dovecot | tee -a $arquivodelog
	systemctl is-enabled dovecot &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-215() {
	curitem="2.15"
	echo "-	Comando: systemctl disable dovecot" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable dovecot
	check-conformidade
}

check-216() {
	curitem="2.16"
	echo "-	Comando: systemctl is-enabled smb" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled smb | tee -a $arquivodelog
	systemctl is-enabled smb &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-216() {
	curitem="2.16"
	echo "-	Comando: systemctl disable smb" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable smb
	check-conformidade
}

check-217() {
	curitem="2.17"
	echo "-	Comando: systemctl is-enabled squid" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled squid | tee -a $arquivodelog
	systemctl is-enabled squid &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-217() {
	curitem="2.17"
	echo "-	Comando: systemctl disable squid" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable squid
	check-conformidade
}

check-218() {
	curitem="2.18"
	echo "-	Comando: systemctl is-enabled tftp" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled tftp | tee -a $arquivodelog
	systemctl is-enabled tftp &> /dev/null
	[ $? -eq 1 ] && true || false
	check-conformidade
}

apply-218() {
	curitem="2.18"
	echo "-	Comando: systemctl disable tftp" | tee -a $arquivodelog
	mudacor default
	
	systemctl disable tftp
	check-conformidade
}

check-219() {
	curitem="2.19"
	echo "-	Comando: modprobe -c | grep ipv6 | grep disable" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	modprobe -c | grep ipv6 | grep disable | tee -a $arquivodelog
	modprobe -c | grep ipv6 | grep disable &> /dev/null
	check-conformidade
}

apply-219() {
	curitem="2.19"
	echo "Desabilitando IPv6 via modprobe" | tee -a $arquivodelog
	mudacor default
	
	touch /etc/modprobe.d/disable-ipv6.conf
	echo "options ipv6 disable=1" > /etc/modprobe.d/disable-ipv6.conf
	
	if [ grep "net.ipv6.conf.all.disable_ipv6" /etc/sysctl.conf ]
	then
		sed -i.bkp-$(date +%Y%m%d-%H%M%S) -e 's/net.ipv6.conf.all.disable_ipv6.*/net.ipv6.conf.all.disable_ipv6 = 1/g' /etc/sysctl.conf
	else
		echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
	fi

	if [ grep "net.ipv6.conf.default.disable_ipv6" /etc/sysctl.conf ]
	then
		sed -i.bkp-$(date +%Y%m%d-%H%M%S) -e 's/net.ipv6.conf.default.disable_ipv6.*/net.ipv6.conf.default.disable_ipv6 = 1/g' /etc/sysctl.conf
	else
		echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
	fi
	systemctl -p | grep "disable_ipv6 = 1" | tee -a $arquivodelog
	check-conformidade
}

check-220() {
	curitem="2.20"
	echo "-	Comando: systemctl is-enabled auditd" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled auditd | tee -a $arquivodelog
	systemctl is-enabled auditd &> /dev/null
	check-conformidade
}

apply-220() {
	curitem="2.20"
	echo "-	Comando: systemctl enable auditd" | tee -a $arquivodelog
	mudacor default
	
	yum install auditd -y &> /dev/null
	systemctl enable auditd
	check-conformidade
}

## 03 - Requisitos de senha

check-301() {
	local retorno=0
	curitem="3.01"
	echo "-	Comando: cat /etc/pam.d/password-auth" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	cat /etc/pam.d/password-auth | tee -a $arquivodelog

	egrep -q "^auth\s+required\s+pam_env.so" /etc/pam.d/password-auth && true || ((retorno++))
	egrep -q "^auth\s+required\s+pam_faillock.so\s+preauth\s+audit\s+silent\s+deny=3\s+unlock_time=900" /etc/pam.d/password-auth && true || ((retorno++))
	egrep -q "^auth\s+[success=1\s+default=bad]\s+pam_unix.so" /etc/pam.d/password-auth && true || ((retorno++))
	egrep -q "^auth\s+[default=die]\s+pam_faillock.so\s+authfail\s+audit\s+deny=3\s+unlock_time=900" /etc/pam.d/password-auth && true || ((retorno++))
	egrep -q "^auth\s+sufficient\s+pam_faillock.so\s+authsucc\s+audit\s+deny=3\s+unlock_time=900" /etc/pam.d/password-auth && true || ((retorno++))
	egrep -q "^auth\s+required\s+pam_deny.so" /etc/pam.d/password-auth && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-warning
}

apply-301() {
	/etc/pam.d/password-auth
	#%PAM-1.0
	# This file is auto-generated.
	# User changes will be destroyed the next time authconfig is run.
	auth required pam_env.so
	auth required pam_faillock.so preauth audit silent deny=3 unlock_time=900
	auth [success=1 default=bad] pam_unix.so
	auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=900
	auth sufficient pam_faillock.so authsucc audit deny=3 unlock_time=900
	auth required pam_deny.so
}

check-302() {
	curitem="3.02"
	echo "-	Comando: egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth | tee -a $arquivodelog
	egrep -q '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth
	check-conformidade
}

apply-302() {
	/etc/pam.d/password-auth
	password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
}

check-303() {
	curitem="3.03"
	echo "-	Comando: egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false")  {print}'" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false")  {print}' | tee -a $arquivodelog
	[ $(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false")  {print}' | wc -l) -eq 0 ] && true || false
	check-conformidade
}

apply-303() {
	Contas justificadas na matriz de acesso
}

check-304() {
	curitem="3.04"
	echo '-	Comando: stat /etc/passwd | grep "Access\|Uid"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/passwd | grep "Access\|Uid" | tee -a $arquivodelog
	stat /etc/passwd | grep "Access\|Uid" | grep -q "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-304() {
	chmod 644 /etc/passwd
	chown root.root /etc/passwd
}

check-305() {
	curitem="3.05"
	echo '-	Comando: stat /etc/group | grep "Access\|Uid"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/group | grep "Access\|Uid" | tee -a $arquivodelog
	stat /etc/group | grep "Access\|Uid" | grep -q "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-305() {
	chmod 644 /etc/group
	chown root.root /etc/group
}

check-306() {
	curitem="3.06"
	echo '-	Comando: stat /etc/shadow | grep "Access\|Uid"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/shadow | grep "Access\|Uid" | tee -a $arquivodelog
	stat /etc/shadow | grep "Access\|Uid" | grep -q "Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-306() {
	chmod 000 /etc/shadow
	chown root.root /etc/shadow
}

check-307() {
	curitem="3.07"
	echo '-	Comando: stat /etc/gshadow | grep "Access\|Uid"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/gshadow | grep "Access\|Uid" | tee -a $arquivodelog
	stat /etc/gshadow | grep "Access\|Uid" | grep -q "Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-307() {
	chmod 000 /etc/gshadow
	chown root.root /etc/gshadow
}

check-308() {
	curitem="3.08"
	echo '-	Comando: stat /etc/passwd- | grep "Access\|Uid"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/passwd- | grep "Access\|Uid" | tee -a $arquivodelog
	stat /etc/passwd- | grep "Access\|Uid" | grep -q "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-308() {
	chmod 644 /etc/passwd-
	chown root.root /etc/passwd-
}

check-309() {
	curitem="3.09"
	echo '-	Comando: stat /etc/shadow- | grep "Access\|Uid"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/shadow- | grep "Access\|Uid" | tee -a $arquivodelog
	stat /etc/shadow- | grep "Access\|Uid" | grep -q "Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-309() {
	chmod 000 /etc/shadow-
	chown root.root /etc/shadow-
}

check-310() {
	curitem="3.10"
	echo '-	Comando: stat /etc/group- | grep "Access\|Uid"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/group- | grep "Access\|Uid" | tee -a $arquivodelog
	stat /etc/group- | grep "Access\|Uid" | grep -q "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-310() {
	chmod 644 /etc/group-
	chown root.root /etc/group-
}

check-311() {
	curitem="3.11"
	echo '-	Comando: stat /etc/gshadow- | grep "Access\|Uid"' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	stat /etc/gshadow- | grep "Access\|Uid" | tee -a $arquivodelog
	stat /etc/gshadow- | grep "Access\|Uid" | grep -q "Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root)"
	check-conformidade
}

apply-311() {
	chmod 000 /etc/gshadow-
	chown root.root /etc/gshadow-
}

check-312() {
	curitem="3.12"
	echo '-	Comando: for i in `getent  passwd | awk -F":" '{print $6}'` ; do stat $i | grep -i uid; done' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	for i in `getent  passwd | awk -F":" '{print $6}'` ; do stat $i | grep -i uid; done | tee -a $arquivodelog
	false
	check-warning
}

apply-312() {
	for i in `getent  passwd | awk -F":" '{print $6}'` ; do
		ls -lha | grep -v "drwxrw----"
	done
}

check-313() {
	curitem="3.13"
	echo '-	Comando: Script customizado' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
		dirperm=`ls -ld $dir | cut -f1 -d" "`
		if [ `echo $dirperm | cut -c6` != "-" ]; then
			echo "Group Write permission set on directory $dir"
		fi
		if [ `echo $dirperm | cut -c8` != "-" ]; then
			echo "Other Read permission set on directory $dir"
		fi
		if [ `echo $dirperm | cut -c9` != "-" ]; then
			echo "Other Write permission set on directory $dir"
		fi
		if [ `echo $dirperm | cut -c10` != "-" ]; then
			echo "Other Execute permission set on directory $dir"
		fi
	done

	[ $( for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
		dirperm=`ls -ld $dir | cut -f1 -d" "`
		if [ `echo $dirperm | cut -c6` != "-" ]; then
			echo "Group Write permission set on directory $dir"
		fi
		if [ `echo $dirperm | cut -c8` != "-" ]; then
			echo "Other Read permission set on directory $dir"
		fi
		if [ `echo $dirperm | cut -c9` != "-" ]; then
			echo "Other Write permission set on directory $dir"
		fi
		if [ `echo $dirperm | cut -c10` != "-" ]; then
			echo "Other Execute permission set on directory $dir"
		fi
		done | wc -l) -eq 0 ] && true || false
	
	check-conformidade

}

apply-313() {
	for i in `getent  passwd | awk -F":" '{print $6}'` ; do
		ls -lha | grep -v "drwxrw----"
	done
}

check-314() {
	curitem="3.14"
	echo '-	Comando: Script customizado' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
		grep -q -P "^.*?:[^:]*:$i:" /etc/group
		if [ $? -ne 0 ]; then
			echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
		fi
	done

	[ $( for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
		grep -q -P "^.*?:[^:]*:$i:" /etc/group
		if [ $? -ne 0 ]; then
			echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
		fi
		done | wc -l) -eq 0 ] && true || false
	check-conformidade
}

apply-314() {
	for i in `getent  passwd | awk -F":" '{print $6}'` ; do
		ls -lha | grep -v "drwxrw----"
	done
}

check-315() {
	curitem="3.15"
	echo '-	Comando: Script customizado' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
			echo "Duplicate UID ($2): ${users}"
		fi
	done

	[ $( cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
			echo "Duplicate UID ($2): ${users}"
		fi
		done | wc -l) -eq 0 ] && true || false
	check-conformidade
}

apply-315() {
	for i in `getent  passwd | awk -F":" '{print $6}'` ; do
		ls -lha | grep -v "drwxrw----"
	done
}

check-316() {
	curitem="3.16"
	echo '-	Comando: Script customizado' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			groups=`awk -F: '($3 == n) { print$1}' n=$2 /etc/group | xargs`
			echo "Duplicate GID ($2): ${groups}"
		fi
	done

	[ $( cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			groups=`awk -F: '($3 == n) { print$1}' n=$2 /etc/group | xargs`
			echo "Duplicate GID ($2): ${groups}"
		fi
		done | wc -l) -eq 0 ] && true || false
	check-conformidade
}

apply-316() {
	for i in `getent  passwd | awk -F":" '{print $6}'` ; do
		ls -lha | grep -v "drwxrw----"
	done
}

check-317() {
	curitem="3.17"
	echo '-	Comando: Script customizado' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	cat /etc/passwd | cut -f1 -d":" |sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			uids=`awk -F: '($1 == n) { print $3}' n=$2 /etc/passwd | xargs`
			echo "Duplicate User Name ($2):${uids}"
		fi
	done

	[ $( cat /etc/passwd | cut -f1 -d":" |sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			uids=`awk -F: '($1 == n) { print $3}' n=$2 /etc/passwd | xargs`
			echo "Duplicate User Name ($2):${uids}"
		fi
		done | wc -l) -eq 0 ] && true || false
	check-conformidade
}

apply-317() {
	for i in `getent  passwd | awk -F":" '{print $6}'` ; do
		ls -lha | grep -v "drwxrw----"
	done
}

check-318() {
	curitem="3.18"
	echo '-	Comando: Script customizado' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			gids=`gawk -F: '($1 == n) { print $3}' n=$2 /etc/group | xargs`
			echo "Duplicate Group Name ($2):${gids}"
		fi
	done

	[ $( cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			gids=`gawk -F: '($1 == n) { print $3}' n=$2 /etc/group | xargs`
			echo "Duplicate Group Name ($2):${gids}"
		fi
		done | wc -l) -eq 0 ] && true || false
	check-conformidade
}

apply-318() {
	for i in `getent  passwd | awk -F":" '{print $6}'` ; do
		ls -lha | grep -v "drwxrw----"
	done
}

## 04 - Configuração de SSH

check-401() {
	curitem="4.01"
	echo '-	Comando: grep -i protocol /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep -i protocol /etc/ssh/sshd_config | tee -a $arquivodelog
	egrep -q "^Protocol 2" /etc/ssh/sshd_config
	check-conformidade
}

apply-401() {
	if egrep -q "^Protocol 2" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*Protocol.*/d' /etc/ssh/sshd_config
		echo "Protocol 2" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "Protocol 2" >> /etc/ssh/sshd_config
	fi
}

check-402() {
	curitem="4.02"
	echo '-	Comando: grep LogLevel /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep LogLevel /etc/ssh/sshd_config | tee -a $arquivodelog
	egrep -q "^LogLevel INFO" /etc/ssh/sshd_config
	check-conformidade
}

apply-402() {
	if egrep -q "^LogLevel INFO" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*LogLevel.*/d' /etc/ssh/sshd_config
		echo "LogLevel INFO" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "LogLevel INFO" >> /etc/ssh/sshd_config
	fi
}

check-403() {
	curitem="4.03"
	echo '-	Comando: grep X11Forwarding /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep X11Forwarding /etc/ssh/sshd_config | tee -a $arquivodelog
	
	check-conformidade
}

apply-403() {
	if egrep -q "^X11Forwarding no" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*X11Forwarding.*/d' /etc/ssh/sshd_config
		echo "X11Forwarding no" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "X11Forwarding no" >> /etc/ssh/sshd_config
	fi
}

check-404() {
	curitem="4.04"
	echo '-	Comando: grep MaxAuthTries /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep MaxAuthTries /etc/ssh/sshd_config | tee -a $arquivodelog
	egrep -q "^MaxAuthTries 4" /etc/ssh/sshd_config
	check-conformidade
}

apply-404() {
	if egrep -q "^MaxAuthTries 4" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*MaxAuthTries.*/d' /etc/ssh/sshd_config
		echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
	fi
}

check-405() {
	curitem="4.05"
	echo '-	Comando: grep Hostbased /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep Hostbased /etc/ssh/sshd_config | tee -a $arquivodelog
	egrep -q "^HostbasedAuthentication no" /etc/ssh/sshd_config
	check-conformidade
}

apply-405() {
	if egrep -q "^HostbasedAuthentication no" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*Hostbased.*/d' /etc/ssh/sshd_config
		echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
	fi
}

check-406() {
	curitem="4.06"
	echo '-	Comando: grep PermitRoot /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep PermitRoot /etc/ssh/sshd_config | tee -a $arquivodelog
	egrep -q "^PermitRootLogin no" /etc/ssh/sshd_config
	check-conformidade
}

apply-406() {
	if egrep -q "^PermitRootLogin no" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*PermitRoot.*/d' /etc/ssh/sshd_config
		echo "PermitRootLogin no" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "PermitRootLogin no" >> /etc/ssh/sshd_config
	fi
}

check-407() {
	curitem="4.07"
	echo '-	Comando: grep PermitEmpty /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep PermitEmpty /etc/ssh/sshd_config | tee -a $arquivodelog
	egrep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config
	check-conformidade
}

apply-407() {
	if egrep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*PermitEmpty.*/d' /etc/ssh/sshd_config
		echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
	fi
}

check-408() {
	curitem="4.08"
	echo '-	Comando: grep PermitUser /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep PermitUser /etc/ssh/sshd_config | tee -a $arquivodelog
	egrep -q "^PermitUserEnvironment no" /etc/ssh/sshd_config
	check-conformidade
}

apply-408() {
	if egrep -q "^PermitUserEnvironment no" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*PermitUser.*/d' /etc/ssh/sshd_config
		echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
	fi
}

check-409() {
	curitem="4.09"
	echo '-	Comando: grep Ciphers /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep Ciphers /etc/ssh/sshd_config | tee -a $arquivodelog
	egrep -q "^Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc" /etc/ssh/sshd_config
	check-conformidade
}

apply-409() {
	if egrep -q "^Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*Ciphers.*/d' /etc/ssh/sshd_config
		echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc" >> /etc/ssh/sshd_config
	fi
}

check-410() {
	curitem="4.10"
	echo '-	Comando: grep Banner /etc/ssh/sshd_config' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep Banner /etc/ssh/sshd_config | tee -a $arquivodelog
	egrep -q "^Banner /etc/issue.net" /etc/ssh/sshd_config
	check-conformidade
}

apply-410() {
	if egrep -q "^Banner /etc/issue.net" /etc/ssh/sshd_config
	then
		sed -i.bak-$(date +%Y%m%d-%H%M%S) -e '/.*Banner.*/d' /etc/ssh/sshd_config
		echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
	else
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)
		echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
	fi
}

check-411() {
	curitem="4.11"
	echo '-	Comando: realm list' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	if [ $(which realm &> /dev/null) ]
	then
		realm list | tee -a $arquivodelog
		[ $(realm list | wc -l) -eq 0 ] && true || false
	else
		echo "Comando realm não encontrado no servidor." | tee -a $arquivodelog
		true
	fi
	check-conformidade
}

apply-411() {
	echo "Cheque internamente configurações do sssd para comunicação com o AD."
}

## 05 - Log e auditoria

check-501() {
	local retorno=0
	curitem="5.01"
	echo '-	Comando: egrep "^auth,user|^kern|^daemon|^syslog|^lpr" /etc/rsyslog.conf' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	egrep "^auth,user|^kern|^daemon|^syslog|^lpr" /etc/rsyslog.conf | tee -a $arquivodelog

	egrep -q "auth,user.*/var/log/messages" /etc/rsyslog.conf && true || ((retorno++))
	egrep -q "kern.*/var/log/kern.log" /etc/rsyslog.conf && true || ((retorno++))
	egrep -q "daemon.*/var/log/daemon.log" /etc/rsyslog.conf && true || ((retorno++))
	egrep -q "syslog.*/var/log/syslog" /etc/rsyslog.conf && true || ((retorno++))
	egrep -q "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.*/var/log/unused.log" /etc/rsyslog.conf && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-warning
}

apply-501() {
	auth,user.* /var/log/messages
	kern.* /var/log/kern.log
	daemon.* /var/log/daemon.log
	syslog.* /var/log/syslog
	lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log
}

#check-502() {
#	Configure rsyslog to Send Logs to a Remote Log Host
#}
#
#apply-502() {
#	
#}

check-503() {
	curitem="5.03"
	echo "-	Comando: systemctl is-enabled rsyslog" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	systemctl is-enabled rsyslog | tee -a $arquivodelog
	systemctl is-enabled rsyslog &> /dev/null
	check-conformidade
}

apply-503() {
	systemctl enable rsyslogd
}

check-504() {
	curitem="5.04"
	echo '-	Comando: grep "MAC-policy" /etc/audit/rules.d/audit.rules' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep "MAC-policy" /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-w /etc/selinux/ \-p wa \-k MAC-policy" /etc/audit/rules.d/audit.rules && true || false
	check-conformidade
}

apply-504() {
	-w /etc/selinux/ -p wa -k MAC-policy
}

check-505() {
	local retorno=0
	curitem="5.05"
	echo "-	Comando: grep faillog /etc/audit/rules.d/audit.rules" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep faillog /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-w /var/log/faillog \-p wa \-k logins" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	mudacor ciano
	echo "-	Comando: grep tallylog /etc/audit/rules.d/audit.rules" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep tallylog /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-w /var/log/tallylog \-p wa \-k logins" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	mudacor ciano
	echo "-	Comando: grep lastlog /etc/audit/rules.d/audit.rules" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep lastlog /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-w /var/log/lastlog \-p wa \-k logins" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-warning
}

apply-505() {
	-w /var/log/faillog -p wa -k logins
	-w /var/log/lastlog -p wa -k logins
	-w /var/log/tallylog -p wa -k logins 
}

check-506() {
	local retorno=0
	curitem="5.06"
	echo "-	Comando: grep utmp /etc/audit/rules.d/audit.rules" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep utmp /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-w /var/run/utmp \-p wa \-k session" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	mudacor ciano
	echo "-	Comando: grep btmp /etc/audit/rules.d/audit.rules" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep btmp /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-w /var/log/btmp \-p wa \-k session" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	mudacor ciano
	echo "-	Comando: grep wtmp /etc/audit/rules.d/audit.rules" | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep wtmp /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-w /var/log/wtmp \-p wa \-k session" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-warning
}

apply-506() {
	-w /var/run/utmp -p wa -k session
	-w /var/log/wtmp -p wa -k session
	-w /var/log/btmp -p wa -k session
}

check-507() {
	local retorno=0
	curitem="5.07"
	echo '-	Comando: egrep "fchmod|fchmodat|lremovexattr" /etc/audit/rules.d/audit.rules' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	egrep "fchmod|fchmodat|lremovexattr" /etc/audit/rules.d/audit.rules | tee -a $arquivodelog

	egrep -q "\-a always,exit \-F arch=b64 \-S chmod \-S fchmod \-S fchmodat \-F auid>=500 \-F auid!=4294967295 \-k perm_mod" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-a always,exit \-F arch=b32 \-S chmod \-S fchmod \-S fchmodat \-F auid>=500 \-F auid!=4294967295 \-k perm_mod" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-a always,exit \-F arch=b64 \-S chown \-S fchown \-S fchownat \-S lchown \-F auid>=500  \-F auid!=4294967295 \-k perm_mod" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-a always,exit \-F arch=b32 \-S chown \-S fchown \-S fchownat \-S lchown \-F auid>=500 \-F auid!=4294967295 \-k perm_mod" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-a always,exit \-F arch=b64 \-S setxattr \-S lsetxattr \-S fsetxattr \-S removexattr \-S lremovexattr \-S fremovexattr \-F auid>=500 \-F auid!=4294967295 \-k perm_mod" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-a always,exit \-F arch=b32 \-S setxattr \-S lsetxattr \-S fsetxattr \-S removexattr \-S lremovexattr \-S fremovexattr" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-warning
}

apply-507() {
	-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500  -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
	-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr
}

check-508() {
	local retorno=0
	curitem="5.08"
	echo '-	Comando: egrep "openat|truncate|EACCES" /etc/audit/rules.d/audit.rules' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	egrep "openat|truncate|EACCES" /etc/audit/rules.d/audit.rules | tee -a $arquivodelog

	egrep -q "\-a always,exit \-F arch=b64 \-S creat \-S open \-S openat \-S truncate \-S ftruncate \-F exit=\-EACCES \-F auid>=500 \-F auid!=4294967295 \-k access" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-a always,exit \-F arch=b32 \-S creat \-S open \-S openat \-S truncate \-S ftruncate \-F exit=\-EACCES \-F auid>=500 \-F auid!=4294967295 \-k access" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-a always,exit \-F arch=b64 \-S creat \-S open \-S openat \-S truncate \-S ftruncate \-F exit=\-EPERM \-F auid>=500 \-F auid!=4294967295 \-k access" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-a always,exit \-F arch=b32 \-S creat \-S open \-S openat \-S truncate \-S ftruncate" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-warning
}

apply-508() {
	-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
	-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
	-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
	-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate
}

check-509() {
	local retorno=0
	curitem="5.09"
	echo '-	Comando: egrep "mounts|mount|always" /etc/audit/rules.d/audit.rules' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	egrep "mounts|mount|always" /etc/audit/rules.d/audit.rules | tee -a $arquivodelog

	egrep -q "\-a always,exit \-F arch=b64 \-S mount \-F auid>=500 \-F auid!=4294967295 \-k mounts" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-a always,exit \-F arch=b32 \-S mount \-F auid>=500 \-F auid!=4294967295 \-k mounts" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-warning
}

apply-509() {
	-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
	-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
}

check-510() {
	curitem="5.10"
	echo '-	Comando: grep "scope" /etc/audit/rules.d/audit.rules' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep "scope" /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-w /etc/sudoers \-p wa \-k scope" /etc/audit/rules.d/audit.rules && true || false
	check-conformidade
}

apply-510() {
	-w /etc/sudoers -p wa -k scope
}

check-511() {
	curitem="5.11"
	echo '-	Comando: grep "actions" /etc/audit/rules.d/audit.rules' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep "actions" /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-w /var/log/sudo.log \-p wa \-k actions" /etc/audit/rules.d/audit.rules && true || false
	check-conformidade

	grep actions  /etc/audit/rules.d/audit.rules
}

apply-511() {
	-w /var/log/sudo.log -p wa -k actions
}

check-512() {
	local retorno=0
	curitem="5.12"
	echo '-	Comando: egrep "insmod|modules" /etc/audit/rules.d/audit.rules' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	cat /etc/audit/rules.d/audit.rules | tee -a $arquivodelog

	egrep -q "\-w /sbin/insmod \-p x \-k modules" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-w /sbin/rmmod \-p x \-k modules" /etc/audit/rules.d/audit.rules && true || ((retorno++))
	egrep -q "\-w /sbin/modprobe \-p x \-k modules" /etc/audit/rules.d/audit.rules && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-warning
}

apply-512() {
	-w /sbin/insmod -p x -k modules
	-w /sbin/rmmod -p x -k modules
	-w /sbin/modprobe -p x -k modules
}

check-513() {
	curitem="5.13"
	echo '-	Comando: grep "e 2" /etc/audit/rules.d/audit.rules' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	grep "e 2" /etc/audit/rules.d/audit.rules | tee -a $arquivodelog
	egrep -q "\-e 2" /etc/audit/rules.d/audit.rules && true || false
	check-conformidade
}

apply-513() {
	-e 2
}

## 06 - Configuração de rede

check-601() {
	curitem="6.01"
	echo '-	Comando: cat /proc/sys/net/ipv4/tcp_syncookies' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	cat /proc/sys/net/ipv4/tcp_syncookies | tee -a $arquivodelog
	cat /proc/sys/net/ipv4/tcp_syncookies | grep -q "1"
	check-conformidade
}

apply-601() {
	curitem="6.01"
	echo "Editando sysctl.conf" | tee -a $arquivodelog
	mudacor default
	
	if [ grep "net.ipv4.tcp_syncookies" /etc/sysctl.conf ]
	then
		sed -i.bkp-$(date +%Y%m%d-%H%M%S) -e 's/net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies = 1/g' /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	fi

	systemctl -p | grep "net.ipv4.tcp_syncookies = 1" | tee -a $arquivodelog
	check-conformidade
}

check-602() {
	curitem="6.02"
	echo '-	Comando: cat /proc/sys/net/ipv4/ip_forward' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	cat /proc/sys/net/ipv4/ip_forward | tee -a $arquivodelog
	cat /proc/sys/net/ipv4/ip_forward | grep -q "0"
	check-conformidade
}

apply-602() {
	curitem="6.02"
	echo "Editando sysctl.conf" | tee -a $arquivodelog
	mudacor default
	
	if [ grep "net.ipv4.ip_forward" /etc/sysctl.conf ]
	then
		sed -i.bkp-$(date +%Y%m%d-%H%M%S) -e 's/net.ipv4.ip_forward.*/net.ipv4.ip_forward = 0/g' /etc/sysctl.conf
	else
		echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
	fi

	systemctl -p | grep "net.ipv4.ip_forward = 0" | tee -a $arquivodelog
	check-conformidade
}

check-603() {
	local retorno=0
	curitem="6.03"
	echo '-	Comando: sysctl net.ipv4.conf.all.send_redirects' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.all.send_redirects | tee -a $arquivodelog
	sysctl net.ipv4.conf.all.send_redirects | grep -q "0"
	[ $? -eq 0 ] && true || ((retorno++))

	mudacor ciano
	echo '-	Comando: sysctl net.ipv4.conf.default.send_redirects' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.default.send_redirects | tee -a $arquivodelog
	sysctl net.ipv4.conf.default.send_redirects | grep -q "0"
	[ $? -eq 0 ] && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-conformidade
}

apply-603() {
	echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
}

check-604() {
	local retorno=0
	curitem="6.04"
	echo '-	Comando: sysctl net.ipv4.conf.all.accept_source_route' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.all.accept_source_route | tee -a $arquivodelog
	sysctl net.ipv4.conf.all.accept_source_route | grep -q "0"
	[ $? -eq 0 ] && true || ((retorno++))

	mudacor ciano
	echo '-	Comando: sysctl net.ipv4.conf.default.accept_source_route' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.default.accept_source_route | tee -a $arquivodelog
	sysctl net.ipv4.conf.default.accept_source_route | grep -q "0"
	[ $? -eq 0 ] && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-conformidade
}

apply-604() {
	echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
}

check-605() {
	local retorno=0
	curitem="6.05"
	echo '-	Comando: sysctl net.ipv4.conf.all.accept_redirects' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.all.accept_redirects | tee -a $arquivodelog
	sysctl net.ipv4.conf.all.accept_redirects | grep -q "0"
	[ $? -eq 0 ] && true || ((retorno++))

	mudacor ciano
	echo '-	Comando: sysctl net.ipv4.conf.default.accept_redirects' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.default.accept_redirects | tee -a $arquivodelog
	sysctl net.ipv4.conf.default.accept_redirects | grep -q "0"
	[ $? -eq 0 ] && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-conformidade
}

apply-605() {
	echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
}

check-606() {
	local retorno=0
	curitem="6.06"
	echo '-	Comando: sysctl net.ipv4.conf.all.secure_redirects' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.all.secure_redirects | tee -a $arquivodelog
	sysctl net.ipv4.conf.all.secure_redirects | grep -q "0"
	[ $? -eq 0 ] && true || ((retorno++))

	mudacor ciano
	echo '-	Comando: sysctl net.ipv4.conf.default.secure_redirects' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.default.secure_redirects | tee -a $arquivodelog
	sysctl net.ipv4.conf.default.secure_redirects | grep -q "0"
	[ $? -eq 0 ] && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-conformidade
}

apply-606() {
	echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
}

check-607() {
	curitem="6.07"
	echo '-	Comando: sysctl net.ipv4.icmp_echo_ignore_broadcasts' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.icmp_echo_ignore_broadcasts | tee -a $arquivodelog
	sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep -q "1"
	check-conformidade
}

apply-607() {
	echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
}

check-608() {
	curitem="6.08"
	echo '-	Comando: sysctl net.ipv4.icmp_ignore_bogus_error_responses' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.icmp_ignore_bogus_error_responses | tee -a $arquivodelog
	sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep -q "1"
	check-conformidade
}

apply-608() {
	echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
}

check-609() {
	local retorno=0
	curitem="6.09"
	echo '-	Comando: sysctl net.ipv4.conf.all.rp_filter' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.all.rp_filter | tee -a $arquivodelog
	sysctl net.ipv4.conf.all.rp_filter | grep -q "1"
	[ $? -eq 0 ] && true || ((retorno++))

	mudacor ciano
	echo '-	Comando: sysctl net.ipv4.conf.default.rp_filter' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	sysctl net.ipv4.conf.default.rp_filter | tee -a $arquivodelog
	sysctl net.ipv4.conf.default.rp_filter | grep -q "1"
	[ $? -eq 0 ] && true || ((retorno++))

	[ $retorno -eq 0 ] && true || false
	check-conformidade
}

apply-609() {
	echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
}

check-610() {
	curitem="6.10"
	echo '-	Comando: cat /proc/sys/net/ipv4/tcp_syncookies' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	cat /proc/sys/net/ipv4/tcp_syncookies | tee -a $arquivodelog
	cat /proc/sys/net/ipv4/tcp_syncookies | grep -q "1"
	check-conformidade
}

apply-610() {
	curitem="6.10"
	echo "Editando sysctl.conf" | tee -a $arquivodelog
	mudacor default
	
	if [ grep "net.ipv4.tcp_syncookies" /etc/sysctl.conf ]
	then
		sed -i.bkp-$(date +%Y%m%d-%H%M%S) -e 's/net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies = 1/g' /etc/sysctl.conf
	else
		echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	fi

	systemctl -p | grep "net.ipv4.tcp_syncookies = 1" | tee -a $arquivodelog
	check-conformidade
}

check-611() {
	curitem="6.11"
	echo '-	Comando: iwconfig ifdown' | tee -a $arquivodelog
	echo "-	Resultado: " | tee -a $arquivodelog
	mudacor default

	if [ $(which iwconfig &> /dev/null) ]
	then
		iwconfig ifdown | tee -a $arquivodelog
		[ $(iwconfig ifdown | wc -l) -eq 0 ] && true || false
	else
		echo "Comando iwconfig não encontrado no servidor." | tee -a $arquivodelog
		true
	fi
	check-conformidade
}

apply-611() {
	iwconfig ifdown
}

case "$1" in
	check)
		check-1all
		check-2all
		check-3all
		check-4all
		check-5all
		check-6all
		;;
	check-1all)
		check-1all
		;;
	check-2all)
		check-2all
		;;
	check-3all)
		check-3all
		;;
	check-4all)
		check-4all
		;;
	check-5all)
		check-5all
		;;
	check-6all)
		check-6all
		;;
	summary)
		check-1all &> /dev/null
		check-2all &> /dev/null
		check-3all &> /dev/null
		check-4all &> /dev/null
		check-5all &> /dev/null
		check-6all &> /dev/null	
		egrep "OK|FAILED|WARNING" $arquivodelog
		;;
	apply)
		numero=$2
		apply-0
		;;
	*)
		echo $"Usage: hardening_fast.sh (check | summary | apply | check-?all:"
		echo $"		check-1all"
		echo $"		check-2all"
		echo $"		check-3all"
		echo $"		check-4all"
		echo $"		check-5all"
		echo $"		check-6all )"
		exit 1
		;;
esac

exit $?
