/*
 * Shadow Worker - Default YARA Rules
 *
 * These rules detect common malware patterns and suspicious behaviors.
 * Place additional .yar files in this directory to extend detection.
 */

rule Webshell_Generic {
    meta:
        description = "Detects generic webshell patterns"
        author = "Shadow Worker"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        // PHP webshells
        $php1 = "<?php eval(" ascii nocase
        $php2 = "<?php system(" ascii nocase
        $php3 = "<?php passthru(" ascii nocase
        $php4 = "<?php shell_exec(" ascii nocase
        $php5 = "<?php exec(" ascii nocase
        $php6 = "base64_decode($_" ascii nocase
        $php7 = "assert($_" ascii nocase
        $php8 = "create_function(" ascii nocase

        // ASP webshells
        $asp1 = "<%eval request" ascii nocase
        $asp2 = "<%execute request" ascii nocase
        $asp3 = "<%@ Page Language" ascii nocase

        // JSP webshells
        $jsp1 = "Runtime.getRuntime().exec" ascii
        $jsp2 = "ProcessBuilder" ascii

    condition:
        any of them
}

rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "Shadow Worker"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $enc = "-encodedcommand" ascii nocase
        $bypass = "-executionpolicy bypass" ascii nocase
        $hidden = "-windowstyle hidden" ascii nocase
        $download = "downloadstring" ascii nocase
        $iex = "iex(" ascii nocase
        $webclient = "new-object net.webclient" ascii nocase
        $bits = "start-bitstransfer" ascii nocase
        $invoke = "invoke-expression" ascii nocase
    condition:
        2 of them
}

rule Cryptominer_Strings {
    meta:
        description = "Detects cryptocurrency mining software"
        author = "Shadow Worker"
        severity = "medium"
        mitre = "T1496"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "stratum+ssl://" ascii
        $s3 = "xmrig" ascii nocase
        $s4 = "cryptonight" ascii nocase
        $s5 = "monero" ascii nocase
        $s6 = "coinhive" ascii nocase
        $s7 = "minergate" ascii nocase
        $s8 = "nicehash" ascii nocase
        $wallet = /[0-9A-Za-z]{95}/ ascii  // Monero wallet
    condition:
        2 of them
}

rule Ransomware_Note {
    meta:
        description = "Detects ransomware note patterns"
        author = "Shadow Worker"
        severity = "critical"
        mitre = "T1486"
    strings:
        $s1 = "your files have been encrypted" ascii nocase
        $s2 = "bitcoin" ascii nocase
        $s3 = "decrypt" ascii nocase
        $s4 = "ransom" ascii nocase
        $s5 = "pay" ascii nocase
        $s6 = ".onion" ascii
        $s7 = "restore your files" ascii nocase
        $s8 = "private key" ascii nocase
    condition:
        3 of them
}

rule Suspicious_Base64_PE {
    meta:
        description = "Detects base64 encoded PE files"
        author = "Shadow Worker"
        severity = "high"
        mitre = "T1027"
    strings:
        $mz_b64 = "TVqQAAMAAAA" ascii
        $mz_b64_2 = "TVpQAAIAAAA" ascii
        $mz_b64_3 = "TVoAAAAAAAA" ascii
    condition:
        any of them
}

rule Reverse_Shell_Generic {
    meta:
        description = "Detects reverse shell patterns"
        author = "Shadow Worker"
        severity = "critical"
        mitre = "T1059"
    strings:
        $bash1 = "bash -i >& /dev/tcp/" ascii
        $bash2 = "bash -c 'bash -i >& /dev/tcp" ascii
        $nc1 = "nc -e /bin/sh" ascii
        $nc2 = "nc -e /bin/bash" ascii
        $nc3 = "ncat -e" ascii
        $python1 = "python -c 'import socket,subprocess" ascii
        $python2 = "python3 -c 'import socket,subprocess" ascii
        $perl1 = "perl -e 'use Socket" ascii
        $ruby1 = "ruby -rsocket" ascii
        $php1 = "php -r '$sock=fsockopen" ascii
    condition:
        any of them
}

rule Credential_Dumper {
    meta:
        description = "Detects credential dumping tools"
        author = "Shadow Worker"
        severity = "critical"
        mitre = "T1003"
    strings:
        $m1 = "mimikatz" ascii nocase
        $m2 = "sekurlsa::" ascii
        $m3 = "lsadump::" ascii
        $m4 = "kerberos::" ascii
        $m5 = "privilege::debug" ascii
        $lazagne = "lazagne" ascii nocase
        $pwdump = "pwdump" ascii nocase
        $hashdump = "hashdump" ascii nocase
    condition:
        any of them
}

rule Suspicious_Network_Tool {
    meta:
        description = "Detects network reconnaissance tools"
        author = "Shadow Worker"
        severity = "medium"
        mitre = "T1046"
    strings:
        $nmap = "nmap" ascii nocase
        $masscan = "masscan" ascii nocase
        $zmap = "zmap" ascii nocase
        $netcat = "netcat" ascii nocase
        $socat = "socat" ascii nocase
    condition:
        any of them and filesize < 10MB
}

rule Packed_Executable {
    meta:
        description = "Detects packed/obfuscated executables"
        author = "Shadow Worker"
        severity = "medium"
        mitre = "T1027.002"
    strings:
        $upx = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $themida = "Themida" ascii
        $vmprotect = ".vmp0" ascii
        $aspack = "aPLib" ascii
    condition:
        any of them
}

rule Suspicious_Script_Content {
    meta:
        description = "Detects suspicious script content"
        author = "Shadow Worker"
        severity = "medium"
    strings:
        $curl_exec = /curl.*\|.*(?:bash|sh)/ ascii
        $wget_exec = /wget.*\|.*(?:bash|sh)/ ascii
        $hidden_iframe = "<iframe" ascii nocase
        $document_write = "document.write" ascii
        $eval_base64 = "eval(atob" ascii
        $fromcharcode = "String.fromCharCode" ascii
    condition:
        2 of them
}
